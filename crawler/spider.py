import asyncio
from dataclasses import dataclass, field
from urllib.parse import urlparse

from .scope import ScopeManager
from utils.http_client import HTTPClient, HTTPResponse
from utils.helpers import (
    normalize_url,
    extract_links,
    extract_forms,
    extract_js_endpoints,
    resolve_url,
    url_fingerprint,
)
from utils.logger import setup_logger

logger = setup_logger("dast-agent.crawler")


@dataclass
class CrawlResult:
    url: str
    method: str
    status: int
    content_type: str
    forms: list[dict] = field(default_factory=list)
    parameters: dict = field(default_factory=dict)
    headers: dict = field(default_factory=dict)
    js_endpoints: set = field(default_factory=set)
    depth: int = 0


class Spider:
    def __init__(
        self,
        http_client: HTTPClient,
        scope: ScopeManager,
        max_depth: int = 5,
        max_pages: int = 500,
        respect_robots: bool = True,
    ):
        self.http = http_client
        self.scope = scope
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.respect_robots = respect_robots

        self.visited: set[str] = set()
        self.fingerprints: set[str] = set()
        self.results: list[CrawlResult] = []
        self.disallowed_paths: set[str] = set()
        self._queue: asyncio.Queue = asyncio.Queue()

    async def crawl(self, start_url: str) -> list[CrawlResult]:
        logger.info(f"[bold green]Starting crawl:[/bold green] {start_url}")

        if self.respect_robots:
            await self._fetch_robots(start_url)

        await self._queue.put((start_url, 0))

        workers = [asyncio.create_task(self._worker()) for _ in range(5)]
        await self._queue.join()

        for w in workers:
            w.cancel()
        await asyncio.gather(*workers, return_exceptions=True)

        logger.info(
            f"[bold green]Crawl complete:[/bold green] "
            f"{len(self.results)} pages, {sum(len(r.forms) for r in self.results)} forms found"
        )
        return self.results

    async def _worker(self):
        while True:
            try:
                url, depth = await asyncio.wait_for(self._queue.get(), timeout=10)
            except (asyncio.TimeoutError, asyncio.CancelledError):
                return

            try:
                await self._process_url(url, depth)
            except Exception as e:
                logger.debug(f"Error processing {url}: {e}")
            finally:
                self._queue.task_done()

    async def _process_url(self, url: str, depth: int):
        normalized = normalize_url(url)

        if normalized in self.visited:
            return
        if len(self.results) >= self.max_pages:
            return
        if depth > self.max_depth:
            return
        if not self.scope.is_in_scope(normalized):
            return

        fp = url_fingerprint(normalized)
        if fp in self.fingerprints:
            return

        self.visited.add(normalized)
        self.fingerprints.add(fp)

        if self._is_robots_disallowed(normalized):
            logger.debug(f"Skipping (robots.txt): {normalized}")
            return

        resp = await self.http.get(normalized)
        if resp is None:
            return

        result = CrawlResult(
            url=normalized,
            method="GET",
            status=resp.status,
            content_type=resp.content_type,
            headers=dict(resp.headers),
            depth=depth,
        )

        if resp.is_html:
            forms = extract_forms(resp.body, normalized)
            result.forms = forms
            links = extract_links(resp.body, normalized)
            for link in links:
                if link not in self.visited and self.scope.is_in_scope(link):
                    await self._queue.put((link, depth + 1))

        if "javascript" in resp.content_type or normalized.endswith(".js"):
            endpoints = extract_js_endpoints(resp.body)
            for ep in endpoints:
                full_url = resolve_url(normalized, ep)
                if self.scope.is_in_scope(full_url):
                    result.js_endpoints.add(full_url)
                    if full_url not in self.visited:
                        await self._queue.put((full_url, depth + 1))

        self.results.append(result)

        if len(self.results) % 50 == 0:
            logger.info(f"  Crawled {len(self.results)} pages...")

    async def _fetch_robots(self, start_url: str):
        parsed = urlparse(start_url)
        robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
        resp = await self.http.get(robots_url)
        if resp and resp.status == 200:
            for line in resp.body.splitlines():
                line = line.strip()
                if line.lower().startswith("disallow:"):
                    path = line.split(":", 1)[1].strip()
                    if path:
                        self.disallowed_paths.add(path)
            logger.info(f"  Loaded {len(self.disallowed_paths)} robots.txt rules")

    def _is_robots_disallowed(self, url: str) -> bool:
        path = urlparse(url).path
        return any(path.startswith(d) for d in self.disallowed_paths)
