import asyncio
import time
from dataclasses import dataclass, field
from urllib.parse import urlparse

import aiohttp

from .logger import setup_logger

logger = setup_logger("dast-agent.http")


@dataclass
class HTTPResponse:
    status: int
    headers: dict[str, str]
    body: str
    url: str
    elapsed: float
    redirect_chain: list[str] = field(default_factory=list)

    @property
    def content_type(self) -> str:
        return self.headers.get("content-type", "")

    @property
    def is_html(self) -> bool:
        return "text/html" in self.content_type

    @property
    def is_json(self) -> bool:
        return "application/json" in self.content_type


class RateLimiter:
    def __init__(self, max_per_second: float):
        self._max = max_per_second
        self._tokens = max_per_second
        self._last = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self):
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self._last
            self._tokens = min(self._max, self._tokens + elapsed * self._max)
            self._last = now
            if self._tokens < 1:
                wait = (1 - self._tokens) / self._max
                await asyncio.sleep(wait)
                self._tokens = 0
            else:
                self._tokens -= 1


class HTTPClient:
    def __init__(
        self,
        rate_limit: float = 20,
        timeout: int = 15,
        user_agent: str = "DAST-Agent/1.0 (Authorized Security Testing)",
        max_concurrency: int = 10,
        follow_redirects: bool = True,
        proxy: str | None = None,
    ):
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.user_agent = user_agent
        self.follow_redirects = follow_redirects
        self.proxy = proxy
        self.rate_limiter = RateLimiter(rate_limit)
        self.semaphore = asyncio.Semaphore(max_concurrency)
        self._session: aiohttp.ClientSession | None = None
        self._request_count = 0
        self._error_count = 0

    async def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            connector = aiohttp.TCPConnector(
                limit=100,
                ssl=False,
                enable_cleanup_closed=True,
            )
            self._session = aiohttp.ClientSession(
                connector=connector,
                timeout=self.timeout,
                headers={"User-Agent": self.user_agent},
            )
        return self._session

    async def request(
        self,
        method: str,
        url: str,
        headers: dict | None = None,
        data: str | dict | None = None,
        params: dict | None = None,
        cookies: dict | None = None,
        allow_redirects: bool | None = None,
    ) -> HTTPResponse | None:
        await self.rate_limiter.acquire()
        async with self.semaphore:
            session = await self._get_session()
            start = time.monotonic()
            if allow_redirects is None:
                allow_redirects = self.follow_redirects
            try:
                async with session.request(
                    method,
                    url,
                    headers=headers,
                    data=data,
                    params=params,
                    cookies=cookies,
                    allow_redirects=allow_redirects,
                    proxy=self.proxy,
                ) as resp:
                    body = await resp.text(errors="replace")
                    elapsed = time.monotonic() - start
                    self._request_count += 1

                    redirect_chain = []
                    if resp.history:
                        redirect_chain = [str(r.url) for r in resp.history]

                    return HTTPResponse(
                        status=resp.status,
                        headers=dict(resp.headers),
                        body=body,
                        url=str(resp.url),
                        elapsed=elapsed,
                        redirect_chain=redirect_chain,
                    )
            except asyncio.TimeoutError:
                logger.debug(f"Timeout: {method} {url}")
                self._error_count += 1
                return None
            except aiohttp.ClientError as e:
                logger.debug(f"HTTP error for {url}: {e}")
                self._error_count += 1
                return None

    async def get(self, url: str, **kwargs) -> HTTPResponse | None:
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs) -> HTTPResponse | None:
        return await self.request("POST", url, **kwargs)

    async def put(self, url: str, **kwargs) -> HTTPResponse | None:
        return await self.request("PUT", url, **kwargs)

    async def delete(self, url: str, **kwargs) -> HTTPResponse | None:
        return await self.request("DELETE", url, **kwargs)

    async def head(self, url: str, **kwargs) -> HTTPResponse | None:
        return await self.request("HEAD", url, **kwargs)

    async def options(self, url: str, **kwargs) -> HTTPResponse | None:
        return await self.request("OPTIONS", url, **kwargs)

    @property
    def stats(self) -> dict:
        return {
            "total_requests": self._request_count,
            "errors": self._error_count,
            "error_rate": self._error_count / max(self._request_count, 1),
        }

    async def close(self):
        if self._session and not self._session.closed:
            await self._session.close()
