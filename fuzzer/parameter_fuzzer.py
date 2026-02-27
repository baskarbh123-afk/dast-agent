import asyncio
from urllib.parse import urlparse, urljoin

from crawler.spider import CrawlResult
from reporter.finding import Finding, Severity
from utils.http_client import HTTPClient
from utils.logger import setup_logger
from .wordlists import Wordlists

logger = setup_logger("dast-agent.fuzzer")


class ParameterFuzzer:
    def __init__(self, http_client: HTTPClient, max_params: int = 50):
        self.http = http_client
        self.max_params = max_params
        self.discovered_params: dict[str, set[str]] = {}
        self.findings: list[Finding] = []

    async def discover_parameters(self, crawl_results: list[CrawlResult]) -> dict[str, set[str]]:
        logger.info("[bold]Discovering hidden parameters...[/bold]")

        endpoints = set()
        for result in crawl_results:
            base = result.url.split("?")[0]
            if result.content_type and ("html" in result.content_type or "json" in result.content_type):
                endpoints.add(base)

        tasks = [self._fuzz_endpoint(ep) for ep in list(endpoints)[:50]]
        await asyncio.gather(*tasks)

        total = sum(len(v) for v in self.discovered_params.values())
        logger.info(f"  Discovered {total} hidden parameters across {len(self.discovered_params)} endpoints")
        return self.discovered_params

    async def discover_paths(self, base_url: str) -> list[Finding]:
        logger.info("[bold]Discovering hidden paths and files...[/bold]")

        parsed = urlparse(base_url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        # Discover directories
        dir_tasks = []
        for dirname in Wordlists.COMMON_DIRS:
            url = f"{origin}/{dirname}/"
            dir_tasks.append(self._check_path(url, "directory"))

        # Discover files
        file_tasks = []
        for filename in Wordlists.COMMON_FILES:
            url = f"{origin}/{filename}"
            file_tasks.append(self._check_path(url, "file"))

        # Discover API paths
        api_tasks = []
        for api_path in Wordlists.API_PATHS:
            url = f"{origin}{api_path}"
            api_tasks.append(self._check_path(url, "api_endpoint"))

        all_tasks = dir_tasks + file_tasks + api_tasks
        # Process in batches to avoid overwhelming
        batch_size = 20
        for i in range(0, len(all_tasks), batch_size):
            batch = all_tasks[i:i + batch_size]
            await asyncio.gather(*batch)

        logger.info(f"  Path discovery complete: {len(self.findings)} interesting paths found")
        return self.findings

    async def _fuzz_endpoint(self, url: str):
        baseline = await self.http.get(url)
        if baseline is None:
            return

        found_params = set()
        wordlist = Wordlists.COMMON_PARAMS[:self.max_params]

        # Test params in batches to be efficient
        batch_size = 10
        for i in range(0, len(wordlist), batch_size):
            batch = wordlist[i:i + batch_size]
            tasks = [self._test_param(url, param, baseline) for param in batch]
            results = await asyncio.gather(*tasks)
            for param, is_valid in zip(batch, results):
                if is_valid:
                    found_params.add(param)

        if found_params:
            self.discovered_params[url] = found_params

    async def _test_param(self, url: str, param: str, baseline) -> bool:
        resp = await self.http.get(url, params={param: "dast_test_value"})
        if resp is None:
            return False

        # Parameter exists if response differs meaningfully from baseline
        if resp.status != baseline.status:
            return resp.status != 404

        len_diff = abs(len(resp.body) - len(baseline.body))
        if len_diff > 50:
            return True

        # Check if param name is reflected (might indicate it's processed)
        if f"dast_test_value" in resp.body and "dast_test_value" not in baseline.body:
            return True

        return False

    async def _check_path(self, url: str, path_type: str):
        resp = await self.http.get(url)
        if resp is None:
            return

        if resp.status == 404 or resp.status >= 500:
            return

        if resp.status == 200:
            is_interesting = self._is_interesting_response(resp, url, path_type)
            if is_interesting:
                severity = self._classify_path_severity(url, path_type, resp)
                self.findings.append(Finding(
                    title=f"Discovered {path_type}: {urlparse(url).path}",
                    severity=severity,
                    vuln_type=f"discovered_{path_type}",
                    url=url,
                    description=f"Accessible {path_type} found at {url}. Status: {resp.status}, Size: {len(resp.body)} bytes.",
                    evidence=resp.body[:300],
                    confidence="high" if resp.status == 200 else "medium",
                    tags=["discovery", path_type],
                ))

        elif resp.status in (301, 302, 403):
            # Still worth noting — exists but restricted
            self.findings.append(Finding(
                title=f"Restricted {path_type}: {urlparse(url).path}",
                severity=Severity.INFO,
                vuln_type=f"restricted_{path_type}",
                url=url,
                description=f"Path exists but returns {resp.status}. May be accessible with different auth.",
                evidence=f"Status: {resp.status}",
                confidence="low",
                tags=["discovery", path_type, "restricted"],
            ))

    def _is_interesting_response(self, resp, url: str, path_type: str) -> bool:
        if len(resp.body) < 20:
            return False

        body_lower = resp.body.lower()

        # Generic error pages are not interesting
        generic_errors = ["page not found", "not found", "404", "error"]
        if any(err in body_lower[:500] for err in generic_errors) and resp.status == 200:
            return False

        # Sensitive files are always interesting
        sensitive = [".env", ".git", ".htpasswd", "config.php", "database.yml"]
        if any(s in url for s in sensitive):
            return True

        return True

    def _classify_path_severity(self, url: str, path_type: str, resp) -> Severity:
        path = urlparse(url).path.lower()
        body_lower = resp.body.lower()

        # Critical: sensitive configuration/credential files
        if any(s in path for s in [".env", ".git/config", ".htpasswd", "wp-config"]):
            return Severity.CRITICAL

        # High: admin panels, debug endpoints, API docs
        if any(s in path for s in ["admin", "debug", "actuator", "phpinfo", "graphiql"]):
            return Severity.HIGH

        # Medium: backup files, swagger docs
        if any(s in path for s in [".bak", "swagger", "openapi", "api-docs"]):
            return Severity.MEDIUM

        # Check body for sensitive content
        if any(s in body_lower for s in ["password", "secret", "api_key", "private_key"]):
            return Severity.HIGH

        return Severity.LOW
