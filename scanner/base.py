from abc import ABC, abstractmethod

from crawler.spider import CrawlResult
from reporter.finding import Finding
from utils.http_client import HTTPClient
from utils.logger import setup_logger


class BaseScanner(ABC):
    name: str = "base"
    description: str = ""

    def __init__(self, http_client: HTTPClient):
        self.http = http_client
        self.findings: list[Finding] = []
        self.logger = setup_logger(f"dast-agent.scanner.{self.name}")

    @abstractmethod
    async def scan(self, crawl_results: list[CrawlResult]) -> list[Finding]:
        pass

    def add_finding(self, finding: Finding):
        for existing in self.findings:
            if existing.fingerprint == finding.fingerprint:
                return
        self.findings.append(finding)
        self.logger.info(
            f"  [bold red]FINDING[/bold red] [{finding.severity.value.upper()}] "
            f"{finding.title} @ {finding.url}"
        )

    async def _test_payload(
        self,
        url: str,
        method: str,
        param_name: str,
        payload: str,
        original_params: dict | None = None,
    ):
        """Helper to inject a payload into a parameter and send the request."""
        from utils.helpers import build_url_with_params

        params = dict(original_params) if original_params else {}
        params[param_name] = payload

        if method.upper() == "GET":
            return await self.http.get(url.split("?")[0], params=params)
        else:
            return await self.http.post(url.split("?")[0], data=params)
