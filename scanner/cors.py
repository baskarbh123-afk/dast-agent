from urllib.parse import urlparse

from crawler.spider import CrawlResult
from reporter.finding import Finding, Severity
from utils.http_client import HTTPClient
from .base import BaseScanner


class CORSScanner(BaseScanner):
    name = "cors"
    description = "CORS misconfiguration detection"

    async def scan(self, crawl_results: list[CrawlResult]) -> list[Finding]:
        self.logger.info("[bold]Scanning for CORS misconfigurations...[/bold]")

        seen_origins = set()
        for result in crawl_results:
            origin = f"{urlparse(result.url).scheme}://{urlparse(result.url).netloc}"
            if origin in seen_origins:
                continue
            seen_origins.add(origin)

            await self._test_cors(result)

        self.logger.info(f"  CORS scan complete: {len(self.findings)} findings")
        return self.findings

    async def _test_cors(self, result: CrawlResult):
        parsed = urlparse(result.url)
        target_origin = f"{parsed.scheme}://{parsed.netloc}"

        tests = [
            {
                "origin": "https://evil.com",
                "desc": "arbitrary origin",
                "severity": Severity.HIGH,
            },
            {
                "origin": f"https://evil.{parsed.hostname}",
                "desc": "subdomain prefix",
                "severity": Severity.MEDIUM,
            },
            {
                "origin": f"{target_origin}.evil.com",
                "desc": "origin suffix",
                "severity": Severity.MEDIUM,
            },
            {
                "origin": "null",
                "desc": "null origin",
                "severity": Severity.MEDIUM,
            },
            {
                "origin": f"http://{parsed.hostname}",
                "desc": "HTTP downgrade",
                "severity": Severity.MEDIUM,
            },
        ]

        for test in tests:
            resp = await self.http.get(
                result.url,
                headers={"Origin": test["origin"]},
            )
            if resp is None:
                continue

            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower()

            if not acao:
                continue

            if acao == "*":
                if acac == "true":
                    self.add_finding(Finding(
                        title="CORS: Wildcard origin with credentials",
                        severity=Severity.CRITICAL,
                        vuln_type="cors_wildcard_creds",
                        url=result.url,
                        description=(
                            "The server returns Access-Control-Allow-Origin: * with "
                            "Access-Control-Allow-Credentials: true. While browsers won't "
                            "honor this combination, it indicates a severe misconfiguration."
                        ),
                        evidence=f"ACAO: {acao}, ACAC: {acac}",
                        confidence="high",
                        remediation="Never use wildcard origin with credentials. Validate origins against a whitelist.",
                        tags=["cors", "wildcard", "credentials"],
                    ))
                else:
                    self.add_finding(Finding(
                        title="CORS: Wildcard origin",
                        severity=Severity.LOW,
                        vuln_type="cors_wildcard",
                        url=result.url,
                        description="The server allows requests from any origin (Access-Control-Allow-Origin: *).",
                        evidence=f"ACAO: {acao}",
                        confidence="high",
                        remediation="Restrict allowed origins to trusted domains.",
                        tags=["cors", "wildcard"],
                    ))
                return

            if acao == test["origin"]:
                sev = test["severity"]
                if acac == "true":
                    sev = Severity.CRITICAL if sev.numeric < Severity.CRITICAL.numeric else sev

                self.add_finding(Finding(
                    title=f"CORS: Reflects {test['desc']} origin" + (" with credentials" if acac == "true" else ""),
                    severity=sev,
                    vuln_type="cors_reflection",
                    url=result.url,
                    description=(
                        f"The server reflects the Origin header '{test['origin']}' in "
                        f"Access-Control-Allow-Origin. "
                        f"{'Credentials are also allowed, enabling cookie-based attacks.' if acac == 'true' else ''}"
                    ),
                    evidence=f"Origin: {test['origin']} -> ACAO: {acao}, ACAC: {acac}",
                    confidence="high",
                    remediation="Validate Origin against a strict whitelist of trusted domains.",
                    references=[
                        "https://portswigger.net/web-security/cors",
                    ],
                    tags=["cors", test["desc"].replace(" ", "-")],
                ))
