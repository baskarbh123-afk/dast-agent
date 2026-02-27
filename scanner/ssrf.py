import secrets
from urllib.parse import urlparse

from crawler.spider import CrawlResult
from reporter.finding import Finding, Severity
from utils.http_client import HTTPClient
from .base import BaseScanner


class SSRFScanner(BaseScanner):
    name = "ssrf"
    description = "Server-Side Request Forgery detection"

    INTERESTING_PARAMS = [
        "url", "uri", "link", "src", "source", "redirect", "redirect_uri",
        "callback", "return", "return_url", "next", "dest", "destination",
        "redir", "redirect_url", "go", "target", "path", "file", "page",
        "feed", "host", "site", "html", "proxy", "remote", "img", "image",
        "load", "fetch", "request", "download", "domain",
    ]

    # These payloads test for SSRF by probing internal network responses
    INTERNAL_PAYLOADS = [
        {"payload": "http://127.0.0.1/", "desc": "localhost via IPv4"},
        {"payload": "http://localhost/", "desc": "localhost"},
        {"payload": "http://[::1]/", "desc": "localhost via IPv6"},
        {"payload": "http://0.0.0.0/", "desc": "0.0.0.0"},
        {"payload": "http://169.254.169.254/", "desc": "AWS metadata"},
        {"payload": "http://169.254.169.254/latest/meta-data/", "desc": "AWS metadata path"},
        {"payload": "http://metadata.google.internal/", "desc": "GCP metadata"},
        {"payload": "http://100.100.100.200/", "desc": "Alibaba metadata"},
    ]

    BYPASS_PAYLOADS = [
        "http://127.1/",
        "http://0x7f000001/",
        "http://2130706433/",
        "http://127.0.0.1.nip.io/",
        "http://0177.0.0.1/",
        "http://127.0.0.1:80/",
        "http://127.0.0.1:443/",
    ]

    async def scan(self, crawl_results: list[CrawlResult]) -> list[Finding]:
        self.logger.info("[bold]Scanning for SSRF vulnerabilities...[/bold]")

        for result in crawl_results:
            params = self._find_ssrf_params(result)
            for param_name, param_info in params.items():
                await self._test_ssrf(result, param_name, param_info)

            for form in result.forms:
                await self._test_form_ssrf(result.url, form)

        self.logger.info(f"  SSRF scan complete: {len(self.findings)} findings")
        return self.findings

    def _find_ssrf_params(self, result: CrawlResult) -> dict:
        from utils.helpers import extract_params
        params = {}
        url_params = extract_params(result.url)
        for name, values in url_params.items():
            name_lower = name.lower()
            is_url_param = any(p in name_lower for p in self.INTERESTING_PARAMS)
            has_url_value = values and values[0].startswith(("http://", "https://", "//"))
            if is_url_param or has_url_value:
                params[name] = {"method": "GET", "url": result.url, "value": values[0] if values else ""}
        return params

    async def _test_ssrf(self, result: CrawlResult, param_name: str, param_info: dict):
        # Get baseline response for comparison
        baseline = await self._test_payload(
            param_info["url"], param_info["method"], param_name, param_info["value"]
        )
        if baseline is None:
            return

        for test in self.INTERNAL_PAYLOADS:
            resp = await self._test_payload(
                param_info["url"], param_info["method"], param_name, test["payload"]
            )
            if resp is None:
                continue

            if self._detect_ssrf_indicators(resp, baseline, test["payload"]):
                severity = Severity.CRITICAL if "metadata" in test["desc"].lower() else Severity.HIGH

                self.add_finding(Finding(
                    title=f"SSRF via '{param_name}' ({test['desc']})",
                    severity=severity,
                    vuln_type="ssrf",
                    url=param_info["url"],
                    description=(
                        f"Server-Side Request Forgery detected in parameter '{param_name}'. "
                        f"The server made a request to {test['desc']}."
                    ),
                    parameter=param_name,
                    payload=test["payload"],
                    evidence=self._extract_ssrf_evidence(resp),
                    confidence="medium",
                    remediation=(
                        "Validate and whitelist allowed URLs/domains. Block requests to internal "
                        "IP ranges. Use a URL parser to verify the hostname before making requests."
                    ),
                    references=[
                        "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
                    ],
                    tags=["ssrf", test["desc"].replace(" ", "-").lower()],
                ))
                # Try bypass payloads if basic ones work
                if "localhost" in test["desc"]:
                    await self._test_bypasses(result, param_name, param_info)
                return

    async def _test_bypasses(self, result: CrawlResult, param_name: str, param_info: dict):
        for payload in self.BYPASS_PAYLOADS:
            resp = await self._test_payload(
                param_info["url"], param_info["method"], param_name, payload
            )
            if resp and resp.status in (200, 301, 302):
                self.add_finding(Finding(
                    title=f"SSRF filter bypass via '{param_name}'",
                    severity=Severity.HIGH,
                    vuln_type="ssrf_bypass",
                    url=param_info["url"],
                    description=f"SSRF filter bypass found using alternative IP representation.",
                    parameter=param_name,
                    payload=payload,
                    confidence="medium",
                    remediation="Use a robust URL parser. Block all private IP ranges including alternate representations.",
                    tags=["ssrf", "bypass"],
                ))

    def _detect_ssrf_indicators(self, resp, baseline, payload: str) -> bool:
        if resp.status != baseline.status and resp.status in (200, 301, 302):
            return True

        body_lower = resp.body.lower()
        indicators = [
            "root:", "/bin/bash", "www-data",
            "ami-id", "instance-id", "hostname",
            "computeMetadata", "project-id",
            "<title>apache", "<title>nginx",
            "404 not found" not in body_lower and len(resp.body) > len(baseline.body) * 2,
        ]
        if any(i if isinstance(i, bool) else i in body_lower for i in indicators):
            return True

        return False

    def _extract_ssrf_evidence(self, resp) -> str:
        body_snippet = resp.body[:500] if resp.body else ""
        return f"Status: {resp.status}, Length: {len(resp.body)}, Body: {body_snippet}"

    async def _test_form_ssrf(self, page_url: str, form: dict):
        for inp in form["inputs"]:
            name_lower = inp["name"].lower()
            if not any(p in name_lower for p in self.INTERESTING_PARAMS):
                continue

            for test in self.INTERNAL_PAYLOADS[:3]:
                test_data = {}
                for field in form["inputs"]:
                    if field["name"] == inp["name"]:
                        test_data[field["name"]] = test["payload"]
                    else:
                        test_data[field["name"]] = field["value"] or "test"

                if form["method"] == "GET":
                    resp = await self.http.get(form["action"], params=test_data)
                else:
                    resp = await self.http.post(form["action"], data=test_data)

                if resp and resp.status == 200 and len(resp.body) > 100:
                    self.add_finding(Finding(
                        title=f"Potential SSRF in form field '{inp['name']}'",
                        severity=Severity.MEDIUM,
                        vuln_type="ssrf",
                        url=form["action"],
                        description=f"Form field '{inp['name']}' may be vulnerable to SSRF.",
                        parameter=inp["name"],
                        payload=test["payload"],
                        confidence="low",
                        tags=["ssrf", "form"],
                    ))
                    break
