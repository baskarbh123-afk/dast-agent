import re

from crawler.spider import CrawlResult
from reporter.finding import Finding, Severity
from utils.http_client import HTTPClient
from .base import BaseScanner


class IDORScanner(BaseScanner):
    name = "idor"
    description = "Insecure Direct Object Reference detection"

    ID_PARAMS = [
        "id", "uid", "user_id", "userid", "account", "account_id",
        "profile", "profile_id", "order", "order_id", "doc", "doc_id",
        "document_id", "file_id", "item", "item_id", "record", "record_id",
        "invoice", "invoice_id", "ticket", "ticket_id", "report_id",
        "project_id", "org_id", "team_id", "group_id",
    ]

    PATH_PATTERNS = [
        r"/users?/(\d+)",
        r"/accounts?/(\d+)",
        r"/profiles?/(\d+)",
        r"/orders?/(\d+)",
        r"/documents?/(\d+)",
        r"/files?/(\d+)",
        r"/items?/(\d+)",
        r"/invoices?/(\d+)",
        r"/tickets?/(\d+)",
        r"/api/v\d+/\w+/(\d+)",
    ]

    async def scan(self, crawl_results: list[CrawlResult]) -> list[Finding]:
        self.logger.info("[bold]Scanning for IDOR vulnerabilities...[/bold]")

        for result in crawl_results:
            await self._test_param_idor(result)
            await self._test_path_idor(result)

        self.logger.info(f"  IDOR scan complete: {len(self.findings)} findings")
        return self.findings

    async def _test_param_idor(self, result: CrawlResult):
        from utils.helpers import extract_params

        params = extract_params(result.url)
        for name, values in params.items():
            if not any(p in name.lower() for p in self.ID_PARAMS):
                continue
            if not values or not values[0]:
                continue

            original_value = values[0]
            if not self._is_numeric_or_sequential(original_value):
                continue

            baseline = await self.http.get(result.url)
            if baseline is None or baseline.status != 200:
                continue

            test_values = self._generate_idor_values(original_value)
            for test_val in test_values:
                resp = await self._test_payload(
                    result.url, "GET", name, test_val, {name: original_value}
                )
                if resp is None:
                    continue

                if self._detect_idor(baseline, resp, original_value, test_val):
                    self.add_finding(Finding(
                        title=f"Potential IDOR via '{name}' parameter",
                        severity=Severity.HIGH,
                        vuln_type="idor",
                        url=result.url,
                        description=(
                            f"Changing parameter '{name}' from '{original_value}' to '{test_val}' "
                            f"returned a 200 response with different content, suggesting unauthorized "
                            f"access to another user's resource."
                        ),
                        parameter=name,
                        payload=test_val,
                        evidence=(
                            f"Original response length: {len(baseline.body)}, "
                            f"Modified response length: {len(resp.body)}, "
                            f"Status: {resp.status}"
                        ),
                        confidence="medium",
                        remediation=(
                            "Implement proper authorization checks. Verify that the authenticated "
                            "user has permission to access the requested resource. Use indirect "
                            "references or UUIDs instead of sequential IDs."
                        ),
                        references=[
                            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References",
                        ],
                        tags=["idor", "authorization"],
                    ))
                    break

    async def _test_path_idor(self, result: CrawlResult):
        from urllib.parse import urlparse

        path = urlparse(result.url).path
        for pattern in self.PATH_PATTERNS:
            match = re.search(pattern, path)
            if not match:
                continue

            original_id = match.group(1)
            test_values = self._generate_idor_values(original_id)

            baseline = await self.http.get(result.url)
            if baseline is None or baseline.status != 200:
                continue

            for test_val in test_values:
                new_path = path[:match.start(1)] + test_val + path[match.end(1):]
                parsed = urlparse(result.url)
                test_url = f"{parsed.scheme}://{parsed.netloc}{new_path}"
                if parsed.query:
                    test_url += f"?{parsed.query}"

                resp = await self.http.get(test_url)
                if resp is None:
                    continue

                if self._detect_idor(baseline, resp, original_id, test_val):
                    self.add_finding(Finding(
                        title=f"Potential IDOR in URL path",
                        severity=Severity.HIGH,
                        vuln_type="idor_path",
                        url=result.url,
                        description=(
                            f"Changing the ID in URL path from '{original_id}' to '{test_val}' "
                            f"returned accessible content for a different resource."
                        ),
                        parameter="path_id",
                        payload=test_url,
                        evidence=f"Status: {resp.status}, Length: {len(resp.body)}",
                        confidence="medium",
                        remediation="Enforce authorization checks for all resource access.",
                        tags=["idor", "path-based"],
                    ))
                    break

    def _is_numeric_or_sequential(self, value: str) -> bool:
        if value.isdigit():
            return True
        if re.match(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", value, re.I):
            return False  # UUIDs are not sequential
        return False

    def _generate_idor_values(self, original: str) -> list[str]:
        if original.isdigit():
            val = int(original)
            candidates = [val - 1, val + 1, val - 2, val + 2, 1, 0]
            return [str(c) for c in candidates if c >= 0 and c != val]
        return []

    def _detect_idor(self, baseline, response, original_id: str, test_id: str) -> bool:
        if response.status != 200:
            return False

        if response.status == baseline.status and len(response.body) < 50:
            return False

        # The response should have content and be different from baseline
        if abs(len(response.body) - len(baseline.body)) < 10:
            if test_id in response.body and original_id not in response.body:
                return True
            return False

        # Different content returned successfully
        if response.status == 200 and len(response.body) > 100:
            return True

        return False
