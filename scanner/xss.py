import html
import re
import secrets

from crawler.spider import CrawlResult
from reporter.finding import Finding, Severity
from utils.http_client import HTTPClient
from .base import BaseScanner


class XSSScanner(BaseScanner):
    name = "xss"
    description = "Cross-Site Scripting (XSS) detection"

    REFLECTION_PAYLOADS = [
        {"payload": "<dast{id}>", "check": "tag_reflection"},
        {"payload": "'\"><dast{id}>", "check": "tag_reflection"},
        {"payload": "javascript:dast{id}()", "check": "scheme_reflection"},
        {"payload": "'-dast{id}-'", "check": "attr_reflection"},
        {"payload": "\"-dast{id}-\"", "check": "attr_reflection"},
    ]

    CONTEXT_PAYLOADS = {
        "html_body": [
            "<img src=x onerror=alert({id})>",
            "<svg/onload=alert({id})>",
            "<details open ontoggle=alert({id})>",
        ],
        "html_attr": [
            "\" onfocus=alert({id}) autofocus=\"",
            "' onfocus=alert({id}) autofocus='",
            "\" onmouseover=alert({id}) \"",
        ],
        "js_string": [
            "'-alert({id})-'",
            "\";alert({id});//",
            "\\';alert({id});//",
        ],
        "url_context": [
            "javascript:alert({id})",
            "data:text/html,<script>alert({id})</script>",
        ],
    }

    def __init__(self, http_client: HTTPClient):
        super().__init__(http_client)
        self._canary_base = "dast" + secrets.token_hex(4)

    async def scan(self, crawl_results: list[CrawlResult]) -> list[Finding]:
        self.logger.info("[bold]Scanning for XSS vulnerabilities...[/bold]")

        for result in crawl_results:
            if not result.content_type or "html" not in result.content_type:
                if result.forms:
                    pass
                else:
                    continue

            params = self._extract_injectable_params(result)
            for param_name, param_info in params.items():
                await self._test_reflection(result, param_name, param_info)

            for form in result.forms:
                await self._test_form_xss(result.url, form)

        self.logger.info(f"  XSS scan complete: {len(self.findings)} findings")
        return self.findings

    def _extract_injectable_params(self, result: CrawlResult) -> dict:
        from utils.helpers import extract_params

        params = {}
        url_params = extract_params(result.url)
        for name, values in url_params.items():
            params[name] = {"method": "GET", "url": result.url, "value": values[0] if values else ""}
        return params

    async def _test_reflection(self, result: CrawlResult, param_name: str, param_info: dict):
        canary = f"{self._canary_base}{secrets.token_hex(2)}"

        for probe in self.REFLECTION_PAYLOADS:
            payload = probe["payload"].replace("{id}", canary)
            resp = await self._test_payload(
                param_info["url"], param_info["method"], param_name, payload
            )
            if resp is None:
                continue

            if canary not in resp.body:
                continue

            context = self._detect_context(resp.body, canary, payload)
            await self._exploit_context(result, param_name, param_info, context, canary)
            break

    def _detect_context(self, body: str, canary: str, payload: str) -> str:
        tag_pattern = f"<dast{canary}>"
        if tag_pattern in body:
            return "html_body"

        escaped = html.escape(canary)
        idx = body.find(canary)
        if idx == -1:
            return "html_body"

        before = body[max(0, idx - 50):idx]
        if re.search(r'["\'][\s]*$', before):
            return "html_attr"
        if re.search(r'<script[^>]*>', before, re.IGNORECASE):
            return "js_string"
        if re.search(r'(?:href|src|action)\s*=\s*["\']?$', before, re.IGNORECASE):
            return "url_context"

        return "html_body"

    async def _exploit_context(
        self, result: CrawlResult, param_name: str, param_info: dict, context: str, canary: str
    ):
        payloads = self.CONTEXT_PAYLOADS.get(context, self.CONTEXT_PAYLOADS["html_body"])

        for payload_template in payloads:
            xss_id = secrets.token_hex(4)
            payload = payload_template.replace("{id}", xss_id)

            resp = await self._test_payload(
                param_info["url"], param_info["method"], param_name, payload
            )
            if resp is None:
                continue

            if self._verify_xss(resp.body, payload, xss_id):
                self.add_finding(Finding(
                    title=f"Reflected XSS via {param_name} ({context})",
                    severity=Severity.HIGH,
                    vuln_type="xss_reflected",
                    url=param_info["url"],
                    description=(
                        f"Reflected Cross-Site Scripting found in parameter '{param_name}'. "
                        f"User input is reflected in {context} context without proper encoding."
                    ),
                    parameter=param_name,
                    payload=payload,
                    evidence=self._extract_evidence(resp.body, xss_id),
                    confidence="high",
                    remediation=(
                        "Apply context-aware output encoding. Use Content-Security-Policy headers. "
                        "Validate and sanitize all user input on the server side."
                    ),
                    references=[
                        "https://owasp.org/www-community/attacks/xss/",
                        "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
                    ],
                    tags=["xss", "reflected", context],
                ))
                return

    def _verify_xss(self, body: str, payload: str, xss_id: str) -> bool:
        event_handlers = ["onerror", "onload", "onfocus", "onmouseover", "ontoggle"]
        for handler in event_handlers:
            if handler in payload and handler in body:
                if xss_id in body:
                    return True

        if f"alert({xss_id})" in body:
            return True
        if f"javascript:alert({xss_id})" in body:
            return True

        return False

    def _extract_evidence(self, body: str, marker: str, context_chars: int = 200) -> str:
        idx = body.find(marker)
        if idx == -1:
            return ""
        start = max(0, idx - context_chars // 2)
        end = min(len(body), idx + context_chars // 2)
        return body[start:end]

    async def _test_form_xss(self, page_url: str, form: dict):
        for inp in form["inputs"]:
            if inp["type"] in ("hidden", "submit", "button", "image", "file"):
                continue

            canary = f"{self._canary_base}{secrets.token_hex(2)}"
            test_data = {}
            for field in form["inputs"]:
                if field["name"] == inp["name"]:
                    test_data[field["name"]] = f"<dast{canary}>"
                else:
                    test_data[field["name"]] = field["value"] or "test"

            if form["method"] == "GET":
                resp = await self.http.get(form["action"], params=test_data)
            else:
                resp = await self.http.post(form["action"], data=test_data)

            if resp and f"<dast{canary}>" in resp.body:
                self.add_finding(Finding(
                    title=f"Reflected XSS in form field '{inp['name']}'",
                    severity=Severity.HIGH,
                    vuln_type="xss_reflected",
                    url=form["action"],
                    description=(
                        f"Form field '{inp['name']}' reflects unescaped HTML tags. "
                        f"Form at {page_url} submits to {form['action']}."
                    ),
                    parameter=inp["name"],
                    payload=f"<dast{canary}>",
                    evidence=f"Injected HTML tag reflected in response.",
                    confidence="high",
                    remediation="Encode all user-supplied output in HTML context.",
                    tags=["xss", "reflected", "form"],
                ))
