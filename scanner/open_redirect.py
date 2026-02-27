from urllib.parse import urlparse

from crawler.spider import CrawlResult
from reporter.finding import Finding, Severity
from utils.http_client import HTTPClient
from .base import BaseScanner


class OpenRedirectScanner(BaseScanner):
    name = "open_redirect"
    description = "Open Redirect detection"

    REDIRECT_PARAMS = [
        "url", "uri", "redirect", "redirect_uri", "redirect_url",
        "return", "return_url", "returnto", "return_to", "next",
        "dest", "destination", "redir", "rurl", "go", "target",
        "out", "view", "login", "logout", "link", "forward",
        "continue", "callback", "ref", "rto",
    ]

    PAYLOADS = [
        {"payload": "https://evil.com", "desc": "direct external URL"},
        {"payload": "//evil.com", "desc": "protocol-relative URL"},
        {"payload": "/\\evil.com", "desc": "backslash bypass"},
        {"payload": "https://evil.com%00.target.com", "desc": "null byte bypass"},
        {"payload": "https://evil.com%0d%0a.target.com", "desc": "CRLF bypass"},
        {"payload": "////evil.com", "desc": "multiple slashes"},
        {"payload": "https:evil.com", "desc": "missing slashes"},
        {"payload": "〱evil.com", "desc": "unicode bypass"},
        {"payload": "https://evil.com#@target.com", "desc": "fragment bypass"},
        {"payload": "https://target.com@evil.com", "desc": "userinfo bypass"},
    ]

    async def scan(self, crawl_results: list[CrawlResult]) -> list[Finding]:
        self.logger.info("[bold]Scanning for Open Redirects...[/bold]")

        for result in crawl_results:
            params = self._find_redirect_params(result)
            for param_name, param_info in params.items():
                await self._test_redirect(result, param_name, param_info)

        self.logger.info(f"  Open Redirect scan complete: {len(self.findings)} findings")
        return self.findings

    def _find_redirect_params(self, result: CrawlResult) -> dict:
        from utils.helpers import extract_params

        params = {}
        url_params = extract_params(result.url)
        for name, values in url_params.items():
            if any(p in name.lower() for p in self.REDIRECT_PARAMS):
                params[name] = {"method": "GET", "url": result.url, "value": values[0] if values else ""}
            elif values and values[0].startswith(("http://", "https://", "//")):
                params[name] = {"method": "GET", "url": result.url, "value": values[0]}
        return params

    async def _test_redirect(self, result: CrawlResult, param_name: str, param_info: dict):
        target_host = urlparse(param_info["url"]).hostname

        for test in self.PAYLOADS:
            payload = test["payload"].replace("target.com", target_host or "target.com")
            resp = await self._test_payload(
                param_info["url"], param_info["method"], param_name, payload
            )
            if resp is None:
                continue

            # Check for redirect in response
            redirected = self._check_redirect(resp, payload)
            if redirected:
                self.add_finding(Finding(
                    title=f"Open Redirect via '{param_name}' ({test['desc']})",
                    severity=Severity.MEDIUM,
                    vuln_type="open_redirect",
                    url=param_info["url"],
                    description=(
                        f"Open redirect in parameter '{param_name}'. The application redirects "
                        f"to an attacker-controlled URL using {test['desc']}."
                    ),
                    parameter=param_name,
                    payload=payload,
                    evidence=redirected,
                    confidence="high",
                    remediation=(
                        "Validate redirect targets against a whitelist of allowed domains. "
                        "Use relative paths for internal redirects. Avoid using user input "
                        "directly in redirect locations."
                    ),
                    references=[
                        "https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html",
                    ],
                    tags=["open-redirect", test["desc"].replace(" ", "-")],
                ))
                return

        # Also check for redirect behavior without follow_redirects
        for test in self.PAYLOADS[:3]:
            payload = test["payload"].replace("target.com", target_host or "target.com")
            from utils.helpers import build_url_with_params, extract_params

            orig_params = extract_params(param_info["url"])
            orig_params[param_name] = payload
            flat = {k: v if isinstance(v, str) else v[0] for k, v in orig_params.items()}

            resp = await self.http.get(
                param_info["url"].split("?")[0],
                params=flat,
                allow_redirects=False,
            )
            if resp is None:
                continue

            if resp.status in (301, 302, 303, 307, 308):
                location = resp.headers.get("Location", "")
                if self._is_external_redirect(location, target_host):
                    self.add_finding(Finding(
                        title=f"Open Redirect via '{param_name}' (HTTP {resp.status})",
                        severity=Severity.MEDIUM,
                        vuln_type="open_redirect",
                        url=param_info["url"],
                        description=f"HTTP redirect to external domain via '{param_name}'.",
                        parameter=param_name,
                        payload=payload,
                        evidence=f"Location: {location}",
                        confidence="high",
                        remediation="Validate redirect destinations against allowed domains.",
                        tags=["open-redirect", "http-redirect"],
                    ))
                    return

    def _check_redirect(self, resp, payload: str) -> str | None:
        if resp.redirect_chain:
            for redirect_url in resp.redirect_chain:
                if "evil.com" in redirect_url:
                    return f"Redirected through: {' -> '.join(resp.redirect_chain)}"

        if resp.url and "evil.com" in resp.url:
            return f"Final URL: {resp.url}"

        return None

    def _is_external_redirect(self, location: str, target_host: str) -> bool:
        if not location:
            return False
        try:
            parsed = urlparse(location)
            if parsed.hostname and parsed.hostname != target_host:
                if not parsed.hostname.endswith(f".{target_host}"):
                    return True
        except ValueError:
            pass
        if location.startswith("//") and not location.startswith(f"//{target_host}"):
            return True
        return False
