from urllib.parse import urlparse

from crawler.spider import CrawlResult
from reporter.finding import Finding, Severity
from utils.http_client import HTTPClient
from .base import BaseScanner


class HeaderAnalysisScanner(BaseScanner):
    name = "header_analysis"
    description = "Security header analysis"

    SECURITY_HEADERS = {
        "Strict-Transport-Security": {
            "severity": Severity.MEDIUM,
            "desc": "HSTS header missing. The site does not enforce HTTPS.",
            "remediation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' header.",
        },
        "Content-Security-Policy": {
            "severity": Severity.MEDIUM,
            "desc": "CSP header missing. No protection against XSS and data injection.",
            "remediation": "Implement a Content-Security-Policy header with restrictive directives.",
        },
        "X-Content-Type-Options": {
            "severity": Severity.LOW,
            "desc": "X-Content-Type-Options header missing. Browser may MIME-sniff responses.",
            "remediation": "Add 'X-Content-Type-Options: nosniff' header.",
        },
        "X-Frame-Options": {
            "severity": Severity.MEDIUM,
            "desc": "X-Frame-Options header missing. Site may be vulnerable to clickjacking.",
            "remediation": "Add 'X-Frame-Options: DENY' or 'SAMEORIGIN' header.",
        },
        "Permissions-Policy": {
            "severity": Severity.LOW,
            "desc": "Permissions-Policy header missing. Browser features not restricted.",
            "remediation": "Add Permissions-Policy header to restrict browser feature access.",
        },
        "Referrer-Policy": {
            "severity": Severity.LOW,
            "desc": "Referrer-Policy header missing. Referrer information may leak.",
            "remediation": "Add 'Referrer-Policy: strict-origin-when-cross-origin' header.",
        },
    }

    DANGEROUS_HEADERS = [
        ("Server", "version information disclosed"),
        ("X-Powered-By", "technology stack disclosed"),
        ("X-AspNet-Version", "ASP.NET version disclosed"),
        ("X-AspNetMvc-Version", "ASP.NET MVC version disclosed"),
    ]

    async def scan(self, crawl_results: list[CrawlResult]) -> list[Finding]:
        self.logger.info("[bold]Analyzing security headers...[/bold]")

        analyzed_origins = set()
        for result in crawl_results:
            origin = f"{urlparse(result.url).scheme}://{urlparse(result.url).netloc}"
            if origin in analyzed_origins:
                continue
            analyzed_origins.add(origin)

            if not result.headers:
                resp = await self.http.get(result.url)
                if resp is None:
                    continue
                headers = resp.headers
            else:
                headers = result.headers

            self._check_missing_headers(result.url, headers)
            self._check_dangerous_headers(result.url, headers)
            self._check_cookie_security(result.url, headers)
            self._check_csp_weaknesses(result.url, headers)

        self.logger.info(f"  Header analysis complete: {len(self.findings)} findings")
        return self.findings

    def _check_missing_headers(self, url: str, headers: dict):
        headers_lower = {k.lower(): v for k, v in headers.items()}

        for header_name, info in self.SECURITY_HEADERS.items():
            if header_name.lower() not in headers_lower:
                self.add_finding(Finding(
                    title=f"Missing {header_name} header",
                    severity=info["severity"],
                    vuln_type="missing_header",
                    url=url,
                    description=info["desc"],
                    remediation=info["remediation"],
                    confidence="high",
                    tags=["headers", "missing-header"],
                ))

    def _check_dangerous_headers(self, url: str, headers: dict):
        headers_lower = {k.lower(): v for k, v in headers.items()}

        for header_name, desc in self.DANGEROUS_HEADERS:
            value = headers_lower.get(header_name.lower())
            if value:
                self.add_finding(Finding(
                    title=f"Information disclosure via {header_name} header",
                    severity=Severity.LOW,
                    vuln_type="info_disclosure_header",
                    url=url,
                    description=f"{desc}: {header_name}: {value}",
                    evidence=f"{header_name}: {value}",
                    remediation=f"Remove or suppress the {header_name} header.",
                    confidence="high",
                    tags=["headers", "info-disclosure"],
                ))

    def _check_cookie_security(self, url: str, headers: dict):
        set_cookies = []
        for key, value in headers.items():
            if key.lower() == "set-cookie":
                set_cookies.append(value)

        for cookie in set_cookies:
            cookie_name = cookie.split("=")[0].strip()
            cookie_lower = cookie.lower()

            issues = []
            if "secure" not in cookie_lower:
                issues.append("missing Secure flag")
            if "httponly" not in cookie_lower:
                issues.append("missing HttpOnly flag")
            if "samesite" not in cookie_lower:
                issues.append("missing SameSite attribute")

            if issues:
                self.add_finding(Finding(
                    title=f"Insecure cookie: {cookie_name}",
                    severity=Severity.MEDIUM if "httponly" in " ".join(issues) else Severity.LOW,
                    vuln_type="insecure_cookie",
                    url=url,
                    description=f"Cookie '{cookie_name}' has security issues: {', '.join(issues)}.",
                    evidence=cookie,
                    remediation="Set Secure, HttpOnly, and SameSite=Strict/Lax attributes on cookies.",
                    confidence="high",
                    tags=["cookies", "headers"],
                ))

    def _check_csp_weaknesses(self, url: str, headers: dict):
        headers_lower = {k.lower(): v for k, v in headers.items()}
        csp = headers_lower.get("content-security-policy", "")
        if not csp:
            return

        weaknesses = []
        if "'unsafe-inline'" in csp:
            weaknesses.append("allows unsafe-inline scripts")
        if "'unsafe-eval'" in csp:
            weaknesses.append("allows unsafe-eval")
        if "data:" in csp:
            weaknesses.append("allows data: URIs")
        if "*" in csp.split():
            weaknesses.append("uses wildcard source")

        if weaknesses:
            self.add_finding(Finding(
                title="Weak Content-Security-Policy",
                severity=Severity.MEDIUM,
                vuln_type="weak_csp",
                url=url,
                description=f"CSP has weaknesses: {', '.join(weaknesses)}.",
                evidence=csp[:500],
                remediation="Tighten CSP directives. Remove unsafe-inline, unsafe-eval, and wildcard sources.",
                confidence="high",
                tags=["csp", "headers"],
            ))
