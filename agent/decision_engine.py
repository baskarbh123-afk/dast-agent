from dataclasses import dataclass

from crawler.spider import CrawlResult
from reporter.finding import Finding, Severity
from utils.logger import setup_logger

logger = setup_logger("dast-agent.decision")


@dataclass
class ScanDecision:
    should_scan: bool
    scanners: list[str]
    priority: str
    reason: str


class DecisionEngine:
    """Intelligent decision engine that analyzes crawl results and findings
    to prioritize scanning efforts and adapt the attack strategy."""

    # Technology detection patterns
    TECH_SIGNATURES = {
        "php": {
            "headers": ["x-powered-by: php", "set-cookie: phpsessid"],
            "extensions": [".php"],
            "body_patterns": ["php", "laravel", "symfony", "wordpress", "drupal"],
        },
        "java": {
            "headers": ["x-powered-by: servlet", "set-cookie: jsessionid"],
            "extensions": [".jsp", ".do", ".action"],
            "body_patterns": ["java", "spring", "struts", "tomcat"],
        },
        "dotnet": {
            "headers": ["x-powered-by: asp.net", "x-aspnet-version"],
            "extensions": [".aspx", ".ashx", ".asmx"],
            "body_patterns": ["__viewstate", "__eventvalidation", "asp.net"],
        },
        "python": {
            "headers": ["x-powered-by: python", "server: gunicorn", "server: uvicorn"],
            "extensions": [".py"],
            "body_patterns": ["django", "flask", "fastapi"],
        },
        "node": {
            "headers": ["x-powered-by: express"],
            "extensions": [],
            "body_patterns": ["node", "express", "next.js", "nuxt"],
        },
        "ruby": {
            "headers": ["x-powered-by: phusion", "set-cookie: _session_id"],
            "extensions": [".rb"],
            "body_patterns": ["rails", "ruby", "sinatra"],
        },
    }

    def __init__(self):
        self.detected_tech: set[str] = set()
        self.attack_surface: dict = {
            "has_forms": False,
            "has_api": False,
            "has_file_upload": False,
            "has_auth": False,
            "has_url_params": False,
            "has_redirects": False,
            "has_cookies": False,
            "interesting_headers": [],
        }
        self.finding_stats: dict[str, int] = {}

    def analyze_crawl_results(self, results: list[CrawlResult]) -> dict:
        logger.info("[bold]Analyzing attack surface...[/bold]")

        for result in results:
            self._detect_technology(result)
            self._analyze_surface(result)

        summary = {
            "technologies": list(self.detected_tech),
            "attack_surface": self.attack_surface,
            "total_pages": len(results),
            "forms_found": sum(1 for r in results if r.forms),
            "js_endpoints": sum(len(r.js_endpoints) for r in results),
        }

        logger.info(f"  Technologies: {', '.join(self.detected_tech) or 'unknown'}")
        logger.info(f"  Attack surface: {self._summarize_surface()}")
        return summary

    def decide_scan_strategy(self, result: CrawlResult) -> ScanDecision:
        scanners = []
        priority = "medium"

        from utils.helpers import extract_params
        params = extract_params(result.url)

        # Always run header analysis on first page of each origin
        scanners.append("header_analysis")

        if params:
            scanners.extend(["xss", "sqli", "open_redirect"])
            # URL-taking params get SSRF testing
            for name, values in params.items():
                if any(p in name.lower() for p in ["url", "uri", "redirect", "callback", "path", "file"]):
                    scanners.append("ssrf")
                    break
            # ID-like params get IDOR testing
            for name, values in params.items():
                if any(p in name.lower() for p in ["id", "uid", "user", "account", "order"]):
                    scanners.append("idor")
                    break

        if result.forms:
            scanners.extend(["xss", "sqli"])
            for form in result.forms:
                for inp in form.get("inputs", []):
                    if inp.get("type") == "file":
                        priority = "high"
                    if any(p in inp.get("name", "").lower() for p in ["url", "link", "redirect"]):
                        scanners.append("ssrf")

        # Always check CORS
        scanners.append("cors")

        scanners = list(dict.fromkeys(scanners))

        return ScanDecision(
            should_scan=len(scanners) > 1,
            scanners=scanners,
            priority=priority,
            reason=self._explain_decision(result, scanners),
        )

    def prioritize_findings(self, findings: list[Finding]) -> list[Finding]:
        return sorted(findings, key=lambda f: (-f.severity.numeric, f.confidence != "high"))

    def suggest_follow_up(self, findings: list[Finding]) -> list[dict]:
        suggestions = []
        vuln_types = {f.vuln_type for f in findings}

        if any("sqli" in vt for vt in vuln_types):
            suggestions.append({
                "action": "deep_sqli",
                "description": "SQL injection found — attempt UNION-based extraction and database enumeration.",
                "priority": "critical",
            })

        if any("ssrf" in vt for vt in vuln_types):
            suggestions.append({
                "action": "ssrf_chain",
                "description": "SSRF found — attempt to access cloud metadata and internal services.",
                "priority": "critical",
            })

        if any("xss" in vt for vt in vuln_types):
            suggestions.append({
                "action": "xss_escalation",
                "description": "XSS found — test for stored XSS and DOM-based variants.",
                "priority": "high",
            })

        if any("cors" in vt for vt in vuln_types):
            suggestions.append({
                "action": "cors_exploit",
                "description": "CORS misconfiguration — test if sensitive data can be exfiltrated cross-origin.",
                "priority": "high",
            })

        if any("idor" in vt for vt in vuln_types):
            suggestions.append({
                "action": "idor_enum",
                "description": "IDOR found — enumerate accessible resources to determine impact.",
                "priority": "high",
            })

        return suggestions

    def _detect_technology(self, result: CrawlResult):
        headers_lower = {k.lower(): v.lower() for k, v in result.headers.items()} if result.headers else {}
        url_lower = result.url.lower()
        body_lower = ""

        for tech, sigs in self.TECH_SIGNATURES.items():
            for header_sig in sigs["headers"]:
                key, _, val = header_sig.partition(": ")
                if key in headers_lower and val in headers_lower[key]:
                    self.detected_tech.add(tech)

            for ext in sigs["extensions"]:
                if ext in url_lower:
                    self.detected_tech.add(tech)

    def _analyze_surface(self, result: CrawlResult):
        if result.forms:
            self.attack_surface["has_forms"] = True
        if "/api/" in result.url or "/rest/" in result.url:
            self.attack_surface["has_api"] = True
        if "?" in result.url:
            self.attack_surface["has_url_params"] = True
        if result.headers:
            if any("set-cookie" in k.lower() for k in result.headers):
                self.attack_surface["has_cookies"] = True
            if any("location" in k.lower() for k in result.headers):
                self.attack_surface["has_redirects"] = True

    def _summarize_surface(self) -> str:
        active = [k.replace("has_", "").replace("_", " ") for k, v in self.attack_surface.items() if v is True]
        return ", ".join(active) if active else "minimal"

    def _explain_decision(self, result: CrawlResult, scanners: list[str]) -> str:
        reasons = []
        if "xss" in scanners:
            reasons.append("parameters present for injection testing")
        if "sqli" in scanners:
            reasons.append("input fields detected")
        if "ssrf" in scanners:
            reasons.append("URL-accepting parameters found")
        if "idor" in scanners:
            reasons.append("ID-like parameters detected")
        return "; ".join(reasons) if reasons else "baseline security checks"
