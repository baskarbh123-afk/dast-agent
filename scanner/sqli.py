import re
import secrets
import time

from crawler.spider import CrawlResult
from reporter.finding import Finding, Severity
from utils.http_client import HTTPClient
from .base import BaseScanner


class SQLiScanner(BaseScanner):
    name = "sqli"
    description = "SQL Injection detection"

    ERROR_PATTERNS = [
        (r"you have an error in your sql syntax", "MySQL"),
        (r"warning:.*mysql", "MySQL"),
        (r"unclosed quotation mark", "MSSQL"),
        (r"microsoft sql server", "MSSQL"),
        (r"pg_query\(\).*failed", "PostgreSQL"),
        (r"unterminated quoted string", "PostgreSQL"),
        (r"org\.postgresql\.util\.PSQLException", "PostgreSQL"),
        (r"sqlite3?\.OperationalError", "SQLite"),
        (r"near \".*\": syntax error", "SQLite"),
        (r"ORA-\d{5}", "Oracle"),
        (r"quoted string not properly terminated", "Oracle"),
        (r"SQL syntax.*?error", "Generic"),
        (r"invalid input syntax for", "PostgreSQL"),
        (r"sqlstate\[", "Generic"),
        (r"ODBC SQL Server Driver", "MSSQL"),
        (r"javax\.persistence\.PersistenceException", "Java/JPA"),
        (r"hibernate.*exception", "Java/Hibernate"),
    ]

    ERROR_PAYLOADS = [
        "'",
        "\"",
        "'--",
        "' OR '1'='1",
        "\" OR \"1\"=\"1",
        "1' AND '1'='1",
        "1 AND 1=1",
        "' UNION SELECT NULL--",
        "1; SELECT 1--",
        "') OR ('1'='1",
    ]

    BOOLEAN_TESTS = [
        {"true": "' OR '1'='1'--", "false": "' OR '1'='2'--"},
        {"true": "\" OR \"1\"=\"1\"--", "false": "\" OR \"1\"=\"2\"--"},
        {"true": " OR 1=1--", "false": " OR 1=2--"},
        {"true": "' OR 1=1#", "false": "' OR 1=2#"},
    ]

    TIME_PAYLOADS = [
        {"payload": "' OR SLEEP({delay})--", "db": "MySQL"},
        {"payload": "'; WAITFOR DELAY '0:0:{delay}'--", "db": "MSSQL"},
        {"payload": "' OR pg_sleep({delay})--", "db": "PostgreSQL"},
        {"payload": "' AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB({delay}00000000))))--", "db": "SQLite"},
    ]

    async def scan(self, crawl_results: list[CrawlResult]) -> list[Finding]:
        self.logger.info("[bold]Scanning for SQL Injection...[/bold]")

        for result in crawl_results:
            params = self._extract_params(result)
            for param_name, param_info in params.items():
                await self._test_error_based(result, param_name, param_info)
                await self._test_boolean_based(result, param_name, param_info)
                await self._test_time_based(result, param_name, param_info)

            for form in result.forms:
                await self._test_form_sqli(result.url, form)

        self.logger.info(f"  SQLi scan complete: {len(self.findings)} findings")
        return self.findings

    def _extract_params(self, result: CrawlResult) -> dict:
        from utils.helpers import extract_params
        params = {}
        for name, values in extract_params(result.url).items():
            params[name] = {"method": "GET", "url": result.url, "value": values[0] if values else ""}
        return params

    async def _test_error_based(self, result: CrawlResult, param_name: str, param_info: dict):
        baseline = await self._test_payload(
            param_info["url"], param_info["method"], param_name, param_info["value"]
        )
        if baseline is None:
            return

        baseline_errors = self._find_errors(baseline.body)

        for payload in self.ERROR_PAYLOADS:
            resp = await self._test_payload(
                param_info["url"], param_info["method"], param_name, payload
            )
            if resp is None:
                continue

            new_errors = self._find_errors(resp.body)
            triggered = [e for e in new_errors if e not in baseline_errors]

            if triggered:
                db_type = triggered[0][1]
                self.add_finding(Finding(
                    title=f"Error-based SQL Injection in '{param_name}' ({db_type})",
                    severity=Severity.CRITICAL,
                    vuln_type="sqli_error",
                    url=param_info["url"],
                    description=(
                        f"SQL error messages triggered in parameter '{param_name}'. "
                        f"Database type appears to be {db_type}."
                    ),
                    parameter=param_name,
                    payload=payload,
                    evidence=triggered[0][0],
                    confidence="high",
                    remediation="Use parameterized queries / prepared statements. Never concatenate user input into SQL.",
                    references=[
                        "https://owasp.org/www-community/attacks/SQL_Injection",
                        "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
                    ],
                    tags=["sqli", "error-based", db_type.lower()],
                ))
                return

    async def _test_boolean_based(self, result: CrawlResult, param_name: str, param_info: dict):
        baseline = await self._test_payload(
            param_info["url"], param_info["method"], param_name, param_info["value"]
        )
        if baseline is None:
            return

        for test in self.BOOLEAN_TESTS:
            true_resp = await self._test_payload(
                param_info["url"], param_info["method"], param_name, param_info["value"] + test["true"]
            )
            false_resp = await self._test_payload(
                param_info["url"], param_info["method"], param_name, param_info["value"] + test["false"]
            )

            if true_resp is None or false_resp is None:
                continue

            if self._responses_differ_significantly(true_resp.body, false_resp.body, baseline.body):
                self.add_finding(Finding(
                    title=f"Boolean-based SQL Injection in '{param_name}'",
                    severity=Severity.CRITICAL,
                    vuln_type="sqli_boolean",
                    url=param_info["url"],
                    description=(
                        f"Boolean-based blind SQL injection detected in parameter '{param_name}'. "
                        f"The application responds differently to TRUE and FALSE SQL conditions."
                    ),
                    parameter=param_name,
                    payload=f"TRUE: {test['true']} | FALSE: {test['false']}",
                    evidence=f"Response length TRUE={len(true_resp.body)} vs FALSE={len(false_resp.body)}",
                    confidence="medium",
                    remediation="Use parameterized queries / prepared statements.",
                    tags=["sqli", "boolean-based", "blind"],
                ))
                return

    async def _test_time_based(self, result: CrawlResult, param_name: str, param_info: dict):
        delay = 5

        baseline = await self._test_payload(
            param_info["url"], param_info["method"], param_name, param_info["value"]
        )
        if baseline is None:
            return
        baseline_time = baseline.elapsed

        for test in self.TIME_PAYLOADS:
            payload = test["payload"].replace("{delay}", str(delay))
            start = time.monotonic()
            resp = await self._test_payload(
                param_info["url"], param_info["method"], param_name, param_info["value"] + payload
            )
            elapsed = time.monotonic() - start

            if resp is None:
                if elapsed >= delay - 1:
                    pass
                continue

            if resp.elapsed >= delay - 1 and resp.elapsed > baseline_time * 3:
                # Confirm with second request
                confirm_resp = await self._test_payload(
                    param_info["url"], param_info["method"], param_name, param_info["value"] + payload
                )
                if confirm_resp and confirm_resp.elapsed >= delay - 1:
                    self.add_finding(Finding(
                        title=f"Time-based SQL Injection in '{param_name}' ({test['db']})",
                        severity=Severity.CRITICAL,
                        vuln_type="sqli_time",
                        url=param_info["url"],
                        description=(
                            f"Time-based blind SQL injection in parameter '{param_name}'. "
                            f"A {delay}s delay was introduced using {test['db']}-specific syntax."
                        ),
                        parameter=param_name,
                        payload=payload,
                        evidence=f"Baseline: {baseline_time:.2f}s, Injected: {resp.elapsed:.2f}s",
                        confidence="high",
                        remediation="Use parameterized queries / prepared statements.",
                        tags=["sqli", "time-based", "blind", test["db"].lower()],
                    ))
                    return

    def _find_errors(self, body: str) -> list[tuple[str, str]]:
        found = []
        body_lower = body.lower()
        for pattern, db in self.ERROR_PATTERNS:
            if re.search(pattern, body_lower):
                match = re.search(pattern, body_lower)
                found.append((match.group(0), db))
        return found

    def _responses_differ_significantly(self, true_body: str, false_body: str, baseline: str) -> bool:
        true_len, false_len, base_len = len(true_body), len(false_body), len(baseline)

        if true_len == false_len:
            return False

        diff_ratio = abs(true_len - false_len) / max(true_len, false_len, 1)
        if diff_ratio < 0.05:
            return False

        true_matches_base = abs(true_len - base_len) / max(base_len, 1) < 0.1
        false_differs_base = abs(false_len - base_len) / max(base_len, 1) > 0.1

        return true_matches_base and false_differs_base

    async def _test_form_sqli(self, page_url: str, form: dict):
        for inp in form["inputs"]:
            if inp["type"] in ("hidden", "submit", "button", "file"):
                continue

            for payload in self.ERROR_PAYLOADS[:3]:
                test_data = {}
                for field in form["inputs"]:
                    if field["name"] == inp["name"]:
                        test_data[field["name"]] = payload
                    else:
                        test_data[field["name"]] = field["value"] or "test"

                if form["method"] == "GET":
                    resp = await self.http.get(form["action"], params=test_data)
                else:
                    resp = await self.http.post(form["action"], data=test_data)

                if resp and self._find_errors(resp.body):
                    errors = self._find_errors(resp.body)
                    self.add_finding(Finding(
                        title=f"SQL Injection in form field '{inp['name']}'",
                        severity=Severity.CRITICAL,
                        vuln_type="sqli_error",
                        url=form["action"],
                        description=f"SQL error triggered via form field '{inp['name']}' on {page_url}.",
                        parameter=inp["name"],
                        payload=payload,
                        evidence=errors[0][0],
                        confidence="high",
                        remediation="Use parameterized queries.",
                        tags=["sqli", "error-based", "form"],
                    ))
                    break
