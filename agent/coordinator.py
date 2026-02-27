import asyncio
import time
from datetime import datetime, timezone

from crawler.spider import Spider, CrawlResult
from crawler.scope import ScopeManager
from scanner import SCANNER_REGISTRY
from scanner.base import BaseScanner
from fuzzer.parameter_fuzzer import ParameterFuzzer
from reporter.finding import Finding, Severity
from reporter.html_report import HTMLReporter
from utils.http_client import HTTPClient
from utils.logger import setup_logger

from .decision_engine import DecisionEngine
from .task_queue import TaskQueue, Task, TaskPriority, TaskStatus

logger = setup_logger("dast-agent.coordinator")


class AgentCoordinator:
    """Central agent that coordinates all scanning activities.

    The coordinator orchestrates the full DAST pipeline:
    1. Crawl the target to map the attack surface
    2. Analyze results to build an intelligent scan strategy
    3. Run vulnerability scanners based on the decision engine
    4. Perform parameter/path fuzzing for hidden endpoints
    5. Aggregate, deduplicate, and prioritize findings
    6. Generate a comprehensive report
    """

    def __init__(self, config: dict):
        self.config = config
        self.start_time = None

        # Core components
        self.http = HTTPClient(
            rate_limit=config.get("scanner", {}).get("rate_limit", 20),
            timeout=config.get("scanner", {}).get("request_timeout", 15),
            user_agent=config.get("crawler", {}).get("user_agent", "DAST-Agent/1.0"),
            max_concurrency=config.get("scanner", {}).get("max_concurrency", 10),
        )

        target_url = config["target"]["url"]
        scope_cfg = config.get("target", {}).get("scope", {})
        self.scope = ScopeManager(
            target_url=target_url,
            include_subdomains=scope_cfg.get("include_subdomains", True),
            allowed_domains=scope_cfg.get("allowed_domains", []),
            excluded_paths=scope_cfg.get("excluded_paths", []),
        )

        self.spider = Spider(
            http_client=self.http,
            scope=self.scope,
            max_depth=config.get("crawler", {}).get("max_depth", 5),
            max_pages=config.get("crawler", {}).get("max_pages", 500),
            respect_robots=config.get("crawler", {}).get("respect_robots_txt", True),
        )

        self.decision_engine = DecisionEngine()
        self.task_queue = TaskQueue()
        self.fuzzer = ParameterFuzzer(
            http_client=self.http,
            max_params=config.get("fuzzer", {}).get("max_params_per_endpoint", 50),
        )

        # Results
        self.crawl_results: list[CrawlResult] = []
        self.all_findings: list[Finding] = []
        self.scan_metadata: dict = {}

    async def run(self) -> list[Finding]:
        self.start_time = time.monotonic()
        target = self.config["target"]["url"]
        logger.info(f"\n[bold blue]{'='*60}[/bold blue]")
        logger.info(f"[bold blue]  DAST Agent - Bug Bounty Automation Tool[/bold blue]")
        logger.info(f"[bold blue]{'='*60}[/bold blue]")
        logger.info(f"  Target: {target}")
        logger.info(f"  Scope: {self.scope.get_scope_summary()}")
        logger.info("")

        try:
            # Phase 1: Crawl
            logger.info("[bold cyan]Phase 1: Crawling target...[/bold cyan]")
            self.crawl_results = await self.spider.crawl(target)
            if not self.crawl_results:
                logger.warning("No pages crawled. Check target URL and scope.")
                return []

            # Phase 2: Analyze attack surface
            logger.info("\n[bold cyan]Phase 2: Analyzing attack surface...[/bold cyan]")
            surface_analysis = self.decision_engine.analyze_crawl_results(self.crawl_results)

            # Phase 3: Run scanners
            logger.info("\n[bold cyan]Phase 3: Running vulnerability scanners...[/bold cyan]")
            scanner_findings = await self._run_scanners()
            self.all_findings.extend(scanner_findings)

            # Phase 4: Fuzzing
            if self.config.get("fuzzer", {}).get("enabled", True):
                logger.info("\n[bold cyan]Phase 4: Fuzzing for hidden parameters and paths...[/bold cyan]")
                fuzz_findings = await self._run_fuzzer()
                self.all_findings.extend(fuzz_findings)

            # Phase 5: Intelligent follow-up
            if self.config.get("agent", {}).get("auto_escalate", True):
                logger.info("\n[bold cyan]Phase 5: Agent-driven follow-up analysis...[/bold cyan]")
                follow_ups = self.decision_engine.suggest_follow_up(self.all_findings)
                if follow_ups:
                    for suggestion in follow_ups:
                        logger.info(f"  Suggestion [{suggestion['priority']}]: {suggestion['description']}")

            # Deduplicate and prioritize
            self.all_findings = self._deduplicate(self.all_findings)
            self.all_findings = self.decision_engine.prioritize_findings(self.all_findings)

            # Phase 6: Report
            logger.info("\n[bold cyan]Phase 6: Generating report...[/bold cyan]")
            await self._generate_report(surface_analysis)

            # Summary
            elapsed = time.monotonic() - self.start_time
            self._print_summary(elapsed)

            return self.all_findings

        finally:
            await self.http.close()

    async def _run_scanners(self) -> list[Finding]:
        findings = []
        enabled_modules = self.config.get("scanner", {}).get("modules", list(SCANNER_REGISTRY.keys()))

        scanner_tasks = []
        for module_name in enabled_modules:
            scanner_cls = SCANNER_REGISTRY.get(module_name)
            if not scanner_cls:
                logger.warning(f"  Unknown scanner module: {module_name}")
                continue
            scanner = scanner_cls(self.http)
            scanner_tasks.append(scanner.scan(self.crawl_results))

        results = await asyncio.gather(*scanner_tasks, return_exceptions=True)
        for result in results:
            if isinstance(result, Exception):
                logger.error(f"  Scanner error: {result}")
            elif isinstance(result, list):
                findings.extend(result)

        return findings

    async def _run_fuzzer(self) -> list[Finding]:
        findings = []

        # Discover hidden params
        discovered = await self.fuzzer.discover_parameters(self.crawl_results)

        # Discover hidden paths
        target = self.config["target"]["url"]
        path_findings = await self.fuzzer.discover_paths(target)
        findings.extend(path_findings)

        return findings

    def _deduplicate(self, findings: list[Finding]) -> list[Finding]:
        seen = set()
        unique = []
        for f in findings:
            if f.fingerprint not in seen:
                seen.add(f.fingerprint)
                unique.append(f)
        deduped = len(findings) - len(unique)
        if deduped:
            logger.info(f"  Deduplicated {deduped} duplicate findings")
        return unique

    async def _generate_report(self, surface_analysis: dict):
        elapsed = time.monotonic() - self.start_time
        self.scan_metadata = {
            "target": self.config["target"]["url"],
            "start_time": datetime.now(timezone.utc).isoformat(),
            "duration_seconds": round(elapsed, 2),
            "pages_crawled": len(self.crawl_results),
            "requests_made": self.http.stats["total_requests"],
            "technologies": surface_analysis.get("technologies", []),
            "scope": self.scope.get_scope_summary(),
        }

        reporter = HTMLReporter(
            output_dir=self.config.get("reporting", {}).get("output_dir", "./reports")
        )
        report_path = reporter.generate(
            findings=self.all_findings,
            metadata=self.scan_metadata,
        )
        logger.info(f"  Report saved to: {report_path}")

    def _print_summary(self, elapsed: float):
        severity_counts = {}
        for f in self.all_findings:
            sev = f.severity.value.upper()
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        logger.info(f"\n[bold green]{'='*60}[/bold green]")
        logger.info(f"[bold green]  Scan Complete[/bold green]")
        logger.info(f"[bold green]{'='*60}[/bold green]")
        logger.info(f"  Duration: {elapsed:.1f}s")
        logger.info(f"  Pages crawled: {len(self.crawl_results)}")
        logger.info(f"  HTTP requests: {self.http.stats['total_requests']}")
        logger.info(f"  Total findings: {len(self.all_findings)}")

        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            count = severity_counts.get(sev, 0)
            if count:
                color = {"CRITICAL": "red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "blue", "INFO": "dim"}.get(sev, "white")
                logger.info(f"    [{color}]{sev}: {count}[/{color}]")

        logger.info(f"[bold green]{'='*60}[/bold green]")
