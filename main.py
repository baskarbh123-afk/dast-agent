#!/usr/bin/env python3
"""
DAST Agent - Advanced Bug Bounty Automation Tool with Agent Integration

Usage:
    python main.py --target https://example.com
    python main.py --target https://example.com --config config.yaml
    python main.py --target https://example.com --modules xss,sqli,ssrf
    python main.py --target https://example.com --fast --no-fuzz

IMPORTANT: Only use this tool against targets you have explicit authorization
to test (e.g., bug bounty programs, your own applications, or authorized
penetration testing engagements).
"""

import asyncio
import os
import sys

import click
import yaml

# Add project root to path so modules can import each other
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from agent.coordinator import AgentCoordinator
from utils.logger import setup_logger

logger = setup_logger("dast-agent")


def load_config(config_path: str | None) -> dict:
    default_config = os.path.join(os.path.dirname(__file__), "config.yaml")
    path = config_path or default_config

    if os.path.exists(path):
        with open(path) as f:
            return yaml.safe_load(f)
    return {}


def merge_cli_overrides(config: dict, **kwargs) -> dict:
    if kwargs.get("target"):
        config.setdefault("target", {})["url"] = kwargs["target"]

    if kwargs.get("modules"):
        modules = [m.strip() for m in kwargs["modules"].split(",")]
        config.setdefault("scanner", {})["modules"] = modules

    if kwargs.get("depth") is not None:
        config.setdefault("crawler", {})["max_depth"] = kwargs["depth"]

    if kwargs.get("max_pages") is not None:
        config.setdefault("crawler", {})["max_pages"] = kwargs["max_pages"]

    if kwargs.get("rate_limit") is not None:
        config.setdefault("scanner", {})["rate_limit"] = kwargs["rate_limit"]

    if kwargs.get("concurrency") is not None:
        config.setdefault("scanner", {})["max_concurrency"] = kwargs["concurrency"]

    if kwargs.get("no_fuzz"):
        config.setdefault("fuzzer", {})["enabled"] = False

    if kwargs.get("output"):
        config.setdefault("reporting", {})["output_dir"] = kwargs["output"]

    if kwargs.get("proxy"):
        config.setdefault("scanner", {})["proxy"] = kwargs["proxy"]

    if kwargs.get("fast"):
        config.setdefault("crawler", {}).setdefault("max_depth", 3)
        config.setdefault("crawler", {}).setdefault("max_pages", 100)
        config.setdefault("scanner", {}).setdefault("rate_limit", 50)

    if kwargs.get("verbose"):
        config.setdefault("logging", {})["level"] = "DEBUG"

    return config


@click.command()
@click.option("--target", "-t", required=True, help="Target URL to scan")
@click.option("--config", "-c", "config_path", default=None, help="Path to config YAML file")
@click.option("--modules", "-m", default=None, help="Comma-separated scanner modules (e.g., xss,sqli,ssrf)")
@click.option("--depth", "-d", default=None, type=int, help="Max crawl depth (default: 5)")
@click.option("--max-pages", default=None, type=int, help="Max pages to crawl (default: 500)")
@click.option("--rate-limit", "-r", default=None, type=int, help="Requests per second (default: 20)")
@click.option("--concurrency", default=None, type=int, help="Max concurrent requests (default: 10)")
@click.option("--output", "-o", default=None, help="Output directory for reports")
@click.option("--proxy", default=None, help="HTTP proxy (e.g., http://127.0.0.1:8080)")
@click.option("--no-fuzz", is_flag=True, help="Disable fuzzing phase")
@click.option("--fast", is_flag=True, help="Fast scan mode (reduced depth and pages)")
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose/debug logging")
@click.option("--include-subdomains/--no-subdomains", default=True, help="Include subdomains in scope")
def main(target, config_path, modules, depth, max_pages, rate_limit,
         concurrency, output, proxy, no_fuzz, fast, verbose, include_subdomains):
    """DAST Agent - Advanced Bug Bounty Automation Tool

    Scans web applications for security vulnerabilities including XSS, SQLi,
    SSRF, IDOR, CORS misconfigurations, open redirects, and more.

    Only use against targets you have explicit authorization to test.
    """
    # Validate target
    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"

    # Load and merge config
    config = load_config(config_path)
    config = merge_cli_overrides(
        config,
        target=target,
        modules=modules,
        depth=depth,
        max_pages=max_pages,
        rate_limit=rate_limit,
        concurrency=concurrency,
        output=output,
        proxy=proxy,
        no_fuzz=no_fuzz,
        fast=fast,
        verbose=verbose,
    )

    if include_subdomains is not None:
        config.setdefault("target", {}).setdefault("scope", {})["include_subdomains"] = include_subdomains

    if verbose:
        setup_logger("dast-agent", level="DEBUG")

    # Confirmation banner
    click.echo()
    click.echo(click.style("  DAST Agent - Bug Bounty Automation Tool", fg="cyan", bold=True))
    click.echo(click.style("  ========================================", fg="cyan"))
    click.echo(f"  Target: {target}")
    click.echo(f"  Modules: {modules or 'all'}")
    click.echo(f"  Fuzzing: {'disabled' if no_fuzz else 'enabled'}")
    click.echo(f"  Mode: {'fast' if fast else 'standard'}")
    click.echo()

    if not click.confirm("  Do you have authorization to test this target?", default=False):
        click.echo("\n  Aborted. Only scan targets you have permission to test.")
        sys.exit(0)

    click.echo()

    # Run the agent
    coordinator = AgentCoordinator(config)
    findings = asyncio.run(coordinator.run())

    # Exit code based on findings
    critical_high = sum(1 for f in findings if f.severity.value in ("critical", "high"))
    sys.exit(1 if critical_high > 0 else 0)


if __name__ == "__main__":
    main()
