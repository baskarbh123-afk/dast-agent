# DAST Agent - Advanced Bug Bounty Automation Tool

An agent-based Dynamic Application Security Testing (DAST) tool with 7 vulnerability scanners, async crawler, parameter/path fuzzer, intelligent decision engine, and interactive HTML reporting.

**Only use this tool against targets you have explicit authorization to test (e.g., bug bounty programs, your own applications, or authorized penetration testing engagements).**

## Features

- **7 Vulnerability Scanners**: XSS, SQLi, SSRF, IDOR, CORS Misconfiguration, Open Redirect, Security Header Analysis
- **Async Web Crawler**: Configurable depth, respects robots.txt, subdomain support
- **Parameter Fuzzer**: Automatic parameter discovery and fuzzing with built-in wordlists
- **Intelligent Agent**: Smart decision engine that auto-escalates findings and deduplicates results
- **HTML Reports**: Interactive reports with severity ratings, evidence, and request/response details

## Installation

### Option 1: Docker (Recommended)

```bash
git clone https://github.com/baskarbh123-afk/dast-agent.git
cd dast-agent
docker build -t dast-agent .
```

### Option 2: Local Python

```bash
git clone https://github.com/baskarbh123-afk/dast-agent.git
cd dast-agent
pip install -r requirements.txt
```

## Usage

### Docker

```bash
# Show help
docker run --rm dast-agent

# Basic scan
docker run --rm -v $(pwd)/reports:/app/reports dast-agent -t https://your-target.com

# Fast scan with specific modules
docker run --rm -v $(pwd)/reports:/app/reports dast-agent -t https://your-target.com --fast -m xss,sqli

# Full scan with verbose output
docker run --rm -v $(pwd)/reports:/app/reports dast-agent -t https://your-target.com -v

# Scan through a proxy (e.g., Burp Suite)
docker run --rm -v $(pwd)/reports:/app/reports dast-agent -t https://your-target.com --proxy http://host.docker.internal:8080
```

### Docker Compose

```bash
# Basic scan
docker compose run dast-agent -t https://your-target.com

# Fast scan
docker compose run dast-agent -t https://your-target.com --fast
```

### Local Python

```bash
# Show help
python main.py --help

# Basic scan
python main.py -t https://your-target.com

# Fast scan with specific modules
python main.py -t https://your-target.com --fast -m xss,sqli

# Disable fuzzing
python main.py -t https://your-target.com --no-fuzz

# Custom depth and rate limit
python main.py -t https://your-target.com -d 3 --rate-limit 10

# Output to custom directory
python main.py -t https://your-target.com -o ./my-reports
```

## CLI Options

| Option | Short | Description |
|---|---|---|
| `--target` | `-t` | Target URL to scan (required) |
| `--config` | `-c` | Path to config YAML file |
| `--modules` | `-m` | Comma-separated scanner modules (e.g., `xss,sqli,ssrf`) |
| `--depth` | `-d` | Max crawl depth (default: 5) |
| `--max-pages` | | Max pages to crawl (default: 500) |
| `--rate-limit` | `-r` | Requests per second (default: 20) |
| `--concurrency` | | Max concurrent requests (default: 10) |
| `--output` | `-o` | Output directory for reports |
| `--proxy` | | HTTP proxy (e.g., `http://127.0.0.1:8080`) |
| `--no-fuzz` | | Disable fuzzing phase |
| `--fast` | | Fast scan mode (reduced depth and pages) |
| `--verbose` | `-v` | Enable verbose/debug logging |
| `--include-subdomains` | | Include subdomains in scope (default: on) |

## Scanner Modules

| Module | Description |
|---|---|
| `xss` | Cross-Site Scripting (reflected, stored, DOM-based) |
| `sqli` | SQL Injection (error-based, blind, time-based) |
| `ssrf` | Server-Side Request Forgery |
| `idor` | Insecure Direct Object Reference |
| `cors` | CORS Misconfiguration |
| `open_redirect` | Open Redirect vulnerabilities |
| `header_analysis` | Missing or misconfigured security headers |

## Configuration

Edit `config.yaml` to customize default settings:

```yaml
target:
  scope:
    include_subdomains: true
    excluded_paths:
      - "/logout"
      - "/delete"

crawler:
  max_depth: 5
  max_pages: 500
  request_delay: 0.3

scanner:
  modules: [xss, sqli, ssrf, idor, cors, open_redirect, header_analysis]
  rate_limit: 20
  max_concurrency: 10

fuzzer:
  enabled: true
  parameter_discovery: true

reporting:
  output_dir: "./reports"
  format: "html"
```

## Reports

HTML reports are saved to the `./reports` directory by default. Each report includes:

- Summary of all findings by severity
- Detailed vulnerability descriptions with evidence
- Full HTTP request/response pairs
- Remediation recommendations

## Disclaimer

This tool is intended for **authorized security testing only**. Always obtain proper authorization before scanning any target. Unauthorized use of this tool against systems you do not own or have permission to test is illegal and unethical.
