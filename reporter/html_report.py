import os
from datetime import datetime, timezone

from jinja2 import Template

from .finding import Finding, Severity


REPORT_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>DAST Agent Report - {{ metadata.target }}</title>
<style>
  :root {
    --bg: #0d1117; --surface: #161b22; --border: #30363d;
    --text: #e6edf3; --text-secondary: #8b949e;
    --critical: #f85149; --high: #f0883e; --medium: #d29922;
    --low: #58a6ff; --info: #8b949e;
    --accent: #58a6ff;
  }
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
    background: var(--bg); color: var(--text); line-height: 1.6; }
  .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
  header { background: var(--surface); border-bottom: 1px solid var(--border);
    padding: 24px; margin-bottom: 24px; border-radius: 8px; }
  h1 { font-size: 1.8em; margin-bottom: 8px; }
  h2 { font-size: 1.3em; margin-bottom: 16px; color: var(--accent); }
  h3 { font-size: 1.1em; margin-bottom: 8px; }
  .meta { color: var(--text-secondary); font-size: 0.9em; }
  .meta span { margin-right: 20px; }
  .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
    gap: 16px; margin: 24px 0; }
  .stat-card { background: var(--surface); border: 1px solid var(--border);
    border-radius: 8px; padding: 16px; text-align: center; }
  .stat-card .number { font-size: 2em; font-weight: bold; }
  .stat-card .label { color: var(--text-secondary); font-size: 0.85em; }
  .stat-critical .number { color: var(--critical); }
  .stat-high .number { color: var(--high); }
  .stat-medium .number { color: var(--medium); }
  .stat-low .number { color: var(--low); }
  .stat-info .number { color: var(--info); }
  .finding { background: var(--surface); border: 1px solid var(--border);
    border-radius: 8px; margin-bottom: 16px; overflow: hidden; }
  .finding-header { padding: 16px; cursor: pointer; display: flex;
    align-items: center; gap: 12px; }
  .finding-header:hover { background: rgba(255,255,255,0.02); }
  .severity-badge { padding: 4px 10px; border-radius: 20px; font-size: 0.75em;
    font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px; }
  .sev-critical { background: rgba(248,81,73,0.15); color: var(--critical); border: 1px solid var(--critical); }
  .sev-high { background: rgba(240,136,62,0.15); color: var(--high); border: 1px solid var(--high); }
  .sev-medium { background: rgba(210,153,34,0.15); color: var(--medium); border: 1px solid var(--medium); }
  .sev-low { background: rgba(88,166,255,0.15); color: var(--low); border: 1px solid var(--low); }
  .sev-info { background: rgba(139,148,158,0.15); color: var(--info); border: 1px solid var(--info); }
  .finding-title { flex: 1; font-weight: 600; }
  .finding-url { color: var(--text-secondary); font-size: 0.85em; }
  .finding-body { padding: 0 16px 16px; border-top: 1px solid var(--border);
    display: none; }
  .finding-body.open { display: block; padding-top: 16px; }
  .detail-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-bottom: 16px; }
  .detail-item label { font-size: 0.8em; color: var(--text-secondary); text-transform: uppercase;
    letter-spacing: 0.5px; display: block; margin-bottom: 4px; }
  .detail-item code { background: var(--bg); padding: 8px 12px; border-radius: 4px;
    display: block; font-size: 0.85em; word-break: break-all; border: 1px solid var(--border); }
  .evidence { background: var(--bg); border: 1px solid var(--border); border-radius: 4px;
    padding: 12px; font-family: monospace; font-size: 0.8em; white-space: pre-wrap;
    word-break: break-all; max-height: 300px; overflow-y: auto; margin-top: 8px; }
  .remediation { background: rgba(88,166,255,0.08); border: 1px solid rgba(88,166,255,0.3);
    border-radius: 4px; padding: 12px; margin-top: 12px; font-size: 0.9em; }
  .tags { display: flex; gap: 6px; flex-wrap: wrap; margin-top: 8px; }
  .tag { background: var(--bg); border: 1px solid var(--border); border-radius: 12px;
    padding: 2px 8px; font-size: 0.75em; color: var(--text-secondary); }
  .confidence { font-size: 0.8em; color: var(--text-secondary); }
  .filter-bar { margin-bottom: 20px; display: flex; gap: 8px; flex-wrap: wrap; }
  .filter-btn { background: var(--surface); border: 1px solid var(--border); border-radius: 20px;
    padding: 6px 14px; color: var(--text); cursor: pointer; font-size: 0.85em; }
  .filter-btn.active { border-color: var(--accent); color: var(--accent); }
  .filter-btn:hover { border-color: var(--text-secondary); }
  footer { text-align: center; color: var(--text-secondary); margin-top: 40px;
    padding: 20px; font-size: 0.85em; border-top: 1px solid var(--border); }
</style>
</head>
<body>
<div class="container">
  <header>
    <h1>DAST Agent Security Report</h1>
    <div class="meta">
      <span>Target: <strong>{{ metadata.target }}</strong></span>
      <span>Date: {{ metadata.start_time[:10] }}</span>
      <span>Duration: {{ metadata.duration_seconds }}s</span>
      <span>Requests: {{ metadata.requests_made }}</span>
    </div>
    {% if metadata.technologies %}
    <div class="meta" style="margin-top: 8px;">
      Technologies: {{ metadata.technologies | join(', ') }}
    </div>
    {% endif %}
  </header>

  <div class="stats">
    <div class="stat-card stat-critical"><div class="number">{{ counts.critical }}</div><div class="label">Critical</div></div>
    <div class="stat-card stat-high"><div class="number">{{ counts.high }}</div><div class="label">High</div></div>
    <div class="stat-card stat-medium"><div class="number">{{ counts.medium }}</div><div class="label">Medium</div></div>
    <div class="stat-card stat-low"><div class="number">{{ counts.low }}</div><div class="label">Low</div></div>
    <div class="stat-card stat-info"><div class="number">{{ counts.info }}</div><div class="label">Info</div></div>
  </div>

  <div class="filter-bar">
    <button class="filter-btn active" onclick="filterFindings('all')">All ({{ findings|length }})</button>
    <button class="filter-btn" onclick="filterFindings('critical')">Critical</button>
    <button class="filter-btn" onclick="filterFindings('high')">High</button>
    <button class="filter-btn" onclick="filterFindings('medium')">Medium</button>
    <button class="filter-btn" onclick="filterFindings('low')">Low</button>
    <button class="filter-btn" onclick="filterFindings('info')">Info</button>
  </div>

  <h2>Findings</h2>
  {% for f in findings %}
  <div class="finding" data-severity="{{ f.severity }}">
    <div class="finding-header" onclick="toggleFinding(this)">
      <span class="severity-badge sev-{{ f.severity }}">{{ f.severity }}</span>
      <span class="finding-title">{{ f.title }}</span>
      <span class="confidence">[{{ f.confidence }}]</span>
    </div>
    <div class="finding-body">
      <p>{{ f.description }}</p>
      <div class="detail-grid">
        <div class="detail-item"><label>URL</label><code>{{ f.url }}</code></div>
        <div class="detail-item"><label>Type</label><code>{{ f.vuln_type }}</code></div>
        {% if f.parameter %}<div class="detail-item"><label>Parameter</label><code>{{ f.parameter }}</code></div>{% endif %}
        {% if f.payload %}<div class="detail-item"><label>Payload</label><code>{{ f.payload }}</code></div>{% endif %}
      </div>
      {% if f.evidence %}
      <h3>Evidence</h3>
      <div class="evidence">{{ f.evidence }}</div>
      {% endif %}
      {% if f.remediation %}
      <div class="remediation"><strong>Remediation:</strong> {{ f.remediation }}</div>
      {% endif %}
      {% if f.tags %}
      <div class="tags">{% for tag in f.tags %}<span class="tag">{{ tag }}</span>{% endfor %}</div>
      {% endif %}
    </div>
  </div>
  {% endfor %}

  {% if not findings %}
  <div style="text-align:center; padding: 40px; color: var(--text-secondary);">
    <h3>No vulnerabilities found</h3>
    <p>The scan completed without finding any issues. This does not guarantee the target is secure.</p>
  </div>
  {% endif %}

  <footer>
    Generated by DAST Agent | Only use for authorized security testing
  </footer>
</div>
<script>
function toggleFinding(header) {
  const body = header.nextElementSibling;
  body.classList.toggle('open');
}
function filterFindings(severity) {
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  event.target.classList.add('active');
  document.querySelectorAll('.finding').forEach(f => {
    f.style.display = (severity === 'all' || f.dataset.severity === severity) ? '' : 'none';
  });
}
</script>
</body>
</html>"""


class HTMLReporter:
    def __init__(self, output_dir: str = "./reports"):
        self.output_dir = output_dir

    def generate(self, findings: list[Finding], metadata: dict) -> str:
        os.makedirs(self.output_dir, exist_ok=True)

        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            counts[f.severity.value] = counts.get(f.severity.value, 0) + 1

        finding_dicts = [f.to_dict() for f in findings]

        template = Template(REPORT_TEMPLATE)
        html = template.render(
            findings=finding_dicts,
            metadata=metadata,
            counts=counts,
        )

        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        filename = f"dast_report_{timestamp}.html"
        filepath = os.path.join(self.output_dir, filename)

        with open(filepath, "w") as f:
            f.write(html)

        return filepath
