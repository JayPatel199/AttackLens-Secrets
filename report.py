import json
from datetime import date
from jinja2 import Template
from severity import score_finding

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
SEVERITY_COLOR = {"critical": "#c00", "high": "#e07b00", "medium": "#1a6e3c", "low": "#555"}

data = json.load(open("results/secrets_report.json"))
findings = data["findings"]

for f in findings:
    f["severity"], f["location"] = score_finding(f)

findings.sort(key=lambda f: (SEVERITY_ORDER[f["severity"]], f["location"] != "active"))
counts = {s: sum(1 for f in findings if f["severity"] == s) for s in SEVERITY_ORDER}
active_critical = sum(1 for f in findings if f["severity"] == "critical" and f["location"] == "active")

html = Template("""
<html><head><meta charset="utf-8"><title>Secrets Scan Report</title>
<style>
body{font-family:Arial;max-width:1000px;margin:30px auto;padding:0 20px;color:#222}
h1{border-bottom:3px solid #1a3c6e;padding-bottom:8px}
table{border-collapse:collapse;width:100%;margin:15px 0;font-size:13px}
td,th{border:1px solid #ccc;padding:8px;text-align:left;vertical-align:top}
th{background:#1a3c6e;color:white}
.active{font-weight:bold}
</style></head><body>
<h1>Secrets &amp; Sensitive Data Scan Report</h1>
<p><b>Target:</b> {{ target }}<br><b>Date:</b> {{ today }}</p>
<h2>Executive Summary</h2>
<p>Found <b>{{ total }}</b> potential secrets: {{ c['critical'] }} critical, {{ c['high'] }} high,
{{ c['medium'] }} medium, {{ c['low'] }} low.
<b>{{ active_critical }}</b> critical finding(s) are still active in the current codebase, requiring
immediate rotation. The rest exist only in Git history but remain permanently recoverable unless history is rewritten.</p>
<h2>Findings</h2>
<table><tr><th>Severity</th><th>Status</th><th>Type</th><th>Match</th><th>Source</th><th>Fingerprint</th></tr>
{% for f in findings %}
<tr><td style="color:{{ colors[f.severity] }}"><b>{{ f.severity|upper }}</b></td>
<td class="{{ f.location }}">{{ "ACTIVE NOW" if f.location == "active" else "history only" }}</td>
<td>{{ f.type }}</td><td>{{ f.match }}</td><td>{{ f.source }}</td><td>{{ f.get("fingerprint","-") }}</td></tr>
{% endfor %}</table>
</body></html>
""").render(findings=findings, c=counts, total=len(findings), today=date.today(),
            target=data["target"], colors=SEVERITY_COLOR, active_critical=active_critical)

open("results/secrets_report.html", "w", encoding="utf-8").write(html)
print(f"Report saved: results/secrets_report.html")
print(f"{len(findings)} findings: {counts}")
print(f"Active critical findings requiring immediate action: {active_critical}")
