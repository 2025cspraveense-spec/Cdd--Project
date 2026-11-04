"""
Generates an interactive HTML Security Dashboard for Secret Leak Guard.
Synthesizes Gitleaks and Trivy JSON findings into a comprehensive DevSecOps report.
Includes:
- Severity breakdown (Critical, High, Medium, Low)
- Historical audit trend tracker (reports/history.json)
- Embedded charts (severity distribution & historical trends)
- Print/PDF export stylesheet
"""

import os
import sys
import json
import argparse
from datetime import datetime, timezone

# Ensure safe UTF-8 output on Windows consoles
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")


def mask_snippet(raw_val: str, prefix_len: int = 4, suffix_len: int = 4) -> str:
    """Masks secret values in table previews."""
    if not raw_val:
        return "[REDACTED]"
    s = str(raw_val).strip()
    if len(s) <= (prefix_len + suffix_len):
        return "*" * len(s)
    masked = "*" * (len(s) - prefix_len - suffix_len)
    return f"{s[:prefix_len]}{masked}{s[-suffix_len:]}"


def parse_reports(gitleaks_path: str, trivy_path: str):
    items = []

    # 1. Gitleaks parsing
    if os.path.exists(gitleaks_path):
        try:
            with open(gitleaks_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, list):
                    for entry in data:
                        secret_val = entry.get("Secret", "")
                        rule_id = entry.get("RuleID", "Secret Leak").lower()
                        # Determine severity level
                        if any(k in rule_id for k in ["aws", "private-key", "token", "password", "postgres", "db"]):
                            sev = "CRITICAL"
                        elif "campus" in rule_id or "slg" in rule_id or "entropy" in rule_id:
                            sev = "HIGH"
                        else:
                            sev = "MEDIUM"

                        items.append({
                            "scanner": "Gitleaks",
                            "rule": entry.get("RuleID", "Secret Leak"),
                            "description": entry.get("Description", "Detected plaintext credential"),
                            "file": entry.get("File", "Unknown"),
                            "line": entry.get("StartLine", 0),
                            "commit": entry.get("Commit", "Working Tree"),
                            "author": entry.get("Author", "Local Dev"),
                            "severity": sev,
                            "masked": mask_snippet(secret_val or entry.get("Match", "")),
                            "remediation": "Move to .env / HashiCorp Vault. Purge from git history using git-filter-repo."
                        })
        except Exception as e:
            print(f"[Warning] Failed to parse Gitleaks report: {e}")

    # 2. Trivy parsing
    if os.path.exists(trivy_path):
        try:
            with open(trivy_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                results = data.get("Results", [])
                for res in results:
                    target = res.get("Target", "Docker Image")
                    for sec in res.get("Secrets", []):
                        raw_sev = sec.get("Severity", "CRITICAL").upper()
                        items.append({
                            "scanner": "Trivy (Docker)",
                            "rule": sec.get("RuleID", "Image Secret"),
                            "description": sec.get("Title", "Secret embedded in container"),
                            "file": target,
                            "line": sec.get("StartLine", "-"),
                            "commit": "Docker Image Layer",
                            "author": "Docker Build",
                            "severity": raw_sev,
                            "masked": mask_snippet(sec.get("Match", "credential-pattern")),
                            "remediation": "Remove ENV secret directive from Dockerfile. Add file to .dockerignore."
                        })
        except Exception as e:
            print(f"[Warning] Failed to parse Trivy report: {e}")

    return items


def update_history(history_file: str, total: int, critical: int, high: int, medium: int, low: int):
    """Maintains security event history in JSON."""
    history = []
    if os.path.exists(history_file):
        try:
            with open(history_file, "r", encoding="utf-8") as f:
                history = json.load(f)
        except Exception:
            history = []

    current_entry = {
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M"),
        "total": total,
        "critical": critical,
        "high": high,
        "medium": medium,
        "low": low
    }
    history.append(current_entry)
    # Keep last 10 runs
    history = history[-10:]

    try:
        with open(history_file, "w", encoding="utf-8") as f:
            json.dump(history, f, indent=2)
    except Exception as e:
        print(f"[Warning] Failed to save history: {e}")

    return history


def generate_html(items: list, output_path: str, history: list, repo_name: str = "secret-leak-guard"):
    total = len(items)
    gitleaks_count = sum(1 for i in items if i["scanner"] == "Gitleaks")
    trivy_count = sum(1 for i in items if "Trivy" in i["scanner"])
    critical_count = sum(1 for i in items if i["severity"] == "CRITICAL")
    high_count = sum(1 for i in items if i["severity"] == "HIGH")
    medium_count = sum(1 for i in items if i["severity"] == "MEDIUM")
    low_count = sum(1 for i in items if i["severity"] == "LOW")

    rows_html = ""
    if not items:
        rows_html = """
        <tr>
            <td colspan="6" style="text-align:center; padding: 40px; color: #3fb950; font-size: 16px;">
                🎉 <strong>Zero Secrets Detected!</strong> All pre-commit and container security gates passed cleanly.
            </td>
        </tr>
        """
    else:
        for it in items:
            sev_class = f"sev-{it['severity'].lower()}"
            scanner_class = "scanner-gitleaks" if it["scanner"] == "Gitleaks" else "scanner-trivy"
            rows_html += f"""
            <tr class="item-row" data-scanner="{it['scanner'].lower()}" data-sev="{it['severity'].lower()}">
                <td><span class="badge {scanner_class}">{it['scanner']}</span></td>
                <td><span class="badge {sev_class}">{it['severity']}</span></td>
                <td><strong>{it['rule']}</strong><br><small style="color:#8b949e">{it['description']}</small></td>
                <td><code>{it['file']}</code> (Line {it['line']})</td>
                <td><code class="masked-code">{it['masked']}</code></td>
                <td><small>{it['remediation']}</small></td>
            </tr>
            """

    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    # Serialize chart datasets
    chart_labels = json.dumps(["Critical", "High", "Medium", "Low"])
    chart_data = json.dumps([critical_count, high_count, medium_count, low_count])
    history_labels = json.dumps([h["timestamp"].split(" ")[1] for h in history]) if history else "[]"
    history_totals = json.dumps([h["total"] for h in history]) if history else "[]"

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Secret Leak Guard - DevSecOps Audit Dashboard</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        :root {{
            --bg: #0d1117;
            --surface: #161b22;
            --surface-hover: #1f242c;
            --border: #30363d;
            --text: #c9d1d9;
            --heading: #f0f6fc;
            --accent-blue: #58a6ff;
            --accent-green: #238636;
            --accent-red: #f85149;
            --accent-orange: #d29922;
            --code-bg: #090d13;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: var(--bg);
            color: var(--text);
            margin: 0;
            padding: 30px 20px;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}
        .header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid var(--border);
            padding-bottom: 20px;
            margin-bottom: 25px;
            flex-wrap: wrap;
            gap: 15px;
        }}
        .header h1 {{
            margin: 0;
            color: var(--heading);
            font-size: 26px;
            display: flex;
            align-items: center;
            gap: 12px;
        }}
        .timestamp {{
            font-size: 13px;
            color: #8b949e;
        }}
        .header-actions {{
            display: flex;
            gap: 10px;
            align-items: center;
        }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 16px;
            margin-bottom: 25px;
        }}
        .stat-card {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 18px 20px;
        }}
        .stat-card h3 {{
            margin: 0 0 8px 0;
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            color: #8b949e;
        }}
        .stat-card .val {{
            font-size: 30px;
            font-weight: 700;
            color: var(--heading);
        }}
        .stat-card.danger .val {{ color: var(--accent-red); }}
        .stat-card.warning .val {{ color: var(--accent-orange); }}
        .stat-card.info .val {{ color: var(--accent-blue); }}
        .stat-card.success .val {{ color: #3fb950; }}

        .charts-grid {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            margin-bottom: 30px;
        }}
        @media (max-width: 800px) {{
            .charts-grid {{ grid-template-columns: 1fr; }}
        }}
        .chart-card {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 20px;
        }}
        .chart-card h3 {{
            margin: 0 0 15px 0;
            font-size: 15px;
            color: var(--heading);
        }}

        .controls {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
            flex-wrap: wrap;
            gap: 10px;
        }}
        .filter-group {{
            display: flex;
            gap: 8px;
            flex-wrap: wrap;
        }}
        .btn {{
            background: var(--surface);
            border: 1px solid var(--border);
            color: var(--text);
            padding: 6px 14px;
            border-radius: 6px;
            cursor: pointer;
            font-size: 13px;
            transition: all 0.15s ease;
        }}
        .btn:hover, .btn.active {{
            background: #21262d;
            border-color: #8b949e;
            color: var(--heading);
        }}
        .btn-print {{
            background: #238636;
            color: #fff;
            border: none;
            font-weight: 600;
        }}
        .btn-print:hover {{
            background: #2ea043;
            color: #fff;
        }}
        .search-input {{
            background: var(--surface);
            border: 1px solid var(--border);
            color: var(--text);
            padding: 6px 12px;
            border-radius: 6px;
            font-size: 13px;
            width: 240px;
        }}
        .table-card {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 8px;
            overflow-x: auto;
            margin-bottom: 30px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            text-align: left;
        }}
        th {{
            background: #1c2128;
            padding: 12px 14px;
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
            color: #8b949e;
            border-bottom: 1px solid var(--border);
        }}
        td {{
            padding: 14px;
            border-bottom: 1px solid var(--border);
            font-size: 13px;
            vertical-align: middle;
        }}
        tr:hover {{
            background: var(--surface-hover);
        }}
        code {{
            background: var(--code-bg);
            padding: 2px 6px;
            border-radius: 4px;
            font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
            font-size: 12px;
        }}
        .masked-code {{
            color: #f85149;
            background: #2b1114;
            border: 1px solid #da3633;
        }}
        .badge {{
            display: inline-block;
            padding: 3px 8px;
            border-radius: 12px;
            font-size: 11px;
            font-weight: 600;
        }}
        .scanner-gitleaks {{ background: #1f6feb; color: white; }}
        .scanner-trivy {{ background: #8957e5; color: white; }}
        .sev-critical {{ background: #da3633; color: white; }}
        .sev-high {{ background: #d29922; color: white; }}
        .sev-medium {{ background: #1f6feb; color: white; }}
        .sev-low {{ background: #388bfd; color: white; }}

        .remediation-box {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 20px;
        }}
        .remediation-box h2 {{
            margin-top: 0;
            font-size: 18px;
            color: var(--heading);
        }}
        .remediation-box ol {{
            margin: 10px 0 0 20px;
            padding: 0;
            line-height: 1.6;
        }}

        @media print {{
            body {{ background: #fff; color: #000; padding: 0; }}
            .controls, .header-actions, .filter-group, .search-input {{ display: none !important; }}
            .stat-card, .table-card, .chart-card, .remediation-box {{ border: 1px solid #ccc; background: #fff; color: #000; }}
            th {{ background: #eee; color: #000; }}
            td {{ color: #000; }}
            .stat-card .val {{ color: #000 !important; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div>
                <h1>🛡️ Secret Leak Guard &mdash; DevSecOps Audit Dashboard</h1>
                <div class="timestamp">Repository: <strong>{repo_name}</strong> &bull; Generated: {timestamp}</div>
            </div>
            <div class="header-actions">
                <span class="badge" style="background:#238636; font-size:13px; padding:6px 12px;">Shift-Left Enforced</span>
                <button class="btn btn-print" onclick="window.print()">📥 Download / Print PDF</button>
            </div>
        </div>

        <div class="stats-grid">
            <div class="stat-card {'danger' if total > 0 else 'success'}">
                <h3>Total Findings</h3>
                <div class="val">{total}</div>
            </div>
            <div class="stat-card {'danger' if critical_count > 0 else 'success'}">
                <h3>Critical Leaks</h3>
                <div class="val">{critical_count}</div>
            </div>
            <div class="stat-card {'warning' if high_count > 0 else 'success'}">
                <h3>High Severity</h3>
                <div class="val">{high_count}</div>
            </div>
            <div class="stat-card info">
                <h3>Medium Severity</h3>
                <div class="val">{medium_count}</div>
            </div>
            <div class="stat-card">
                <h3>Low Severity</h3>
                <div class="val">{low_count}</div>
            </div>
        </div>

        <div class="charts-grid">
            <div class="chart-card">
                <h3>Severity Distribution</h3>
                <canvas id="severityChart" height="180"></canvas>
            </div>
            <div class="chart-card">
                <h3>Audit Scan Trend (Recent Runs)</h3>
                <canvas id="trendChart" height="180"></canvas>
            </div>
        </div>

        <div class="controls">
            <div class="filter-group">
                <button class="btn active" onclick="filterItems('all', this)">All Findings ({total})</button>
                <button class="btn" onclick="filterItems('gitleaks', this)">Gitleaks ({gitleaks_count})</button>
                <button class="btn" onclick="filterItems('trivy', this)">Trivy ({trivy_count})</button>
                <button class="btn" onclick="filterItems('critical', this)">Critical ({critical_count})</button>
                <button class="btn" onclick="filterItems('high', this)">High ({high_count})</button>
            </div>
            <div>
                <input type="text" class="search-input" id="searchBox" placeholder="Filter by rule, file, or line..." onkeyup="searchTable()">
            </div>
        </div>

        <div class="table-card">
            <table id="findingsTable">
                <thead>
                    <tr>
                        <th>Scanner</th>
                        <th>Severity</th>
                        <th>Rule / Secret Signature</th>
                        <th>Target File / Layer</th>
                        <th>Redacted Value Preview</th>
                        <th>Remediation Action</th>
                    </tr>
                </thead>
                <tbody>
                    {rows_html}
                </tbody>
            </table>
        </div>

        <div class="remediation-box">
            <h2>🛠️ Standard Secret Remediation Protocol</h2>
            <ol>
                <li><strong>Revoke &amp; Rotate:</strong> The leaked credential must be revoked immediately in the provider console. Deleting code does <em>not</em> revoke exposed API tokens.</li>
                <li><strong>Purge Git History:</strong> Run <code>git-filter-repo --replace-text &lt;(echo "LEAKED_KEY==&gt;REDACTED")</code> and force-push.</li>
                <li><strong>Adopt 12-Factor Injection:</strong> Move credentials to <code>.env</code> for local development and HashiCorp Vault or GitHub Secrets for CI/CD and production.</li>
                <li><strong>Guard Container Images:</strong> Never use <code>ENV SECRET=...</code> or <code>COPY .env</code> inside Dockerfiles. Keep <code>.dockerignore</code> strictly maintained.</li>
            </ol>
        </div>
    </div>

    <script>
        // Severity Chart
        const ctxSev = document.getElementById('severityChart').getContext('2d');
        new Chart(ctxSev, {{
            type: 'doughnut',
            data: {{
                labels: {chart_labels},
                datasets: [{{
                    data: {chart_data},
                    backgroundColor: ['#da3633', '#d29922', '#1f6feb', '#388bfd']
                }}]
            }},
            options: {{
                responsive: true,
                plugins: {{
                    legend: {{ position: 'right', labels: {{ color: '#c9d1d9' }} }}
                }}
            }}
        }});

        // Trend Chart
        const ctxTrend = document.getElementById('trendChart').getContext('2d');
        new Chart(ctxTrend, {{
            type: 'line',
            data: {{
                labels: {history_labels},
                datasets: [{{
                    label: 'Total Leaks Detected',
                    data: {history_totals},
                    borderColor: '#f85149',
                    backgroundColor: 'rgba(248, 81, 73, 0.15)',
                    tension: 0.3,
                    fill: true
                }}]
            }},
            options: {{
                responsive: true,
                scales: {{
                    y: {{ beginAtZero: true, grid: {{ color: '#30363d' }}, ticks: {{ color: '#8b949e' }} }},
                    x: {{ grid: {{ color: '#30363d' }}, ticks: {{ color: '#8b949e' }} }}
                }},
                plugins: {{
                    legend: {{ labels: {{ color: '#c9d1d9' }} }}
                }}
            }}
        }});

        function filterItems(type, btn) {{
            document.querySelectorAll('.filter-group .btn').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            const rows = document.querySelectorAll('.item-row');
            rows.forEach(r => {{
                if (type === 'all') {{
                    r.style.display = '';
                }} else if (type === 'gitleaks') {{
                    r.style.display = r.dataset.scanner.includes('gitleaks') ? '' : 'none';
                }} else if (type === 'trivy') {{
                    r.style.display = r.dataset.scanner.includes('trivy') ? '' : 'none';
                }} else if (type === 'critical') {{
                    r.style.display = r.dataset.sev === 'critical' ? '' : 'none';
                }} else if (type === 'high') {{
                    r.style.display = r.dataset.sev === 'high' ? '' : 'none';
                }}
            }});
        }}

        function searchTable() {{
            const filter = document.getElementById('searchBox').value.toLowerCase();
            const rows = document.querySelectorAll('.item-row');
            rows.forEach(r => {{
                const text = r.textContent.toLowerCase();
                r.style.display = text.includes(filter) ? '' : 'none';
            }});
        }}
    </script>
</body>
</html>
"""

    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_content)
    print(f"✅ Dashboard generated successfully: {output_path} ({total} findings recorded)")


def main():
    parser = argparse.ArgumentParser(description="Generate Secret Leak Guard HTML Dashboard")
    parser.add_argument("--gitleaks-report", default="reports/gitleaks-report.json")
    parser.add_argument("--trivy-report", default="reports/trivy-secret-report.json")
    parser.add_argument("--history-file", default="reports/history.json")
    parser.add_argument("--output", default="reports/dashboard.html")
    parser.add_argument("--repo-name", default="secret-leak-guard")

    args = parser.parse_args()
    items = parse_reports(args.gitleaks_report, args.trivy_report)

    critical_count = sum(1 for i in items if i["severity"] == "CRITICAL")
    high_count = sum(1 for i in items if i["severity"] == "HIGH")
    medium_count = sum(1 for i in items if i["severity"] == "MEDIUM")
    low_count = sum(1 for i in items if i["severity"] == "LOW")

    history = update_history(args.history_file, len(items), critical_count, high_count, medium_count, low_count)
    generate_html(items, args.output, history, repo_name=args.repo_name)


if __name__ == "__main__":
    main()
