"""
Standalone Interactive HTML Security Audit Report Generator
"""

import json
from typing import Any, Dict, List


class HTMLReportGenerator:
    """Renders self-contained, interactive HTML audit reports."""

    @classmethod
    def generate(cls, scan_data: Dict[str, Any], findings: List[Dict[str, Any]]) -> str:
        summary = scan_data.get("summary", {})
        grade = scan_data.get("security_grade", "A")
        score = scan_data.get("risk_score", 0.0)
        grade_color = "#dc3545" if grade in ["D", "F"] else ("#fd7e14" if grade == "C" else "#198754")

        findings_json = json.dumps(findings)

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Security Audit: {scan_data.get('project_name', 'Project')} - Secret Leak Guard</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
  <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.2/dist/chart.umd.min.js"></script>
  <style>
    :root {{
      --bg-color: #0f172a;
      --card-bg: #1e293b;
      --border-color: #334155;
      --text-main: #f8fafc;
      --text-muted: #94a3b8;
    }}
    body {{
      background-color: var(--bg-color);
      color: var(--text-main);
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      padding-bottom: 60px;
    }}
    .card {{
      background-color: var(--card-bg);
      border: 1px solid var(--border-color);
      border-radius: 12px;
      color: var(--text-main);
    }}
    .badge-critical {{ background-color: #dc3545; color: white; }}
    .badge-high {{ background-color: #fd7e14; color: white; }}
    .badge-medium {{ background-color: #ffc107; color: black; }}
    .badge-low {{ background-color: #0dcaf0; color: black; }}
    .badge-info {{ background-color: #6c757d; color: white; }}
    pre.evidence {{
      background-color: #090d16;
      border: 1px solid #1e293b;
      color: #38bdf8;
      padding: 10px;
      border-radius: 6px;
      font-size: 0.85rem;
      white-space: pre-wrap;
      word-break: break-all;
    }}
    .table-dark {{
      --bs-table-bg: var(--card-bg);
      --bs-table-border-color: var(--border-color);
      color: var(--text-main);
    }}
    @media print {{
      body {{ background-color: white !important; color: black !important; }}
      .card {{ border: 1px solid #ccc !important; background-color: white !important; color: black !important; }}
      .no-print {{ display: none !important; }}
    }}
  </style>
</head>
<body>
  <div class="container py-4">
    <div class="d-flex justify-content-between align-items-center mb-4 pb-3 border-bottom border-secondary">
      <div>
        <h2 class="fw-bold mb-1">Secret Leak Guard — Security Audit Report</h2>
        <p class="text-secondary mb-0">Project: <b>{scan_data.get('project_name')}</b> | Scan ID: <code>{scan_data.get('scan_id')}</code> | Completed: {scan_data.get('completed_at', 'N/A')}</p>
      </div>
      <div class="no-print">
        <button onclick="window.print()" class="btn btn-outline-info btn-sm me-2">Print / PDF</button>
        <button onclick="downloadJSON()" class="btn btn-outline-success btn-sm">Export JSON</button>
      </div>
    </div>

    <div class="row g-3 mb-4">
      <div class="col-md-3">
        <div class="card p-3 text-center">
          <div class="text-secondary small text-uppercase">Security Grade</div>
          <div class="display-4 fw-bold" style="color: {grade_color};">{grade}</div>
          <div class="small text-secondary">Risk Score: {score}/100</div>
        </div>
      </div>
      <div class="col-md-3">
        <div class="card p-3 text-center">
          <div class="text-secondary small text-uppercase">Total Findings</div>
          <div class="display-4 fw-bold">{summary.get('total_findings', 0)}</div>
          <div class="small text-secondary">Duration: {scan_data.get('duration_seconds', 0)}s</div>
        </div>
      </div>
      <div class="col-md-3">
        <div class="card p-3 text-center">
          <div class="text-secondary small text-uppercase">Critical Vulnerabilities</div>
          <div class="display-4 fw-bold text-danger">{summary.get('critical', 0)}</div>
          <div class="small text-secondary">High: {summary.get('high', 0)}</div>
        </div>
      </div>
      <div class="col-md-3">
        <div class="card p-3 text-center">
          <div class="text-secondary small text-uppercase">Exposed Secrets</div>
          <div class="display-4 fw-bold text-warning">{summary.get('secrets_count', 0)}</div>
          <div class="small text-secondary">Deps: {summary.get('dependencies_count', 0)} | SAST: {summary.get('sast_count', 0)}</div>
        </div>
      </div>
    </div>

    <div class="row g-3 mb-4">
      <div class="col-md-6">
        <div class="card p-3 h-100">
          <h6 class="fw-bold mb-3">Severity Breakdown</h6>
          <div style="max-height: 220px; position: relative;">
            <canvas id="sevChart"></canvas>
          </div>
        </div>
      </div>
      <div class="col-md-6">
        <div class="card p-3 h-100">
          <h6 class="fw-bold mb-3">Security Category Distribution</h6>
          <div style="max-height: 220px; position: relative;">
            <canvas id="catChart"></canvas>
          </div>
        </div>
      </div>
    </div>

    <div class="card p-3">
      <div class="d-flex justify-content-between align-items-center mb-3">
        <h5 class="fw-bold mb-0">Detailed Findings ({len(findings)})</h5>
        <div class="d-flex gap-2 no-print">
          <input type="text" id="searchInput" onkeyup="filterFindings()" class="form-control form-control-sm bg-dark text-white border-secondary" placeholder="Search findings...">
          <select id="sevSelect" onchange="filterFindings()" class="form-select form-select-sm bg-dark text-white border-secondary">
            <option value="ALL">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
          </select>
        </div>
      </div>

      <div class="table-responsive">
        <table class="table table-dark table-hover align-middle mb-0" id="findingsTable">
          <thead>
            <tr>
              <th style="width: 100px;">Severity</th>
              <th>Vulnerability Title</th>
              <th>Location</th>
              <th>Engine</th>
              <th>CWE</th>
            </tr>
          </thead>
          <tbody id="findingsBody"></tbody>
        </table>
      </div>
    </div>
  </div>

  <script>
    const findingsData = {findings_json};

    function renderFindings(list) {{
      const tbody = document.getElementById("findingsBody");
      tbody.innerHTML = "";
      if (list.length === 0) {{
        tbody.innerHTML = "<tr><td colspan='5' class='text-center text-muted py-4'>No findings match the current criteria.</td></tr>";
        return;
      }}
      list.forEach((f, idx) => {{
        const sevClass = "badge-" + (f.severity || "medium").toLowerCase();
        const tr = document.createElement("tr");
        tr.innerHTML = `
          <td><span class="badge ${{sevClass}}">${{f.severity}}</span></td>
          <td>
            <div class="fw-bold">${{f.title}}</div>
            <div class="text-secondary small">${{f.description || ""}}</div>
            ${{f.evidence_redacted ? `<pre class="evidence mt-1 mb-0">${{f.evidence_redacted}}</pre>` : ""}}
            ${{f.recommended_remediation ? `<div class="small text-info mt-1"><b>Fix:</b> ${{f.recommended_remediation}}</div>` : ""}}
          </td>
          <td><code>${{f.file_path}}:${{f.line_number || "N/A"}}</code></td>
          <td><span class="badge bg-secondary">${{f.engine}}</span></td>
          <td><small class="text-muted">${{f.cwe || "N/A"}}</small></td>
        `;
        tbody.appendChild(tr);
      }});
    }}

    function filterFindings() {{
      const q = document.getElementById("searchInput").value.toLowerCase();
      const sev = document.getElementById("sevSelect").value;
      const filtered = findingsData.filter(f => {{
        const matchQ = f.title.toLowerCase().includes(q) || f.file_path.toLowerCase().includes(q) || (f.description && f.description.toLowerCase().includes(q));
        const matchSev = (sev === "ALL" || f.severity === sev);
        return matchQ && matchSev;
      }});
      renderFindings(filtered);
    }}

    function downloadJSON() {{
      const blob = new Blob([JSON.stringify(findingsData, null, 2)], {{ type: "application/json" }});
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `scan_${scan_data.get('scan_id')}_findings.json`;
      a.click();
    }}

    window.addEventListener("DOMContentLoaded", () => {{
      renderFindings(findingsData);

      new Chart(document.getElementById("sevChart"), {{
        type: "doughnut",
        data: {{
          labels: ["Critical", "High", "Medium", "Low"],
          datasets: [{{
            data: [{summary.get('critical', 0)}, {summary.get('high', 0)}, {summary.get('medium', 0)}, {summary.get('low', 0)}],
            backgroundColor: ["#dc3545", "#fd7e14", "#ffc107", "#0dcaf0"],
            borderWidth: 0
          }}]
        }},
        options: {{ responsive: true, maintainAspectRatio: false, plugins: {{ legend: {{ position: "right", labels: {{ color: "#fff" }} }} }} }}
      }});

      new Chart(document.getElementById("catChart"), {{
        type: "bar",
        data: {{
          labels: ["Secrets", "SAST", "Dependencies", "Docker", "Git History"],
          datasets: [{{
            label: "Findings",
            data: [{summary.get('secrets_count', 0)}, {summary.get('sast_count', 0)}, {summary.get('dependencies_count', 0)}, {summary.get('docker_count', 0)}, {summary.get('git_history_count', 0)}],
            backgroundColor: "#38bdf8",
            borderRadius: 6
          }}]
        }},
        options: {{
          responsive: true,
          maintainAspectRatio: false,
          scales: {{
            y: {{ ticks: {{ color: "#fff" }}, grid: {{ color: "#334155" }} }},
            x: {{ ticks: {{ color: "#fff" }}, grid: {{ color: "transparent" }} }}
          }},
          plugins: {{ legend: {{ display: false }} }}
        }}
      }});
    }});
  </script>
</body>
</html>
"""
        return html
