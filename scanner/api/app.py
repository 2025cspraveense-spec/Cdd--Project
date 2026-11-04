"""
Flask Application Factory for Universal Security Scanner
"""

import logging
from pathlib import Path
from flask import Flask, jsonify, request, send_from_directory, Response

from scanner.config import ScannerConfig
from scanner.db import db
from scanner.api.routes import health_bp, scan_bp, report_bp, project_bp

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [%(name)s]: %(message)s",
)
logger = logging.getLogger("scanner.api")


def create_app() -> Flask:
    app = Flask(__name__, static_folder=str(ScannerConfig.FRONTEND_DIR), static_url_path="/")
    app.config["SECRET_KEY"] = ScannerConfig.SECRET_KEY
    app.config["MAX_CONTENT_LENGTH"] = ScannerConfig.MAX_UPLOAD_SIZE_MB * 1024 * 1024

    @app.after_request
    def set_security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Access-Control-Allow-Origin"] = "*"
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization, X-Requested-With"
        return response

    @app.before_request
    def handle_cors_preflight():
        if request.method == "OPTIONS":
            res = Response()
            res.headers["Access-Control-Allow-Origin"] = "*"
            res.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
            res.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization, X-Requested-With"
            return res

    app.register_blueprint(health_bp, url_prefix="/api/v1")
    app.register_blueprint(scan_bp, url_prefix="/api/v1")
    app.register_blueprint(report_bp, url_prefix="/api/v1")
    app.register_blueprint(project_bp, url_prefix="/api/v1")

    @app.errorhandler(404)
    def not_found(e):
        return jsonify({"error": "Resource not found."}), 404

    @app.errorhandler(413)
    def payload_too_large(e):
        return jsonify({
            "error": f"Upload payload exceeds maximum allowable size of {ScannerConfig.MAX_UPLOAD_SIZE_MB} MB."
        }), 413

    @app.errorhandler(500)
    def server_error(e):
        logger.error("Internal server error: %s", e)
        return jsonify({"error": "Internal server error occurred."}), 500

    @app.route("/", methods=["GET"])
    @app.route("/dashboard", methods=["GET"])
    def serve_dashboard():
        index_file = ScannerConfig.FRONTEND_DIR / "index.html"
        if index_file.exists():
            return send_from_directory(str(ScannerConfig.FRONTEND_DIR), "index.html")
        return render_default_portal()

    logger.info("Universal Security Scanner API initialized successfully.")
    return app


def render_default_portal() -> str:
    return r"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Secret Leak Guard — Universal Security Scanner</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
  <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.css" rel="stylesheet">
  <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.2/dist/chart.umd.min.js"></script>
  <style>
    :root {
      --bg: #0b0f19;
      --card-bg: #111827;
      --border: #1f2937;
      --accent: #38bdf8;
      --text: #f9fafb;
    }
    body { background-color: var(--bg); color: var(--text); font-family: system-ui, -apple-system, sans-serif; }
    .card { background-color: var(--card-bg); border: 1px solid var(--border); border-radius: 12px; }
    .nav-tabs .nav-link { color: #9ca3af; border: none; }
    .nav-tabs .nav-link.active { background: transparent; color: var(--accent); border-bottom: 2px solid var(--accent); }
    .badge-critical { background: #ef4444; color: white; }
    .badge-high { background: #f97316; color: white; }
    .badge-medium { background: #eab308; color: black; }
    .badge-low { background: #06b6d4; color: black; }
    .table-dark { --bs-table-bg: var(--card-bg); --bs-table-border-color: var(--border); }
  </style>
</head>
<body>
  <nav class="navbar navbar-dark border-bottom border-secondary px-4 py-3">
    <div class="d-flex align-items-center gap-2">
      <i class="bi bi-shield-lock-fill text-info fs-3"></i>
      <div>
        <h5 class="mb-0 fw-bold">Secret Leak Guard</h5>
        <small class="text-secondary">Universal Source Code Security Scanner (Gitleaks, Semgrep, Trivy, OSV)</small>
      </div>
    </div>
    <div class="d-flex align-items-center gap-3">
      <span class="badge bg-success py-2 px-3" id="dbStatusBadge">MongoDB Active</span>
      <button class="btn btn-outline-info btn-sm" onclick="loadDashboard()"><i class="bi bi-arrow-clockwise"></i> Refresh</button>
    </div>
  </nav>

  <div class="container-fluid px-4 py-4">
    <div class="card p-4 mb-4 shadow-sm">
      <h6 class="fw-bold mb-3 text-info"><i class="bi bi-play-circle"></i> Launch New Security Scan</h6>
      <ul class="nav nav-tabs mb-3" id="scanTabs">
        <li class="nav-item"><a class="nav-link active" data-bs-toggle="tab" href="#tab-local">Local Folder</a></li>
        <li class="nav-item"><a class="nav-link" data-bs-toggle="tab" href="#tab-upload">Upload ZIP / File</a></li>
        <li class="nav-item"><a class="nav-link" data-bs-toggle="tab" href="#tab-github">GitHub Repository</a></li>
        <li class="nav-item"><a class="nav-link" data-bs-toggle="tab" href="#tab-docker">Dockerfile / Compose</a></li>
      </ul>
      <div class="tab-content">
        <div class="tab-pane fade show active" id="tab-local">
          <div class="row g-2 align-items-center">
            <div class="col-md-5">
              <input type="text" id="localPath" class="form-control bg-dark text-white border-secondary" placeholder="Path (e.g. E:\Cdd\secret-leak-guard\bad-example)">
            </div>
            <div class="col-md-3">
              <input type="text" id="localProjName" class="form-control bg-dark text-white border-secondary" placeholder="Project Name (optional)">
            </div>
            <div class="col-md-2">
              <button onclick="submitLocalScan()" class="btn btn-info w-100 fw-bold"><i class="bi bi-lightning-charge"></i> Scan Folder</button>
            </div>
          </div>
        </div>
        <div class="tab-pane fade" id="tab-upload">
          <div class="row g-2 align-items-center">
            <div class="col-md-5">
              <input type="file" id="uploadFile" class="form-control bg-dark text-white border-secondary">
            </div>
            <div class="col-md-3">
              <input type="text" id="uploadProjName" class="form-control bg-dark text-white border-secondary" placeholder="Project Name (optional)">
            </div>
            <div class="col-md-2">
              <button onclick="submitUploadScan()" class="btn btn-info w-100 fw-bold"><i class="bi bi-upload"></i> Upload & Scan</button>
            </div>
          </div>
        </div>
        <div class="tab-pane fade" id="tab-github">
          <div class="row g-2 align-items-center">
            <div class="col-md-5">
              <input type="url" id="githubUrl" class="form-control bg-dark text-white border-secondary" placeholder="https://github.com/org/repo">
            </div>
            <div class="col-md-3">
              <input type="text" id="githubBranch" class="form-control bg-dark text-white border-secondary" placeholder="Branch (e.g. main)">
            </div>
            <div class="col-md-2">
              <button onclick="submitGithubScan()" class="btn btn-info w-100 fw-bold"><i class="bi bi-github"></i> Clone & Scan</button>
            </div>
          </div>
        </div>
        <div class="tab-pane fade" id="tab-docker">
          <textarea id="dockerContent" rows="3" class="form-control bg-dark text-white border-secondary mb-2" placeholder="Paste Dockerfile or docker-compose.yml content..."></textarea>
          <button onclick="submitDockerScan()" class="btn btn-info fw-bold"><i class="bi bi-box-seam"></i> Scan Dockerfile</button>
        </div>
      </div>
      <div id="scanStatusAlert" class="mt-3 d-none"></div>
    </div>

    <div class="row g-3 mb-4" id="kpiContainer">
      <div class="col-md-2">
        <div class="card p-3 text-center">
          <small class="text-secondary text-uppercase fw-semibold">Projects Scanned</small>
          <div class="fs-2 fw-bold" id="kpiProjects">-</div>
        </div>
      </div>
      <div class="col-md-2">
        <div class="card p-3 text-center">
          <small class="text-secondary text-uppercase fw-semibold">Total Findings</small>
          <div class="fs-2 fw-bold text-info" id="kpiFindings">-</div>
        </div>
      </div>
      <div class="col-md-2">
        <div class="card p-3 text-center">
          <small class="text-secondary text-uppercase fw-semibold">Critical Vulnerabilities</small>
          <div class="fs-2 fw-bold text-danger" id="kpiCritical">-</div>
        </div>
      </div>
      <div class="col-md-2">
        <div class="card p-3 text-center">
          <small class="text-secondary text-uppercase fw-semibold">High Severity</small>
          <div class="fs-2 fw-bold text-warning" id="kpiHigh">-</div>
        </div>
      </div>
      <div class="col-md-2">
        <div class="card p-3 text-center">
          <small class="text-secondary text-uppercase fw-semibold">Exposed Secrets</small>
          <div class="fs-2 fw-bold text-warning" id="kpiSecrets">-</div>
        </div>
      </div>
      <div class="col-md-2">
        <div class="card p-3 text-center">
          <small class="text-secondary text-uppercase fw-semibold">Avg Risk Score</small>
          <div class="fs-2 fw-bold" id="kpiScore">-</div>
        </div>
      </div>
    </div>

    <div class="card p-3 mb-4">
      <h6 class="fw-bold mb-3"><i class="bi bi-clock-history"></i> Recent Security Scans</h6>
      <div class="table-responsive">
        <table class="table table-dark table-hover align-middle mb-0">
          <thead>
            <tr>
              <th>Scan ID</th>
              <th>Project</th>
              <th>Source</th>
              <th>Status</th>
              <th>Grade</th>
              <th>Risk Score</th>
              <th>Findings</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody id="scansTableBody">
            <tr><td colspan="8" class="text-center text-muted py-3">Loading scans...</td></tr>
          </tbody>
        </table>
      </div>
    </div>
  </div>

  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
  <script>
    async function loadDashboard() {
      try {
        const hRes = await fetch('/api/v1/health');
        const hData = await hRes.json();
        document.getElementById('dbStatusBadge').innerText = hData.database.mode;

        const mRes = await fetch('/api/v1/dashboard/metrics');
        const m = await mRes.json();
        document.getElementById('kpiProjects').innerText = m.total_projects || 0;
        document.getElementById('kpiFindings').innerText = m.total_findings || 0;
        document.getElementById('kpiCritical').innerText = m.severity_distribution.critical || 0;
        document.getElementById('kpiHigh').innerText = m.severity_distribution.high || 0;
        document.getElementById('kpiSecrets').innerText = m.category_distribution.secrets || 0;
        document.getElementById('kpiScore').innerText = m.average_risk_score + '/100';

        renderScans(m.recent_scans || []);
      } catch (err) {
        console.error(err);
      }
    }

    function renderScans(scans) {
      const tbody = document.getElementById('scansTableBody');
      tbody.innerHTML = '';
      if (!scans.length) {
        tbody.innerHTML = '<tr><td colspan="8" class="text-center text-muted py-3">No scans recorded yet. Launch one above!</td></tr>';
        return;
      }
      scans.forEach(s => {
        const gradeColor = (s.security_grade === 'A+' || s.security_grade === 'A') ? 'success' : (s.security_grade === 'B' ? 'info' : (s.security_grade === 'C' ? 'warning' : 'danger'));
        const tr = document.createElement('tr');
        tr.innerHTML = `
          <td><code>${s.scan_id}</code></td>
          <td class="fw-bold">${s.project_name}</td>
          <td><span class="badge bg-secondary">${s.source_type}</span></td>
          <td><span class="badge bg-${s.status === 'COMPLETED' ? 'success' : (s.status === 'FAILED' ? 'danger' : 'info')}">${s.status}</span></td>
          <td><span class="badge bg-${gradeColor}">${s.security_grade}</span></td>
          <td><b>${s.risk_score}</b>/100</td>
          <td>${s.summary ? s.summary.total_findings : 0} findings</td>
          <td>
            <a href="/api/v1/scans/${s.scan_id}/report/html" target="_blank" class="btn btn-outline-info btn-sm me-1"><i class="bi bi-eye"></i> Audit</a>
            <a href="/api/v1/scans/${s.scan_id}/report/pdf" class="btn btn-outline-danger btn-sm me-1"><i class="bi bi-file-earmark-pdf"></i> PDF</a>
            <a href="/api/v1/scans/${s.scan_id}/report/json" class="btn btn-outline-success btn-sm"><i class="bi bi-braces"></i> JSON</a>
          </td>
        `;
        tbody.appendChild(tr);
      });
    }

    async function submitLocalScan() {
      const path = document.getElementById('localPath').value.trim();
      const proj = document.getElementById('localProjName').value.trim();
      if (!path) return alert('Please enter a folder path.');
      showAlert('Initiating local scan...', 'info');
      const res = await fetch('/api/v1/scans/local', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ path: path, project_name: proj || undefined })
      });
      const data = await res.json();
      if (res.ok) {
        pollStatus(data.scan_id);
      } else {
        showAlert('Error: ' + data.error, 'danger');
      }
    }

    async function submitUploadScan() {
      const fileInput = document.getElementById('uploadFile');
      if (!fileInput.files.length) return alert('Please select a file.');
      const fd = new FormData();
      fd.append('file', fileInput.files[0]);
      const proj = document.getElementById('uploadProjName').value.trim();
      if (proj) fd.append('project_name', proj);
      showAlert('Uploading and preparing sandbox...', 'info');
      const res = await fetch('/api/v1/scans/upload', { method: 'POST', body: fd });
      const data = await res.json();
      if (res.ok) {
        pollStatus(data.scan_id);
      } else {
        showAlert('Error: ' + data.error, 'danger');
      }
    }

    async function submitGithubScan() {
      const url = document.getElementById('githubUrl').value.trim();
      const branch = document.getElementById('githubBranch').value.trim();
      if (!url) return alert('Please enter a repository URL.');
      showAlert('Validating URL and cloning...', 'info');
      const res = await fetch('/api/v1/scans/github', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ repo_url: url, branch: branch || undefined })
      });
      const data = await res.json();
      if (res.ok) {
        pollStatus(data.scan_id);
      } else {
        showAlert('Error: ' + data.error, 'danger');
      }
    }

    async function submitDockerScan() {
      const content = document.getElementById('dockerContent').value.trim();
      if (!content) return alert('Please paste Dockerfile or compose content.');
      showAlert('Scanning Docker configuration...', 'info');
      const res = await fetch('/api/v1/scans/docker', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ dockerfile_content: content })
      });
      const data = await res.json();
      if (res.ok) {
        pollStatus(data.scan_id);
      } else {
        showAlert('Error: ' + data.error, 'danger');
      }
    }

    function showAlert(msg, type) {
      const el = document.getElementById('scanStatusAlert');
      el.className = `alert alert-${type} mt-3`;
      el.innerHTML = msg;
      el.classList.remove('d-none');
    }

    function pollStatus(scanId) {
      const timer = setInterval(async () => {
        try {
          const res = await fetch(`/api/v1/scans/${scanId}/status`);
          const s = await res.json();
          showAlert(`<b>Scan in Progress (${s.progress_percentage}%):</b> ${s.current_engine || s.status}`, 'info');
          if (s.status === 'COMPLETED') {
            clearInterval(timer);
            showAlert(`<b>Scan Completed!</b> Security Grade: <b>${s.security_grade}</b> (${s.risk_score}/100) with ${s.summary ? s.summary.total_findings : 0} findings. <a href="/api/v1/scans/${scanId}/report/html" target="_blank" class="alert-link">View Full Audit Report</a>`, 'success');
            loadDashboard();
          } else if (s.status === 'FAILED') {
            clearInterval(timer);
            showAlert(`<b>Scan Failed:</b> ${s.error_message}`, 'danger');
            loadDashboard();
          }
        } catch (e) {
          clearInterval(timer);
        }
      }, 1500);
    }

    window.addEventListener('DOMContentLoaded', loadDashboard);
  </script>
</body>
</html>"""
