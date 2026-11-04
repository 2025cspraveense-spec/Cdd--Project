"""
Secret Leak Guard - Demo Web Application (Enterprise Edition).
Demonstrates 12-Factor App secure secret consumption from Environment or HashiCorp Vault.
Includes automated secret masking in logs, safe exception handling, and rotation monitoring.
"""

import os
import re
import uuid
import logging
from flask import Flask, jsonify, request, render_template_string

# Setup logging with a RedactingFormatter that masks potential leaks
class RedactingFormatter(logging.Formatter):
    """
    Custom formatter that redacts high-entropy keys, passwords, and tokens
    before log records leave the application boundary.
    """
    PATTERNS = [
        re.compile(r'\b(AKIA[0-9A-Z]{16})\b'),                           # AWS Access Key
        re.compile(r'\b(ghp_[A-Za-z0-9]{36,})\b'),                       # GitHub Token
        re.compile(r'\b(SLG_[A-Za-z0-9_-]{24,})\b'),                     # Custom Project Token
        re.compile(r'((?:password|passwd|pwd|secret)=)([^&\s]+)', re.I), # Passwords in URLs/queries
    ]

    @staticmethod
    def _mask_token(val: str) -> str:
        if len(val) <= 8:
            return "[REDACTED]"
        return val[:4] + "*" * (len(val) - 8) + val[-4:]

    def format(self, record):
        orig_msg = super().format(record)
        redacted = orig_msg
        for pattern in self.PATTERNS:
            def repl(m):
                if len(m.groups()) == 2:
                    return f"{m.group(1)}[REDACTED_PASSWORD]"
                return self._mask_token(m.group(1))
            redacted = pattern.sub(repl, redacted)
        return redacted

handler = logging.StreamHandler()
handler.setFormatter(RedactingFormatter("[%(asctime)s] %(levelname)s [%(name)s] %(message)s"))
logging.basicConfig(level=logging.INFO, handlers=[handler])
logger = logging.getLogger("SecretLeakGuard.App")

# Import Config & Lifecycle Monitors
try:
    from app.config import config
    from app.rotation_monitor import rotation_monitor
    from app.vault_client import mask_secret
except ImportError:
    from config import config
    from rotation_monitor import rotation_monitor
    from vault_client import mask_secret

app = Flask(__name__)
app.config["SECRET_KEY"] = config.secret_key

# ------------------------------------------------------------------------------
# Safe Exception Handling (Never leak stack traces or environment variables)
# ------------------------------------------------------------------------------
@app.errorhandler(Exception)
def handle_unexpected_error(err):
    incident_id = str(uuid.uuid4())[:8]
    logger.error("Unhandled exception [Incident #%s]: %s", incident_id, str(err))
    return jsonify({
        "error": "Internal server error occurred.",
        "incident_id": incident_id,
        "message": "Security policy prevents detailed error disclosure."
    }), 500

@app.errorhandler(404)
def handle_not_found(err):
    return jsonify({"error": "Resource not found"}), 404

@app.errorhandler(401)
def handle_unauthorized(err):
    return jsonify({"error": "Unauthorized access"}), 401


HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Secret Leak Guard - DevSecOps Demo</title>
    <style>
        :root {
            --bg: #0d1117;
            --surface: #161b22;
            --border: #30363d;
            --text: #c9d1d9;
            --heading: #58a6ff;
            --accent: #238636;
            --danger: #f85149;
            --warning: #d29922;
            --code-bg: #090d13;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: var(--bg);
            color: var(--text);
            margin: 0;
            padding: 30px 20px;
            display: flex;
            justify-content: center;
        }
        .container {
            max-width: 900px;
            width: 100%;
        }
        .header {
            border-bottom: 1px solid var(--border);
            padding-bottom: 20px;
            margin-bottom: 25px;
        }
        h1 {
            color: var(--heading);
            margin: 0 0 10px 0;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .badge {
            display: inline-block;
            font-size: 12px;
            font-weight: 600;
            padding: 4px 10px;
            border-radius: 20px;
            background-color: var(--accent);
            color: #ffffff;
        }
        .card {
            background-color: var(--surface);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 20px;
        }
        .card h2 {
            margin-top: 0;
            font-size: 18px;
            color: #f0f6fc;
            border-bottom: 1px solid var(--border);
            padding-bottom: 10px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 10px;
        }
        th, td {
            text-align: left;
            padding: 10px;
            border-bottom: 1px solid var(--border);
            font-size: 14px;
        }
        th {
            color: #8b949e;
        }
        code {
            background-color: var(--code-bg);
            padding: 3px 6px;
            border-radius: 4px;
            font-family: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, monospace;
            font-size: 13px;
        }
        .status-pill {
            padding: 2px 8px;
            border-radius: 12px;
            font-size: 12px;
            font-weight: bold;
        }
        .status-ok { background: #238636; color: white; }
        .status-missing { background: #6e7681; color: white; }
        .footer {
            margin-top: 30px;
            font-size: 13px;
            color: #8b949e;
            text-align: center;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Secret Leak Guard <span class="badge">Pipeline Security Active</span></h1>
            <p>Shift-Left DevSecOps demo enforcing secret zero-trust in Git & Docker containers.</p>
        </div>

        <div class="card">
            <h2>Active Secret Ingestion Posture</h2>
            <p>Secrets are loaded dynamically into memory via <strong>{{ posture.secret_provider }}</strong>. No credentials exist inside the Docker image layers or Git repository.</p>
            <table>
                <thead>
                    <tr>
                        <th>Configuration Key</th>
                        <th>Source</th>
                        <th>State</th>
                        <th>Safe Masked Value</th>
                    </tr>
                </thead>
                <tbody>
                    {% for key, val in posture.inspected_secrets.items() %}
                    <tr>
                        <td><code>{{ key }}</code></td>
                        <td>{{ val.source }}</td>
                        <td>
                            {% if val.configured %}
                                <span class="status-pill status-ok">Configured</span>
                            {% else %}
                                <span class="status-pill status-missing">Unset (Default)</span>
                            {% endif %}
                        </td>
                        <td><code>{{ val.masked_value }}</code></td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>

        <div class="card">
            <h2>DevSecOps Shift-Left Verification</h2>
            <ul>
                <li><strong>Pre-Commit Hook:</strong> Gitleaks blocks unauthorized commits locally before code reaches remote git.</li>
                <li><strong>CI Pipeline Stage 1:</strong> Gitleaks deep git history scanning on pull requests and pushes.</li>
                <li><strong>CI Pipeline Stage 2:</strong> Trivy secret scanner inspects Docker image layers &amp; metadata for baked secrets.</li>
                <li><strong>CI Pipeline Stage 3:</strong> Automated webhook alert with masked metadata (Never leaks plaintext secret).</li>
            </ul>
        </div>

        <div class="footer">
            Secret Leak Guard DevSecOps Project &bull; Zero Hardcoded Secrets Standard
        </div>
    </div>
</body>
</html>
"""

@app.route("/")
def index():
    posture = config.validate()
    return render_template_string(HTML_TEMPLATE, posture=posture)

@app.route("/health")
def health():
    return jsonify({
        "status": "healthy",
        "service": "secret-leak-guard-app",
        "secrets_secured": True,
        "provider": config.secret_mgr.provider
    })

@app.route("/api/secrets/status")
def secrets_status():
    """Returns masked diagnostic status of loaded secrets without revealing plaintext values."""
    posture = config.validate()
    return jsonify(posture)

@app.route("/api/secrets/rotation-status")
def secrets_rotation_status():
    """Returns secret expiration and rotation compliance metrics."""
    rotation_info = config.get_rotation_status()
    audit_result = rotation_monitor.audit_credentials(rotation_info)
    return jsonify({
        "rotation_policy": rotation_info["policy"],
        "provider": rotation_info["provider"],
        "compliance": audit_result,
        "credentials": rotation_info["credentials"]
    })

@app.route("/api/data", methods=["GET"])
def protected_data():
    """Protected endpoint requiring project API token."""
    auth_header = request.headers.get("Authorization", "")
    api_key_header = request.headers.get("X-API-Key", "")
    expected_token = config.slg_project_token

    if not expected_token:
        return jsonify({"error": "SLG_PROJECT_API_TOKEN is not configured on server"}), 500

    token = None
    if auth_header.startswith("Bearer "):
        token = auth_header.split(" ", 1)[1]
    elif api_key_header:
        token = api_key_header

    if not token or token != expected_token:
        logger.warning("Unauthorized access attempt from %s with token: %s", request.remote_addr, mask_secret(token))
        return jsonify({"error": "Unauthorized. Invalid or missing API token."}), 401

    logger.info("Authorized access granted for token: %s", mask_secret(token))
    return jsonify({
        "message": "Secure payload retrieved successfully.",
        "records": [
            {"id": 1, "description": "Customer Payment Batch A", "status": "processed"},
            {"id": 2, "description": "Customer Payment Batch B", "status": "verified"}
        ]
    })

if __name__ == "__main__":
    logger.info("Starting Secret Leak Guard app on port %d...", config.port)
    app.run(host="0.0.0.0", port=config.port, debug=False)
