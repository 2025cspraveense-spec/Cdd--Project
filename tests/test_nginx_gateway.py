"""
Tests for Nginx Edge Gateway & Reverse Proxy configuration and routing.
Verifies unified single-URL aggregation for:
  - Scanner Dashboard & REST API (Port 5050)
  - Runtime Hardened Demo App (Port 5000)
  - HashiCorp Vault (Port 8200)
  - Gateway Health Diagnostics (/nginx-health)
"""

import json
from io import BytesIO
from pathlib import Path
from unittest.mock import MagicMock, patch

from scripts.run_gateway import UnifiedGatewayHandler


def test_nginx_configuration_files_exist():
    """Verify that all Nginx configuration and deployment files are present and valid."""
    project_root = Path(__file__).resolve().parent.parent

    nginx_conf = project_root / "nginx" / "nginx.conf"
    default_conf = project_root / "nginx" / "conf.d" / "default.conf"
    dockerfile_nginx = project_root / "Dockerfile.nginx"
    docker_compose = project_root / "docker-compose.yml"

    assert nginx_conf.exists(), "nginx/nginx.conf must exist"
    assert default_conf.exists(), "nginx/conf.d/default.conf must exist"
    assert dockerfile_nginx.exists(), "Dockerfile.nginx must exist"
    assert docker_compose.exists(), "docker-compose.yml must exist"

    # Verify key directives in nginx.conf
    nginx_content = nginx_conf.read_text(encoding="utf-8")
    assert "client_max_body_size 100M;" in nginx_content
    assert "gzip on;" in nginx_content

    # Verify reverse proxy location blocks in default.conf
    default_content = default_conf.read_text(encoding="utf-8")
    assert "location = /nginx-health" in default_content
    assert "location /api/" in default_content
    assert "location /app/" in default_content
    assert "location /vault/" in default_content
    assert "location / {" in default_content
    assert "proxy_pass http://scanner_api;" in default_content
    assert "proxy_pass http://runtime_app/;" in default_content
    assert "proxy_pass http://vault_service/;" in default_content

    # Verify security headers in default.conf
    assert 'add_header X-Frame-Options "SAMEORIGIN"' in default_content
    assert 'add_header X-Content-Type-Options "nosniff"' in default_content
    assert 'add_header X-XSS-Protection "1; mode=block"' in default_content

    # Verify docker-compose has gateway service
    compose_content = docker_compose.read_text(encoding="utf-8")
    assert "gateway:" in compose_content
    assert "slg-gateway" in compose_content
    assert '"80:80"' in compose_content
    assert '"8080:80"' in compose_content


def _create_mock_handler(path: str, method: str = "GET", headers=None, body=b""):
    """Creates an in-memory instance of UnifiedGatewayHandler for testing without opening network sockets."""
    mock_request = MagicMock()
    mock_request.makefile.return_value = BytesIO(body)
    client_address = ("127.0.0.1", 12345)
    mock_server = MagicMock()

    handler = UnifiedGatewayHandler.__new__(UnifiedGatewayHandler)
    handler.request = mock_request
    handler.client_address = client_address
    handler.server = mock_server
    handler.path = path
    handler.command = method
    handler.close_connection = True
    handler.wfile = BytesIO()
    handler.rfile = BytesIO(body)
    handler.headers = headers or {"Host": "localhost"}

    # Mock response capturing methods
    handler._sent_headers = {}
    handler._status_code = None

    def fake_send_response(code, message=None):
        handler._status_code = code

    def fake_send_header(keyword, value):
        handler._sent_headers[keyword.lower()] = value

    def fake_end_headers():
        pass

    handler.send_response = fake_send_response
    handler.send_header = fake_send_header
    handler.end_headers = fake_end_headers

    return handler


def test_gateway_health_endpoint_in_memory():
    """Verify that /nginx-health returns 200 with proper JSON metadata."""
    handler = _create_mock_handler("/nginx-health")
    handler.do_GET()

    assert handler._status_code == 200
    assert "secret-leak-guard" in handler._sent_headers.get("x-gateway", "").lower()
    data = json.loads(handler.wfile.getvalue().decode("utf-8"))
    assert data["status"] == "healthy"
    assert "/" in data["routes"]
    assert "/app/" in data["routes"]
    assert "/vault/" in data["routes"]
    assert "/api/v1/" in data["routes"]


def test_gateway_redirects_naked_app_path_in_memory():
    """Verify accessing /app redirects with 301 to /app/."""
    handler = _create_mock_handler("/app")
    handler.do_GET()

    assert handler._status_code == 301
    assert handler._sent_headers.get("location") == "/app/"


def test_gateway_redirects_naked_vault_path_in_memory():
    """Verify accessing /vault redirects with 301 to /vault/."""
    handler = _create_mock_handler("/vault")
    handler.do_GET()

    assert handler._status_code == 301
    assert handler._sent_headers.get("location") == "/vault/"


def test_gateway_handles_upstream_failure_gracefully():
    """Verify that connection failures to upstream services return 503 JSON."""
    from urllib.error import URLError

    handler = _create_mock_handler("/app/health")
    with patch("scripts.run_gateway.urlopen", side_effect=URLError("Connection refused")):
        handler.do_GET()

    assert handler._status_code == 503
    data = json.loads(handler.wfile.getvalue().decode("utf-8"))
    assert data["error"] == "Upstream service temporarily unavailable"
    assert "Connection refused" in data["reason"]


def test_gateway_successful_proxy_pass():
    """Verify that a successful upstream call forwards status, headers, and body."""
    handler = _create_mock_handler("/api/v1/health")

    mock_resp = MagicMock()
    mock_resp.status = 200
    mock_resp.headers = {"Content-Type": "application/json"}
    mock_resp.read.return_value = b'{"status":"ok"}'

    with patch("scripts.run_gateway.urlopen") as mock_urlopen:
        mock_urlopen.return_value.__enter__.return_value = mock_resp
        handler.do_GET()

    assert handler._status_code == 200
    assert handler.wfile.getvalue() == b'{"status":"ok"}'
