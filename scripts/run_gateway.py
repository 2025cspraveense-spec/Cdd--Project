#!/usr/bin/env python3
"""
Secret Leak Guard - Native Unified Gateway Runner
Replicates Nginx reverse proxy behavior in pure Python for local environments,
connecting all services into a single URL without requiring Docker.

Routes:
  - http://localhost:8080/        -> Scanner UI & API (localhost:5050)
  - http://localhost:8080/api/v1/ -> Scanner REST API (localhost:5050)
  - http://localhost:8080/app/    -> Runtime Hardened Demo App (localhost:5000)
  - http://localhost:8080/vault/  -> HashiCorp Vault (localhost:8200)
  - http://localhost:8080/nginx-health -> Gateway Health Check
"""

import sys
import json
import logging
import argparse
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [Gateway]: %(message)s"
)
logger = logging.getLogger("Gateway")

DEFAULT_UPSTREAMS = {
    "scanner": "http://127.0.0.1:5050",
    "app": "http://127.0.0.1:5000",
    "vault": "http://127.0.0.1:8200",
}


class UnifiedGatewayHandler(BaseHTTPRequestHandler):
    """Reverse-proxy HTTP request handler unifying multiple services into a single URL."""

    upstreams = DEFAULT_UPSTREAMS

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With")
        self.end_headers()

    def do_GET(self):
        self._proxy_request("GET")

    def do_POST(self):
        self._proxy_request("POST")

    def do_PUT(self):
        self._proxy_request("PUT")

    def do_DELETE(self):
        self._proxy_request("DELETE")

    def _proxy_request(self, method: str):
        path = self.path

        # 1. Gateway Health Check Endpoint
        if path == "/nginx-health" or path == "/gateway/health":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("X-Gateway", "Secret-Leak-Guard-Python-Gateway/2.0")
            self.end_headers()
            payload = {
                "status": "healthy",
                "service": "secret-leak-guard-gateway",
                "version": "2.0.0",
                "unified_url": f"http://{self.headers.get('Host', 'localhost')}/",
                "routes": {
                    "/": "Universal Security Scanner UI (React 18 & Port 5050)",
                    "/api/v1/": "Scanner REST API & Execution Engine",
                    "/app/": "Runtime Hardened Web Application & Secret Telemetry (Port 5000)",
                    "/vault/": "HashiCorp Vault UI & REST API (Port 8200)",
                },
                "upstreams": self.upstreams
            }
            self.wfile.write(json.dumps(payload, indent=2).encode("utf-8"))
            return

        # 2. Redirect naked /app to /app/
        if path == "/app":
            self.send_response(301)
            self.send_header("Location", "/app/")
            self.end_headers()
            return

        # 3. Redirect naked /vault to /vault/
        if path == "/vault":
            self.send_response(301)
            self.send_header("Location", "/vault/")
            return

        # 4. Route Selection & Target URL mapping
        if path.startswith("/app/"):
            subpath = path[4:]  # retains trailing / or starts with /
            target_base = self.upstreams["app"]
            target_url = f"{target_base}{subpath}"
            prefix = "/app"
        elif path.startswith("/vault/"):
            subpath = path[6:]
            target_base = self.upstreams["vault"]
            target_url = f"{target_base}{subpath}"
            prefix = "/vault"
        else:
            # All other paths (/, /api/v1/..., static assets) route to Scanner API
            target_base = self.upstreams["scanner"]
            target_url = f"{target_base}{path}"
            prefix = None

        # Read incoming request body if present
        body = None
        content_length = self.headers.get("Content-Length")
        if content_length:
            try:
                body = self.rfile.read(int(content_length))
            except Exception as e:
                logger.warning(f"Error reading request body: {e}")

        # Construct outgoing proxy request
        req = Request(target_url, data=body, method=method)
        for header, value in self.headers.items():
            if header.lower() not in ("host", "content-length"):
                req.add_header(header, value)

        # Set standard forward headers
        client_ip = self.client_address[0] if self.client_address else "127.0.0.1"
        req.add_header("X-Real-IP", client_ip)
        req.add_header("X-Forwarded-For", client_ip)
        req.add_header("X-Forwarded-Proto", "http")
        if prefix:
            req.add_header("X-Forwarded-Prefix", prefix)

        try:
            with urlopen(req, timeout=300) as response:
                status_code = response.status
                self.send_response(status_code)
                for header, value in response.headers.items():
                    if header.lower() not in ("transfer-encoding", "content-length"):
                        self.send_header(header, value)
                self.send_header("X-Gateway", "Secret-Leak-Guard-Gateway/2.0")
                response_data = response.read()
                self.send_header("Content-Length", str(len(response_data)))
                self.end_headers()
                self.wfile.write(response_data)
        except HTTPError as e:
            self.send_response(e.code)
            for header, value in e.headers.items():
                if header.lower() not in ("transfer-encoding", "content-length"):
                    self.send_header(header, value)
            self.end_headers()
            self.wfile.write(e.read())
        except URLError as e:
            logger.error(f"Upstream connection failed for {target_url}: {e.reason}")
            self.send_response(503)
            self.send_header("Content-Type", "application/json")
            self.send_header("X-Gateway", "Secret-Leak-Guard-Gateway/2.0")
            self.end_headers()
            err_payload = {
                "error": "Upstream service temporarily unavailable",
                "target": target_url,
                "reason": str(e.reason),
                "remediation": "Check if the target upstream service is running."
            }
            self.wfile.write(json.dumps(err_payload).encode("utf-8"))
        except Exception as e:
            logger.error(f"Unexpected gateway proxy error: {e}")
            self.send_response(500)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"error": "Internal Gateway Error", "detail": str(e)}).encode("utf-8"))


def run_gateway(host: str = "0.0.0.0", port: int = 8080):
    server_address = (host, port)
    try:
        httpd = HTTPServer(server_address, UnifiedGatewayHandler)
    except OSError as err:
        if port == 80:
            logger.warning(f"Port 80 unavailable ({err}). Falling back to port 8080...")
            port = 8080
            server_address = (host, port)
            httpd = HTTPServer(server_address, UnifiedGatewayHandler)
        else:
            raise

    print("=" * 70)
    print("🛡️  SECRET LEAK GUARD - UNIFIED REVERSE PROXY GATEWAY")
    print("=" * 70)
    print(f" * Unified Portal URL  : http://localhost:{port}/")
    print(f" * Health Diagnostics  : http://localhost:{port}/nginx-health")
    print(f" * Scanner Dashboard   : http://localhost:{port}/")
    print(f" * Scanner REST API    : http://localhost:{port}/api/v1/")
    print(f" * Runtime Secured App : http://localhost:{port}/app/")
    print(f" * HashiCorp Vault     : http://localhost:{port}/vault/")
    print("=" * 70)
    logger.info(f"Gateway listening on http://{host}:{port}/")

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        logger.info("Gateway shutting down...")
        httpd.server_close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Secret Leak Guard Unified Gateway")
    parser.add_argument("--host", default="0.0.0.0", help="Binding host (default 0.0.0.0)")
    parser.add_argument("--port", type=int, default=8080, help="Binding port (default 8080)")
    args = parser.parse_args()
    run_gateway(host=args.host, port=args.port)
