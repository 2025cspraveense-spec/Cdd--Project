"""
Universal Security Scanner Entrypoint Runner
Launches the Flask API server and DevSecOps portal.
"""

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from scanner.config import ScannerConfig
from scanner.api.app import create_app

if __name__ == "__main__":
    app = create_app()
    port = int(os.getenv("SCANNER_PORT", ScannerConfig.PORT))
    host = os.getenv("SCANNER_HOST", ScannerConfig.HOST)

    print("=" * 70)
    print(" SECRET LEAK GUARD — UNIVERSAL SOURCE CODE SECURITY SCANNER")
    print("=" * 70)
    print(f" * Portal Dashboard : http://localhost:{port}/")
    print(f" * REST API Base    : http://localhost:{port}/api/v1")
    print(f" * Health Endpoint  : http://localhost:{port}/api/v1/health")
    print(f" * Database URI     : {ScannerConfig.MONGO_URI}")
    print("=" * 70)

    app.run(host=host, port=port, debug=ScannerConfig.DEBUG)
