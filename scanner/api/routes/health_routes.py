"""
Health and Status Routes
"""

from flask import Blueprint, jsonify
from scanner.config import ScannerConfig
from scanner.db import db
from scanner.orchestrator import orchestrator

health_bp = Blueprint("health_bp", __name__)


@health_bp.route("/health", methods=["GET"])
def health_check():
    """Returns application health, database status, and engine readiness matrix."""
    return jsonify({
        "status": "healthy",
        "service": "Secret Leak Guard — Universal Security Scanner",
        "version": "2.0.0",
        "database": {
            "mode": db.db_mode if hasattr(db, "db_mode") else ("MongoDB (Connected)" if db.is_connected else "MongoDB (In-Memory Fallback)"),
            "connected": db.is_connected,
            "database_name": ScannerConfig.MONGO_DB_NAME,
        },
        "engines": {
            "gitleaks": orchestrator.secret_engine.is_available(),
            "semgrep": orchestrator.sast_engine.is_semgrep_available(),
            "bandit": orchestrator.sast_engine.is_bandit_available(),
            "pip_audit": orchestrator.dependency_engine.is_pip_audit_available(),
            "osv_scanner": orchestrator.dependency_engine.is_osv_scanner_available(),
            "trivy": orchestrator.docker_engine.is_trivy_available(),
            "native_ast_sast": True,
            "native_cve_database": True,
            "native_docker_checker": True,
            "native_entropy_detector": True,
        },
    }), 200
