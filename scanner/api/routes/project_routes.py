"""
Project, Dashboard Analytics, and Authentication Routes
"""

from flask import Blueprint, request, jsonify
from scanner.db import db
from scanner.api.auth import AuthManager

project_bp = Blueprint("project_bp", __name__)


@project_bp.route("/projects", methods=["GET"])
def list_projects():
    projects = db.list_projects()
    return jsonify({"total": len(projects), "projects": projects}), 200


@project_bp.route("/dashboard/metrics", methods=["GET"])
def get_dashboard_metrics():
    metrics = db.get_dashboard_metrics()
    return jsonify(metrics), 200


@project_bp.route("/auth/login", methods=["POST"])
def login():
    data = request.get_json(force=True, silent=True) or {}
    username = data.get("username", "")
    password = data.get("password", "")

    user = AuthManager.authenticate(username, password)
    if not user:
        return jsonify({"error": "Invalid username or password."}), 401

    token = AuthManager.generate_token(user)
    return jsonify({
        "message": "Authentication successful.",
        "access_token": token,
        "token_type": "Bearer",
        "user": user,
    }), 200
