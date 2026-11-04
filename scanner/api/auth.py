"""
Authentication & Role-Based Access Control (RBAC)
Supports JWT token generation, verification, and role enforcement.
"""

from datetime import datetime, timedelta, timezone
from functools import wraps
import hashlib
import logging
from typing import Any, Callable, Dict, List, Optional
from flask import request, jsonify
import jwt

from scanner.config import ScannerConfig

logger = logging.getLogger("scanner.api.auth")


class AuthManager:
    """Manages user authentication and token issuance."""

    _DEFAULT_USERS = {
        "admin": {
            "password_hash": hashlib.sha256("Admin@DevSecOps2026!".encode()).hexdigest(),
            "role": "admin",
            "name": "Security Administrator",
        },
        "analyst": {
            "password_hash": hashlib.sha256("Analyst@ScanGuard2026!".encode()).hexdigest(),
            "role": "analyst",
            "name": "Security Analyst",
        },
        "viewer": {
            "password_hash": hashlib.sha256("Viewer@AuditOnly2026!".encode()).hexdigest(),
            "role": "viewer",
            "name": "Audit Viewer",
        },
    }

    @classmethod
    def authenticate(cls, username: str, password: str) -> Optional[Dict[str, Any]]:
        user = cls._DEFAULT_USERS.get(username)
        if not user:
            return None
        pw_hash = hashlib.sha256(password.encode()).hexdigest()
        if user["password_hash"] == pw_hash:
            return {"username": username, "role": user["role"], "name": user["name"]}
        return None

    @classmethod
    def generate_token(cls, user_data: Dict[str, Any]) -> str:
        exp = datetime.now(timezone.utc) + timedelta(hours=ScannerConfig.JWT_EXPIRATION_HOURS)
        payload = {
            "sub": user_data["username"],
            "role": user_data["role"],
            "name": user_data["name"],
            "exp": exp,
            "iat": datetime.now(timezone.utc),
        }
        return jwt.encode(payload, ScannerConfig.JWT_SECRET, algorithm="HS256")

    @classmethod
    def verify_token(cls, token: str) -> Optional[Dict[str, Any]]:
        try:
            payload = jwt.decode(token, ScannerConfig.JWT_SECRET, algorithms=["HS256"])
            return payload
        except jwt.PyJWTError:
            return None


def jwt_required(optional: bool = False):
    def decorator(fn: Callable):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            auth_header = request.headers.get("Authorization", "")
            if not auth_header.startswith("Bearer "):
                if optional:
                    return fn(*args, user=None, **kwargs)
                return jsonify({"error": "Missing or malformed Authorization header. Bearer token required."}), 401

            token = auth_header.split(" ", 1)[1].strip()
            payload = AuthManager.verify_token(token)
            if not payload:
                return jsonify({"error": "Invalid or expired JWT token."}), 401

            return fn(*args, user=payload, **kwargs)
        return wrapper
    return decorator


def roles_accepted(*allowed_roles: str):
    def decorator(fn: Callable):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            user = kwargs.get("user")
            if not user or user.get("role") not in allowed_roles:
                return jsonify({
                    "error": f"Forbidden: Insufficient privileges. Required role in {list(allowed_roles)}."
                }), 403
            return fn(*args, **kwargs)
        return wrapper
    return decorator
