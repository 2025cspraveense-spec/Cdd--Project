"""
API Route Blueprints
"""

from .health_routes import health_bp
from .scan_routes import scan_bp
from .report_routes import report_bp
from .project_routes import project_bp

__all__ = ["health_bp", "scan_bp", "report_bp", "project_bp"]
