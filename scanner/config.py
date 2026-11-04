"""
Configuration Management for Universal Security Scanner
"""

import os
import tempfile
from pathlib import Path


class ScannerConfig:
    """Central configuration for Scanner API and Execution Engines."""

    # Server Settings
    HOST: str = os.getenv("SCANNER_HOST", "0.0.0.0")
    PORT: int = int(os.getenv("SCANNER_PORT", "5050"))
    DEBUG: bool = os.getenv("SCANNER_DEBUG", "false").lower() == "true"
    SECRET_KEY: str = os.getenv("SECRET_KEY", "devsecops-super-secure-scanner-key-32b")
    JWT_SECRET: str = os.getenv("JWT_SECRET", "jwt-scanner-secret-token-sign-key-99")
    JWT_EXPIRATION_HOURS: int = int(os.getenv("JWT_EXPIRATION_HOURS", "24"))

    # Database Settings (MongoDB is required)
    MONGO_URI: str = os.getenv("MONGO_URI", "mongodb://localhost:27017/secret_leak_guard")
    MONGO_DB_NAME: str = os.getenv("MONGO_DB_NAME", "secret_leak_guard")
    MONGO_TIMEOUT_MS: int = int(os.getenv("MONGO_TIMEOUT_MS", "2000"))

    # Ingestion & Quarantine Sandbox
    MAX_UPLOAD_SIZE_MB: int = int(os.getenv("MAX_UPLOAD_SIZE_MB", "100"))
    MAX_UNCOMPRESSED_SIZE_MB: int = int(os.getenv("MAX_UNCOMPRESSED_SIZE_MB", "500"))
    MAX_ARCHIVE_FILES: int = int(os.getenv("MAX_ARCHIVE_FILES", "10000"))
    WORKSPACE_ROOT: Path = Path(
        os.getenv("SCAN_WORKSPACE_DIR", str(Path(tempfile.gettempdir()) / "scanner_workspaces"))
    )

    # Engine Timeouts (seconds)
    ENGINE_TIMEOUT_SECONDS: int = int(os.getenv("ENGINE_TIMEOUT_SECONDS", "90"))
    GIT_CLONE_TIMEOUT_SECONDS: int = int(os.getenv("GIT_CLONE_TIMEOUT_SECONDS", "60"))

    # File and Extension Guardrails
    ALLOWED_ARCHIVE_EXTENSIONS: set = {".zip", ".tar", ".gz", ".tgz"}
    ALLOWED_SOURCE_EXTENSIONS: set = {
        ".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".go", ".rb", ".php",
        ".cs", ".c", ".cpp", ".h", ".json", ".yaml", ".yml", ".env", ".toml",
        ".xml", ".gradle", ".properties", ".sh", ".bash", ".dockerfile"
    }

    # Static Assets & Frontend Path
    FRONTEND_DIR: Path = Path(os.getenv("FRONTEND_DIR", str(Path(__file__).parent.parent / "frontend" / "build")))

    @classmethod
    def ensure_directories(cls) -> None:
        """Create necessary workspace directories."""
        cls.WORKSPACE_ROOT.mkdir(parents=True, exist_ok=True)


ScannerConfig.ensure_directories()
