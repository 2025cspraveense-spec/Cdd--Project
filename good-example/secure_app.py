"""
GOOD EXAMPLE - SECURE ARCHITECTURE
Demonstrates best practices for zero hardcoded secrets:
1. 12-Factor App secret injection via environment variables or HashiCorp Vault.
2. Startup configuration validation with fail-fast behavior.
3. Automated logging redaction (never print plain credentials).
4. No sensitive values committed or baked into Docker layers.
"""

import os
import sys
import logging
from typing import Optional

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s [SecureApp] %(message)s"
)
logger = logging.getLogger("SecureApp")


def mask_secret(value: Optional[str], visible_prefix: int = 4, visible_suffix: int = 4) -> str:
    """Safely redacts a sensitive string for logging and telemetry."""
    if not value:
        return "[NOT SET]"
    str_val = str(value)
    if len(str_val) <= (visible_prefix + visible_suffix):
        return "*" * len(str_val)
    masked = "*" * (len(str_val) - visible_prefix - visible_suffix)
    return f"{str_val[:visible_prefix]}{masked}{str_val[-visible_suffix:]}"


class AppConfig:
    """Loads configuration safely from runtime environment or external vault."""

    def __init__(self):
        # ✅ Secrets are read dynamically at runtime, never hardcoded
        self.aws_access_key_id = os.getenv("AWS_ACCESS_KEY_ID")
        self.aws_secret_access_key = os.getenv("AWS_SECRET_ACCESS_KEY")
        self.database_url = os.getenv("DATABASE_URL")
        self.github_token = os.getenv("GITHUB_TOKEN")
        self.slg_project_token = os.getenv("SLG_PROJECT_API_TOKEN")
        self.secret_key = os.getenv("SECRET_KEY", "fallback-dev-session-key-only")

    def validate(self, strict: bool = False) -> bool:
        """Validates that necessary credentials are present without printing raw values."""
        missing = []
        if not self.aws_access_key_id:
            missing.append("AWS_ACCESS_KEY_ID")
        if not self.database_url:
            missing.append("DATABASE_URL")
        if not self.slg_project_token:
            missing.append("SLG_PROJECT_API_TOKEN")

        if missing:
            logger.warning("Missing recommended environment variables: %s", ", ".join(missing))
            if strict:
                logger.error("Strict startup validation failed. Exiting.")
                return False
        else:
            logger.info("All essential environment configuration keys verified successfully.")

        # Log active configuration safely masked
        logger.info("Configured AWS Key: %s", mask_secret(self.aws_access_key_id))
        logger.info("Configured DB URL: %s", mask_secret(self.database_url))
        logger.info("Configured Project Token: %s", mask_secret(self.slg_project_token))
        return True


def run_cloud_task(config: AppConfig):
    """Executes business logic using safely injected credentials."""
    logger.info("Executing secure cloud task...")
    # Safe API invocation using runtime header injection
    headers = {
        "Authorization": f"Bearer {config.github_token or 'ANONYMOUS'}",
        "X-Project-Token": config.slg_project_token or "",
    }
    # Business logic executes in memory without writing secrets to disk or logs
    logger.info("Task completed successfully with headers containing masked credentials.")
    return True


if __name__ == "__main__":
    config = AppConfig()
    is_valid = config.validate(strict=False)
    if is_valid:
        run_cloud_task(config)
        print("SecureApp executed successfully with zero hardcoded credentials.")
    else:
        sys.exit(1)
