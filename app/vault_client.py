"""
Vault Client & Secret Management Helper.
Supports HashiCorp Vault (KV v2) with automatic fallback to environment variables.
Provides built-in secret masking for logs and diagnostics.
"""

import os
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger("SecretLeakGuard.Vault")


def mask_secret(value: Optional[str], visible_prefix: int = 4, visible_suffix: int = 4) -> str:
    """
    Safely masks a secret string so it can be logged or displayed in diagnostics.
    Never exposes full credentials in logs, terminals, or web dashboards.

    Example:
        'AKIA...EXAMPLE_KEY' -> 'AKIA************_KEY'
        'short' -> '*****'
    """
    if not value:
        return "[NOT SET]"
    str_val = str(value)
    length = len(str_val)
    if length <= (visible_prefix + visible_suffix):
        return "*" * length
    masked_part = "*" * (length - visible_prefix - visible_suffix)
    return f"{str_val[:visible_prefix]}{masked_part}{str_val[-visible_suffix:]}"


class SecretManager:
    """
    Unified Secret Manager supporting HashiCorp Vault and environment variables.
    """

    def __init__(self):
        self.vault_addr = os.getenv("VAULT_ADDR", "http://127.0.0.1:8200")
        self.vault_token = os.getenv("VAULT_TOKEN")
        self.vault_path = os.getenv("VAULT_SECRET_PATH", "payment-service")
        self.vault_mount_point = os.getenv("VAULT_MOUNT_POINT", "secret")
        self.client = None
        self.provider = "ENVIRONMENT"
        self._cache: Dict[str, Any] = {}

        self._initialize_vault()

    def _initialize_vault(self) -> None:
        """Attempts to initialize HVAC client if VAULT_TOKEN is configured."""
        if not self.vault_token:
            logger.info("VAULT_TOKEN not provided. Using OS environment variables as secret source.")
            return

        try:
            import hvac  # type: ignore

            client = hvac.Client(url=self.vault_addr, token=self.vault_token)
            if client.is_authenticated():
                self.client = client
                self.provider = "HASHICORP_VAULT"
                logger.info("Successfully authenticated with HashiCorp Vault at %s", self.vault_addr)
            else:
                logger.warning("Vault token provided but authentication failed. Falling back to environment variables.")
        except Exception as e:
            logger.warning(
                "Unable to connect to HashiCorp Vault at %s (%s). Falling back to environment variables.",
                self.vault_addr,
                str(e),
            )

    def get_secret(self, key: str, default: Optional[str] = None) -> Optional[str]:
        """
        Retrieves a secret by key. First checks Vault cache/read, then falls back to os.environ.
        """
        # 1. Try HashiCorp Vault if client is authenticated
        if self.client and self.provider == "HASHICORP_VAULT":
            try:
                if not self._cache:
                    secret_version_response = self.client.secrets.kv.v2.read_secret_version(
                        path=self.vault_path,
                        mount_point=self.vault_mount_point,
                    )
                    self._cache = secret_version_response.get("data", {}).get("data", {})

                if key in self._cache:
                    return str(self._cache[key])
            except Exception as e:
                logger.error("Error reading key '%s' from Vault: %s. Falling back to os.environ.", key, str(e))

        # 2. Fallback to Environment Variables
        env_value = os.getenv(key)
        if env_value is not None:
            return env_value

        return default

    def get_security_posture(self) -> Dict[str, Any]:
        """
        Returns security diagnostic metadata with all sensitive values strictly masked.
        """
        keys_to_inspect = [
            "AWS_ACCESS_KEY_ID",
            "DATABASE_URL",
            "SLG_PROJECT_API_TOKEN",
            "CAMPUS_AUTH_TOKEN",
            "SECRET_KEY",
        ]

        inspected = {}
        for k in keys_to_inspect:
            val = self.get_secret(k)
            inspected[k] = {
                "configured": bool(val),
                "masked_value": mask_secret(val),
                "source": self.provider if (self.client and k in self._cache) else "OS_ENV",
            }

        return {
            "secret_provider": self.provider,
            "vault_connected": bool(self.client),
            "vault_address": self.vault_addr if self.client else "N/A",
            "inspected_secrets": inspected,
        }
