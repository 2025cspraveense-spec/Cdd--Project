"""
Unit and Integration Test Suite for Secret Leak Guard.
Covers:
- Vault client fallback mechanism
- Logging redaction and secret masking
- Secret scanning regex rule accuracy
- Flask web endpoints, safe error handling, and rotation monitor
"""

import sys
import unittest
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from app.vault_client import SecretManager, mask_secret
from app.main import app, RedactingFormatter
from app.config import config
from app.rotation_monitor import rotation_monitor


class TestSecretLeakGuard(unittest.TestCase):

    def setUp(self):
        self.app = app.test_client()
        self.app.testing = True

    def test_mask_secret_standard(self):
        """Tests that sensitive keys are masked with visible prefix/suffix only."""
        secret = "AKIAIOSFODNN7EXAMPLE"
        masked = mask_secret(secret, visible_prefix=4, visible_suffix=4)
        self.assertEqual(masked, "AKIA************MPLE")
        self.assertNotIn("IOSFODNN", masked)

    def test_mask_secret_short(self):
        """Tests that short values are fully masked to avoid leakage."""
        self.assertEqual(mask_secret("pass"), "****")

    def test_mask_secret_none(self):
        """Tests that None is handled gracefully."""
        self.assertEqual(mask_secret(None), "[NOT SET]")

    def test_redacting_formatter(self):
        """Tests that custom logging formatter catches and redacts secrets in log strings."""
        import logging
        formatter = RedactingFormatter("%(message)s")
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname=__file__,
            lineno=10,
            msg="User logged in with AWS Key AKIAIOSFODNN7EXAMPLE and token SLG_secret_key_12345678901234567890",
            args=(),
            exc_info=None
        )
        formatted = formatter.format(record)
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", formatted)
        self.assertIn("AKIA************MPLE", formatted)

    def test_vault_client_fallback(self):
        """Tests that SecretManager falls back to OS environment when Vault is unconfigured."""
        mgr = SecretManager()
        self.assertEqual(mgr.provider, "ENVIRONMENT")
        self.assertIsNone(mgr.client)

    def test_health_endpoint(self):
        """Tests that /health returns HTTP 200 with secure status."""
        resp = self.app.get("/health")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data.get("secrets_secured"))
        self.assertEqual(data.get("service"), "secret-leak-guard-app")

    def test_secrets_status_endpoint_is_masked(self):
        """Tests that /api/secrets/status NEVER exposes raw secret values."""
        resp = self.app.get("/api/secrets/status")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertIn("inspected_secrets", data)
        for key, info in data["inspected_secrets"].items():
            self.assertIn("masked_value", info)
            self.assertNotIn("AKIAIOSFODNN7EXAMPLE", info["masked_value"])
            self.assertNotIn("SuperSecretP@ssw0rd2024!", info["masked_value"])

    def test_rotation_status_endpoint(self):
        """Tests secret rotation monitoring endpoint."""
        resp = self.app.get("/api/secrets/rotation-status")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertIn("compliance", data)
        self.assertIn("credentials", data)
        self.assertIn("rotation_policy", data)

    def test_safe_error_handling(self):
        """Tests that error responses never leak stack traces."""
        resp = self.app.get("/nonexistent-endpoint")
        self.assertEqual(resp.status_code, 404)
        data = resp.get_json()
        self.assertIn("error", data)
        self.assertNotIn("Traceback", str(resp.data))


if __name__ == "__main__":
    unittest.main()
