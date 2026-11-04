"""
Universal Secret & Credential Redaction Engine
Ensures zero leaks in application logs, database findings, and API responses.
"""

import re
from typing import Any, Dict, List


class Redactor:
    """Masks secrets, tokens, passwords, and private keys."""

    SECRET_PATTERNS = [
        # AWS Access Keys
        (re.compile(r"(AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}"), r"\1****************"),
        # GitHub Tokens (classic and fine-grained)
        (re.compile(r"(ghp_[A-Za-z0-9]{4})[A-Za-z0-9]{16,}"), r"\1********************************"),
        (re.compile(r"(github_pat_[A-Za-z0-9]{4})[A-Za-z0-9_]{16,}"), r"\1****************************"),
        # Database URIs with credentials
        (re.compile(r"(://[^:\s]+):([^@\s]+)@"), r"\1:********@"),
        # Private Keys
        (re.compile(r"-----BEGIN (?:[A-Z ]+)?PRIVATE KEY-----[\s\S]*?-----END (?:[A-Z ]+)?PRIVATE KEY-----"),
         "-----BEGIN PRIVATE KEY-----\n[REDACTED PRIVATE KEY DATA]\n-----END PRIVATE KEY-----"),
        # JWT Tokens
        (re.compile(r"(eyJ[A-Za-z0-9_-]{8,}\.)[A-Za-z0-9_.-]+"), r"\1[REDACTED_JWT_PAYLOAD_SIGNATURE]"),
        # Hardcoded key assignments: password = "value", pass = "value", etc.
        (re.compile(r'(?i)(["\']?(?:password|passwd|pass|api[_-]?key|secret[_-]?key|auth[_-]?token|access[_-]?token)["\']?\s*[:=]\s*["\'])([^"\']{4,})(["\'])'),
         r'\1********\3'),
        # Slack / Discord Webhook Tokens
        (re.compile(r"(https://hooks\.slack\.com/services/[A-Z0-9]+/[A-Z0-9]+/)[A-Za-z0-9]+"), r"\1********"),
        (re.compile(r"(https://discord\.com/api/webhooks/\d+/)[A-Za-z0-9_-]+"), r"\1********"),
    ]

    @classmethod
    def mask_secret(cls, raw_text: str) -> str:
        """Applies regex masking rules to redact sensitive tokens in text."""
        if not raw_text or not isinstance(raw_text, str):
            return ""

        masked = raw_text
        for pattern, replacement in cls.SECRET_PATTERNS:
            masked = pattern.sub(replacement, masked)

        return masked

    @classmethod
    def mask_evidence(cls, line_content: str, secret_val: str = "") -> str:
        """Redacts line evidence while preserving surrounding syntax context."""
        if not line_content:
            return ""
        masked = cls.mask_secret(line_content)
        if secret_val and len(secret_val) > 4 and secret_val in masked:
            prefix = secret_val[:2]
            suffix = secret_val[-2:]
            placeholder = f"{prefix}{'*' * max(4, len(secret_val) - 4)}{suffix}"
            masked = masked.replace(secret_val, placeholder)
        return masked.strip()
