"""
BAD EXAMPLE - DO NOT USE IN PRODUCTION!
This file intentionally demonstrates common secret leakage anti-patterns
to verify that Gitleaks, pre-commit hooks, and CI pipelines catch them.

NOTE: All credentials below are dummy RFC-compliant test fixtures.
"""

import os
import logging
import requests

logging.basicConfig(level=logging.INFO)

# ❌ ANTI-PATTERN 1: Hardcoded AWS Credentials
# Gitleaks rule: 'aws-access-token'
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# ❌ ANTI-PATTERN 2: Hardcoded Database Connection String with Password
# Gitleaks rule: 'generic-api-key' / 'postgres-uri'
DATABASE_URI = "postgresql://dbadmin:SuperSecretP@ssw0rd2024!@postgres-prod.internal:5432/customer_billing"

# ❌ ANTI-PATTERN 3: Hardcoded GitHub Personal Access Token (Classic)
# Gitleaks rule: 'github-pat'
GITHUB_PAT_TOKEN = "ghp_EXAMPLETOKEN999999999999999999999999"

# ❌ ANTI-PATTERN 4: Custom Project API Token (Secret Leak Guard Custom Pattern)
# Gitleaks custom rule: 'slg-project-token'
SLG_PROJECT_API_TOKEN = "SLG_demo_9876543210abcdef9876543210abcdef"

# ❌ ANTI-PATTERN 5: Custom College / University Campus Auth Token
# Gitleaks custom rule: 'college-campus-auth-token'
CAMPUS_AUTH_TOKEN = "CAMPUS-2024-ENGG-987654321098"

# ❌ ANTI-PATTERN 6: Hardcoded JWT Secret / Flask Session Key
SECRET_KEY = "d94b1509b53141f185ef34dc9b8e2345"


def bad_cloud_backup():
    """
    Demonstrates insecure logging and direct usage of hardcoded credentials.
    """
    # ❌ Leaks plaintext secret into application logs and centralized SIEM
    logging.info("Initiating cloud backup using AWS Access Key: %s", AWS_ACCESS_KEY_ID)
    logging.info("Using DB Connection: %s", DATABASE_URI)

    headers = {
        "Authorization": f"Bearer {GITHUB_PAT_TOKEN}",
        "X-Project-Token": SLG_PROJECT_API_TOKEN,
        "X-Campus-Auth": CAMPUS_AUTH_TOKEN,
    }

    response = requests.get("https://api.github.com/user", headers=headers, timeout=5)
    return response.status_code


if __name__ == "__main__":
    print("Warning: This script demonstrates anti-patterns for security testing.")
    print(f"Loaded fake AWS Key: {AWS_ACCESS_KEY_ID}")
