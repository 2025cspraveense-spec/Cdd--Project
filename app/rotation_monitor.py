"""
Secret Rotation & Expiration Monitor - Secret Leak Guard.
Periodically audits secret expiration dates, lease lifetimes in HashiCorp Vault,
and triggers warnings when credentials exceed their maximum age limit (e.g. 90 days).
"""

import logging
from typing import Dict, Any

logger = logging.getLogger("SecretLeakGuard.RotationMonitor")


class SecretRotationMonitor:
    """Monitors secret age and flags expired credentials for zero-trust compliance."""

    def __init__(self, max_age_days: int = 90):
        self.max_age_days = max_age_days

    def audit_credentials(self, rotation_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        Evaluates credential ages against policy.
        Returns compliance metrics and actionable alerts.
        """
        credentials = rotation_info.get("credentials", {})
        overdue = []
        compliant = []

        for name, meta in credentials.items():
            age = meta.get("age_days", 0)
            if age > self.max_age_days:
                overdue.append({
                    "secret_name": name,
                    "age_days": age,
                    "max_allowed": self.max_age_days,
                    "action": f"Trigger rotation immediately. Key has exceeded {self.max_age_days} day policy."
                })
                logger.warning("Secret '%s' is overdue for rotation (%d days old > %d days allowed)", name, age, self.max_age_days)
            else:
                compliant.append(name)

        return {
            "compliant": len(overdue) == 0,
            "compliant_count": len(compliant),
            "overdue_count": len(overdue),
            "overdue_secrets": overdue,
        }


rotation_monitor = SecretRotationMonitor()
