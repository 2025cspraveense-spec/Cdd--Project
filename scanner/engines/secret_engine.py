"""
Secret Detection Engine
Integrates Gitleaks CLI with custom rules and a native high-entropy / regex detector.
"""

import json
import logging
import math
from pathlib import Path
import re
import shutil
from typing import List

from scanner.engines.base import BaseEngine
from scanner.models import Finding, Severity, Category
from scanner.processing.redactor import Redactor

logger = logging.getLogger("scanner.engines.secret")


class SecretEngine(BaseEngine):
    """Detects leaked credentials, API tokens, cloud keys, and database passwords."""

    engine_name: str = "gitleaks"

    # Regex definitions for secrets
    PATTERNS = [
        (
            "AWS Access Key ID",
            re.compile(r"(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}"),
            Severity.CRITICAL,
            "CWE-798: Use of Hard-coded Credentials",
            "A07:2021-Identification and Authentication Failures",
            "Revoke this AWS Access Key in IAM console immediately. Use IAM Roles or Vault.",
        ),
        (
            "GitHub Personal Access Token",
            re.compile(r"(ghp_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z_]{22,}|gho_[0-9a-zA-Z]{36})"),
            Severity.CRITICAL,
            "CWE-798: Use of Hard-coded Credentials",
            "A07:2021-Identification and Authentication Failures",
            "Revoke this GitHub token immediately on GitHub Settings. Use fine-grained scoped secrets.",
        ),
        (
            "Database Connection String with Credentials",
            re.compile(r"(postgres|postgresql|mysql|mongodb|mongodb\+srv|redis)://[^\s:]+:[^\s@]+@[^\s]+"),
            Severity.CRITICAL,
            "CWE-798: Use of Hard-coded Credentials",
            "A07:2021-Identification and Authentication Failures",
            "Remove database credentials from code and pass via environment variables or Vault.",
        ),
        (
            "Unencrypted Private Key",
            re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
            Severity.CRITICAL,
            "CWE-312: Cleartext Storage of Sensitive Information",
            "A02:2021-Cryptographic Failures",
            "Remove the private key from the codebase immediately and rotate key pairs.",
        ),
        (
            "JSON Web Token (JWT)",
            re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
            Severity.HIGH,
            "CWE-522: Insufficiently Protected Credentials",
            "A07:2021-Identification and Authentication Failures",
            "Do not hardcode live JWT bearer tokens. Obtain tokens dynamically via OAuth/OIDC.",
        ),
        (
            "Slack / Discord Webhook URL",
            re.compile(r"(https://hooks\.slack\.com/services/[A-Za-z0-9/]+|https://discord\.com/api/webhooks/\d+/[A-Za-z0-9_-]+)"),
            Severity.HIGH,
            "CWE-200: Exposure of Sensitive Information",
            "A01:2021-Broken Access Control",
            "Rotate webhook URL in Slack/Discord admin settings and inject via environment variables.",
        ),
        (
            "Hardcoded API Key / Secret Assignment",
            re.compile(r'(?i)(?:api_key|apikey|secret_key|secret_token|app_secret|client_secret)\s*[:=]\s*["\']([a-zA-Z0-9_\-.~]{16,})["\']'),
            Severity.HIGH,
            "CWE-798: Use of Hard-coded Credentials",
            "A07:2021-Identification and Authentication Failures",
            "Externalize the API key into environment variables or secrets manager.",
        ),
        (
            "Hardcoded Password Assignment",
            re.compile(r'(?i)(?:password|passwd|db_pass|database_password)\s*[:=]\s*["\']([^"\'\s]{6,})["\']'),
            Severity.HIGH,
            "CWE-259: Use of Hard-coded Password",
            "A07:2021-Identification and Authentication Failures",
            "Store passwords in HashiCorp Vault or environment variables, never in source code.",
        ),
    ]

    def is_available(self) -> bool:
        return shutil.which("gitleaks") is not None

    def scan(self, source_path: Path, scan_id: str) -> List[Finding]:
        findings: List[Finding] = []

        # 1. Try Gitleaks CLI if installed
        if self.is_available():
            cli_findings = self._scan_with_gitleaks_cli(source_path, scan_id)
            findings.extend(cli_findings)

        # 2. Run native pattern and entropy detector (ensures coverage and fallback)
        native_findings = self._scan_with_native_engine(source_path, scan_id)

        # Deduplicate findings by fingerprint (file_path + line_number + title)
        seen = set()
        unique_findings = []
        for f in findings + native_findings:
            key = f"{f.file_path}:{f.line_number}:{f.title}"
            if key not in seen:
                seen.add(key)
                unique_findings.append(f)

        return unique_findings

    def _scan_with_gitleaks_cli(self, source_path: Path, scan_id: str) -> List[Finding]:
        report_path = source_path / f".gitleaks_report_{scan_id}.json"
        cmd = [
            "gitleaks",
            "detect",
            f"--source={source_path}",
            "--no-git",
            "--report-format=json",
            f"--report-path={report_path}",
        ]

        custom_config = Path("E:/Cdd/secret-leak-guard/.gitleaks.toml")
        if custom_config.exists():
            cmd.append(f"--config={custom_config}")

        res = self.run_command(cmd)
        findings = []

        if report_path.exists():
            try:
                data = json.loads(self.safe_read_file(report_path))
                if isinstance(data, list):
                    for item in data:
                        raw_secret = item.get("Secret", "")
                        line_str = item.get("Match", "") or raw_secret
                        finding = Finding(
                            scan_id=scan_id,
                            title=f"Leaked Secret: {item.get('Description', 'Hardcoded Secret')}",
                            severity=Severity.CRITICAL if "key" in item.get("Description", "").lower() else Severity.HIGH,
                            category=Category.SECRET_LEAK,
                            engine="gitleaks",
                            file_name=Path(item.get("File", "")).name,
                            file_path=str(Path(item.get("File", "")).as_posix()),
                            line_number=item.get("StartLine"),
                            description=item.get("Description", "Secret detected by Gitleaks"),
                            evidence_redacted=Redactor.mask_evidence(line_str, raw_secret),
                            cwe="CWE-798: Use of Hard-coded Credentials",
                            owasp="A07:2021-Identification and Authentication Failures",
                            potential_impact="Unauthorized access to target system or cloud resources.",
                            recommended_remediation="Revoke and rotate the exposed secret immediately. Migrate to Vault.",
                            fingerprint=item.get("Fingerprint", ""),
                        )
                        findings.append(finding)
            except Exception as e:
                logger.warning("Error parsing Gitleaks report: %s", e)
            finally:
                report_path.unlink(missing_ok=True)

        return findings

    def _scan_with_native_engine(self, source_path: Path, scan_id: str) -> List[Finding]:
        findings: List[Finding] = []
        extensions = {
            ".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".go", ".rb", ".php",
            ".env", ".json", ".yaml", ".yml", ".toml", ".xml", ".properties", ".sh", ".dockerfile"
        }
        files = self.find_files_by_extensions(source_path, extensions)

        for file_path in files:
            rel_path = file_path.relative_to(source_path).as_posix()
            content = self.safe_read_file(file_path)
            if not content:
                continue

            lines = content.splitlines()
            for line_idx, line in enumerate(lines, start=1):
                # Pattern scanning
                for title, regex, severity, cwe, owasp, remediation in self.PATTERNS:
                    match = regex.search(line)
                    if match:
                        matched_val = match.group(0)
                        finding = Finding(
                            scan_id=scan_id,
                            title=title,
                            severity=severity,
                            category=Category.SECRET_LEAK,
                            engine="secret_engine",
                            file_name=file_path.name,
                            file_path=rel_path,
                            line_number=line_idx,
                            description=f"{title} identified in source code.",
                            evidence_redacted=Redactor.mask_evidence(line, matched_val),
                            cwe=cwe,
                            owasp=owasp,
                            potential_impact="Exposure of sensitive credentials enabling unauthorized privilege escalation.",
                            recommended_remediation=remediation,
                            reference_urls=[
                                "https://cwe.mitre.org/data/definitions/798.html",
                                "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
                            ],
                        )
                        findings.append(finding)

                # Entropy scanning on assignments (e.g. key = "xyz...")
                entropy_finding = self._check_high_entropy_token(line, line_idx, rel_path, file_path.name, scan_id)
                if entropy_finding:
                    findings.append(entropy_finding)

        return findings

    def _check_high_entropy_token(self, line: str, line_no: int, rel_path: str, file_name: str, scan_id: str) -> Finding | None:
        """Flags high-entropy strings (> 4.5 Shannon entropy) assigned in code."""
        assignment_match = re.search(r'[:=]\s*["\']([a-zA-Z0-9+/=_-]{24,})["\']', line)
        if not assignment_match:
            return None

        token = assignment_match.group(1)
        entropy = self._shannon_entropy(token)

        if entropy >= 4.5:
            return Finding(
                scan_id=scan_id,
                title="High-Entropy String (Suspected API Secret or Token)",
                severity=Severity.HIGH,
                category=Category.SECRET_LEAK,
                engine="entropy_detector",
                file_name=file_name,
                file_path=rel_path,
                line_number=line_no,
                description=f"High Shannon entropy value ({entropy:.2f}) indicates a randomly generated cryptographic key or token.",
                evidence_redacted=Redactor.mask_evidence(line, token),
                cwe="CWE-798: Use of Hard-coded Credentials",
                owasp="A07:2021-Identification and Authentication Failures",
                potential_impact="Exposure of high-entropy token could allow attackers to bypass authentication.",
                recommended_remediation="Verify if this token is a secret. If so, move it to environment variables or Vault.",
            )
        return None

    @staticmethod
    def _shannon_entropy(data: str) -> float:
        if not data:
            return 0.0
        entropy = 0.0
        length = len(data)
        freq = {}
        for char in data:
            freq[char] = freq.get(char, 0) + 1
        for count in freq.values():
            p_x = count / length
            entropy += - p_x * math.log2(p_x)
        return entropy
