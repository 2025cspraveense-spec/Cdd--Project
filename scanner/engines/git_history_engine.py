"""
Git History Security Scanner
Scans historical Git commits to detect credentials removed from HEAD but
persisting in version control history. Integrates Gitleaks git-history mode.
"""

import json
import logging
from pathlib import Path
import re
import shutil
from typing import List

from scanner.engines.base import BaseEngine
from scanner.models import Finding, Severity, Category
from scanner.processing.redactor import Redactor

logger = logging.getLogger("scanner.engines.git_history")


class GitHistoryEngine(BaseEngine):
    """Scans Git repository commit log and tree differentials for historical leaks."""

    engine_name: str = "git_history_scanner"

    def is_available(self) -> bool:
        return shutil.which("gitleaks") is not None or shutil.which("git") is not None

    def scan(self, source_path: Path, scan_id: str) -> List[Finding]:
        findings: List[Finding] = []

        git_dir = source_path / ".git"
        if not git_dir.exists():
            return findings

        if shutil.which("gitleaks") is not None:
            findings.extend(self._scan_with_gitleaks_history(source_path, scan_id))

        if not findings and shutil.which("git") is not None:
            findings.extend(self._scan_with_git_log(source_path, scan_id))

        seen = set()
        unique = []
        for f in findings:
            key = f"{f.file_path}:{f.title}:{f.fingerprint}"
            if key not in seen:
                seen.add(key)
                unique.append(f)

        return unique

    def _scan_with_gitleaks_history(self, source_path: Path, scan_id: str) -> List[Finding]:
        report_path = source_path / f".gitleaks_history_{scan_id}.json"
        cmd = [
            "gitleaks",
            "detect",
            f"--source={source_path}",
            '--log-opts=--all',
            "--report-format=json",
            f"--report-path={report_path}",
        ]

        res = self.run_command(cmd)
        findings = []

        if report_path.exists():
            try:
                data = json.loads(self.safe_read_file(report_path))
                if isinstance(data, list):
                    for item in data:
                        raw_secret = item.get("Secret", "")
                        match_str = item.get("Match", "") or raw_secret
                        commit_hash = item.get("Commit", "unknown_commit")[:8]
                        f = Finding(
                            scan_id=scan_id,
                            title=f"Git History Secret: {item.get('Description', 'Committed Credential')}",
                            severity=Severity.CRITICAL,
                            category=Category.GIT_HISTORY,
                            engine="gitleaks_history",
                            file_name=Path(item.get("File", "")).name,
                            file_path=item.get("File", ""),
                            line_number=item.get("StartLine"),
                            description=f"Secret identified in historic Git commit [{commit_hash}]. Even if deleted in latest commit, credentials remain exposed in git history.",
                            evidence_redacted=Redactor.mask_evidence(match_str, raw_secret),
                            cwe="CWE-798: Use of Hard-coded Credentials",
                            owasp="A07:2021-Identification and Authentication Failures",
                            potential_impact="Attackers cloning this repo can checkout older commits to extract valid credentials.",
                            recommended_remediation="Purge commit from git history using 'git filter-repo' or BFG Repo-Cleaner, and rotate credentials.",
                            reference_urls=["https://github.com/newren/git-filter-repo"],
                            fingerprint=item.get("Fingerprint", ""),
                        )
                        findings.append(f)
            except Exception as e:
                logger.warning("Error parsing Gitleaks history report: %s", e)
            finally:
                report_path.unlink(missing_ok=True)

        return findings

    def _scan_with_git_log(self, source_path: Path, scan_id: str) -> List[Finding]:
        findings: List[Finding] = []
        cmd = ["git", "log", "-p", "-n", "50", "--diff-filter=A|M|D"]
        res = self.run_command(cmd, cwd=source_path)
        if not res or not res.stdout:
            return findings

        current_file = ""
        current_commit = ""
        secret_patterns = [
            (re.compile(r"\+\s*(?:AKIA|ASIA)[A-Z0-9]{16}"), "AWS Access Key in Commit Diff", Severity.CRITICAL),
            (re.compile(r"\+\s*(?:ghp_[A-Za-z0-9]{36})"), "GitHub Token in Commit Diff", Severity.CRITICAL),
            (re.compile(r"\+\s*(?:password|api_key|secret_key)\s*[:=]\s*['\"]([^'\"]{8,})['\"]", re.IGNORECASE), "Password/Key in Commit Diff", Severity.HIGH),
        ]

        for line in res.stdout.splitlines():
            if line.startswith("commit "):
                current_commit = line.split()[1][:8]
            elif line.startswith("diff --git a/"):
                parts = line.split()
                if len(parts) >= 4:
                    current_file = parts[2].replace("a/", "")
            elif line.startswith("+") and not line.startswith("+++"):
                for regex, title, sev in secret_patterns:
                    match = regex.search(line)
                    if match:
                        findings.append(Finding(
                            scan_id=scan_id,
                            title=title,
                            severity=sev,
                            category=Category.GIT_HISTORY,
                            engine="git_log_scanner",
                            file_name=Path(current_file).name,
                            file_path=current_file,
                            description=f"Secret found in commit [{current_commit}]. Deleting the secret in a later commit does not invalidate git history.",
                            evidence_redacted=Redactor.mask_evidence(line),
                            cwe="CWE-798: Use of Hard-coded Credentials",
                            owasp="A07:2021-Identification and Authentication Failures",
                            potential_impact="Historic exposure of secrets enables persistent unauthorized access.",
                            recommended_remediation="Purge secret from git history using git filter-repo and rotate credentials immediately.",
                        ))

        return findings
