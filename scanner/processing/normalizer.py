"""
Result Normalizer & Findings Deduplication Engine
Standardizes disparate outputs from Gitleaks, Semgrep, Bandit, Trivy, and OSV
into a uniform schema with deterministic fingerprints and statistical summaries.
"""

import hashlib
import logging
from typing import List, Tuple

from scanner.models import Finding, ScanSummary, Severity, Category

logger = logging.getLogger("scanner.processing.normalizer")


class ResultNormalizer:
    """Normalizes, validates, deduplicates, and summarizes security scan findings."""

    @classmethod
    def normalize_findings(
        cls,
        raw_findings: List[Finding],
        scan_id: str,
        project_name: str,
    ) -> Tuple[List[Finding], ScanSummary]:
        """
        Processes a raw list of findings:
        - Injects scan_id and project_name
        - Generates consistent SHA-256 fingerprint
        - Deduplicates identical findings across engines
        - Computes statistical summary (critical, high, medium, low, category counts)
        """
        normalized_list: List[Finding] = []
        fingerprints_seen = set()

        summary = ScanSummary()

        for f in raw_findings:
            f.scan_id = scan_id
            f.project_name = project_name

            # Generate unique deterministic fingerprint
            fp_seed = f"{f.file_path}:{f.line_number}:{f.category.value if isinstance(f.category, Category) else f.category}:{f.title}"
            f.fingerprint = hashlib.sha256(fp_seed.encode("utf-8")).hexdigest()

            if f.fingerprint in fingerprints_seen:
                continue

            fingerprints_seen.add(f.fingerprint)
            normalized_list.append(f)

            # Update summary statistics
            summary.total_findings += 1
            sev = f.severity if isinstance(f.severity, Severity) else Severity(str(f.severity))
            if sev == Severity.CRITICAL:
                summary.critical += 1
            elif sev == Severity.HIGH:
                summary.high += 1
            elif sev == Severity.MEDIUM:
                summary.medium += 1
            elif sev == Severity.LOW:
                summary.low += 1
            else:
                summary.info += 1

            cat = f.category if isinstance(f.category, Category) else Category(str(f.category))
            if cat == Category.SECRET_LEAK:
                summary.secrets_count += 1
            elif cat == Category.SAST_VULNERABILITY:
                summary.sast_count += 1
            elif cat == Category.DEPENDENCY:
                summary.dependencies_count += 1
            elif cat == Category.DOCKER_SECURITY:
                summary.docker_count += 1
            elif cat == Category.GIT_HISTORY:
                summary.git_history_count += 1

        return normalized_list, summary
