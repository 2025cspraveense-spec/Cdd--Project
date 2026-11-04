"""
Scan Orchestrator
Coordinates multi-engine execution, tracks scan progression, manages temporary workspaces,
and records normalized results and risk metrics into MongoDB.
"""

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import logging
from pathlib import Path
import time
from typing import Any, Dict, List, Optional

from scanner.config import ScannerConfig
from scanner.db import db
from scanner.engines import (
    SecretEngine,
    SASTEngine,
    DependencyEngine,
    DockerEngine,
    GitHistoryEngine,
)
from scanner.ingestion.upload_manager import UploadManager
from scanner.models import ScanRecord, ScanStatus, Finding
from scanner.processing import ResultNormalizer, RiskScorer

logger = logging.getLogger("scanner.orchestrator")


class ScanOrchestrator:
    """Manages the lifecycle of security scan jobs."""

    def __init__(self):
        self.secret_engine = SecretEngine()
        self.sast_engine = SASTEngine()
        self.dependency_engine = DependencyEngine()
        self.docker_engine = DockerEngine()
        self.git_history_engine = GitHistoryEngine()
        self._executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="scanner_worker")

    def run_scan_async(self, scan_record: ScanRecord, source_path: Path, scan_history: bool = False) -> str:
        """Submits a scan job to background thread pool and returns scan_id immediately."""
        db.save_scan(scan_record.to_dict())
        self._executor.submit(self._execute_scan, scan_record, source_path, scan_history)
        return scan_record.scan_id

    def run_scan_sync(self, scan_record: ScanRecord, source_path: Path, scan_history: bool = False) -> ScanRecord:
        """Executes a scan job synchronously (useful for verification scripts & unit tests)."""
        db.save_scan(scan_record.to_dict())
        return self._execute_scan(scan_record, source_path, scan_history)

    def _execute_scan(self, scan_record: ScanRecord, source_path: Path, scan_history: bool) -> ScanRecord:
        scan_id = scan_record.scan_id
        start_time = time.time()
        logger.info("Starting security scan [%s] for project '%s'...", scan_id, scan_record.project_name)

        try:
            # Update status: SCANNING
            scan_record.status = ScanStatus.SCANNING
            scan_record.progress_percentage = 10
            db.update_scan(scan_id, {
                "status": ScanStatus.SCANNING.value,
                "progress_percentage": 10,
                "current_engine": "Secret Detection",
            })

            all_findings: List[Finding] = []
            engines_run = []

            # Stage 1: Secret Engine
            logger.info("[%s] Running Secret Detection Engine...", scan_id)
            sec_findings = self.secret_engine.scan(source_path, scan_id)
            all_findings.extend(sec_findings)
            engines_run.append("gitleaks")
            scan_record.progress_percentage = 30
            db.update_scan(scan_id, {
                "progress_percentage": 30,
                "current_engine": "Static Analysis (SAST)",
            })

            # Stage 2: SAST Engine
            logger.info("[%s] Running Static Analysis (SAST) Engine...", scan_id)
            sast_findings = self.sast_engine.scan(source_path, scan_id)
            all_findings.extend(sast_findings)
            engines_run.append("semgrep/bandit")
            scan_record.progress_percentage = 55
            db.update_scan(scan_id, {
                "progress_percentage": 55,
                "current_engine": "Dependency Vulnerability Scanner",
            })

            # Stage 3: Dependency Engine
            logger.info("[%s] Running Dependency Vulnerability Engine...", scan_id)
            dep_findings = self.dependency_engine.scan(source_path, scan_id)
            all_findings.extend(dep_findings)
            engines_run.append("osv/pip-audit")
            scan_record.progress_percentage = 75
            db.update_scan(scan_id, {
                "progress_percentage": 75,
                "current_engine": "Docker Security Scanner",
            })

            # Stage 4: Docker Engine
            logger.info("[%s] Running Docker Security Engine...", scan_id)
            docker_findings = self.docker_engine.scan(source_path, scan_id)
            all_findings.extend(docker_findings)
            engines_run.append("trivy")
            scan_record.progress_percentage = 85
            db.update_scan(scan_id, {
                "progress_percentage": 85,
                "current_engine": "Git History Scanner" if scan_history else "Normalizing Results",
            })

            # Stage 5: Git History Engine (if enabled or .git exists)
            if scan_history or (source_path / ".git").exists():
                logger.info("[%s] Running Git History Scanner...", scan_id)
                hist_findings = self.git_history_engine.scan(source_path, scan_id)
                all_findings.extend(hist_findings)
                engines_run.append("git_history")

            # Stage 6: Normalization & Risk Scoring
            logger.info("[%s] Normalizing %d findings...", scan_id, len(all_findings))
            normalized, summary = ResultNormalizer.normalize_findings(
                all_findings, scan_id, scan_record.project_name
            )

            risk_score, security_grade = RiskScorer.calculate_score_and_grade(summary)

            # Persist findings to MongoDB
            db.save_findings([f.to_dict() for f in normalized])

            # Finalize scan record
            duration = round(time.time() - start_time, 2)
            completed_at = datetime.now(timezone.utc).isoformat()

            scan_record.status = ScanStatus.COMPLETED
            scan_record.progress_percentage = 100
            scan_record.completed_at = completed_at
            scan_record.duration_seconds = duration
            scan_record.risk_score = risk_score
            scan_record.security_grade = security_grade
            scan_record.summary = summary
            scan_record.engines_executed = engines_run
            scan_record.current_engine = "Finished"

            db.update_scan(scan_id, scan_record.to_dict())
            logger.info(
                "Scan [%s] COMPLETED in %.2fs: %d findings, Score: %.1f, Grade: %s",
                scan_id, duration, summary.total_findings, risk_score, security_grade
            )

        except Exception as e:
            logger.error("Scan [%s] FAILED: %s", scan_id, e, exc_info=True)
            scan_record.status = ScanStatus.FAILED
            scan_record.error_message = str(e)
            scan_record.duration_seconds = round(time.time() - start_time, 2)
            db.update_scan(scan_id, {
                "status": ScanStatus.FAILED.value,
                "error_message": str(e),
                "duration_seconds": scan_record.duration_seconds,
            })

        finally:
            # Safe temporary workspace cleanup
            UploadManager.cleanup_workspace(scan_id)

        return scan_record


# Singleton Orchestrator Instance
orchestrator = ScanOrchestrator()
