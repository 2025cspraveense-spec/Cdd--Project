"""
Comprehensive Automated Test Suite for Universal Source Code Security Scanner
Validates Ingestion Security (Zip Slip & SSRF), Secret Detection, SAST AST Engine,
Dependency Scanner, Docker Rules, Risk Scoring, PDF/JSON/SARIF Reporting, and REST API.
"""

import io
import json
import os
from pathlib import Path
import tempfile
import zipfile
import pytest

from scanner.config import ScannerConfig
from scanner.db import db
from scanner.models import Finding, ScanRecord, ScanSummary, Severity, Category, SourceType
from scanner.ingestion import UploadManager, RepositoryManager
from scanner.ingestion.upload_manager import UploadSecurityException
from scanner.ingestion.repository_manager import RepositorySecurityException
from scanner.engines import (
    SecretEngine,
    SASTEngine,
    DependencyEngine,
    DockerEngine,
)
from scanner.processing import Redactor, ResultNormalizer, RiskScorer
from scanner.reporting import PDFReportGenerator, JSONReportGenerator, HTMLReportGenerator
from scanner.api.app import create_app


@pytest.fixture
def app_client():
    app = create_app()
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


def test_zip_slip_protection():
    temp_dir = Path(tempfile.mkdtemp())
    malicious_zip = temp_dir / "evil.zip"

    with zipfile.ZipFile(malicious_zip, "w") as zf:
        zf.writestr("../../etc/passwd", "root:x:0:0:root:/root:/bin/bash")

    with pytest.raises(UploadSecurityException) as exc_info:
        UploadManager.process_zip_upload(malicious_zip, "test_slip_scan")

    assert "Zip Slip" in str(exc_info.value)
    malicious_zip.unlink(missing_ok=True)
    temp_dir.rmdir()


def test_ssrf_repository_url_validation():
    blocked_urls = [
        "http://169.254.169.254/latest/meta-data/",
        "http://127.0.0.1:8080/internal-admin",
        "http://10.0.1.5/private-repo.git",
        "ftp://github.com/org/repo.git",
        "",
    ]

    for url in blocked_urls:
        with pytest.raises(RepositorySecurityException):
            RepositoryManager.validate_repository_url(url)

    RepositoryManager.validate_repository_url("https://github.com/2025cspraveense-spec/Cdd--Project")


def test_redactor_masks_sensitive_tokens():
    mock_ghp = "gh" + "p_" + ("mocktoken" * 4)[:36]
    raw_text = f'aws_key = "AKIAIOSFODNN7EXAMPLE"\n{mock_ghp}\npass = "SecretP@ssw0rd!"'
    masked = Redactor.mask_secret(raw_text)

    assert "AKIAIOSFODNN7EXAMPLE" not in masked
    assert mock_ghp not in masked
    assert "SecretP@ssw0rd!" not in masked
    assert "AKIA****************" in masked or "********" in masked


def test_secret_detection_engine(tmp_path):
    test_file = tmp_path / "leaked_config.py"
    mock_ghp = "gh" + "p_" + ("samplepat" * 4)[:36]
    test_file.write_text(
        'AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"\n'
        'DB_URI = "postgres://admin:SuperSecretPass123@db.prod.internal:5432/corp"\n'
        f'GITHUB_TOKEN = "{mock_ghp}"\n',
        encoding="utf-8",
    )

    engine = SecretEngine()
    findings = engine.scan(tmp_path, "test_sec_scan")

    assert len(findings) >= 2
    titles = [f.title for f in findings]
    assert any("AWS Access Key" in t for t in titles)
    assert any("Database Connection" in t or "GitHub" in t for t in titles)

    for f in findings:
        assert "AKIAIOSFODNN7EXAMPLE" not in f.evidence_redacted
        assert "SuperSecretPass123" not in f.evidence_redacted


def test_sast_ast_vulnerability_detection(tmp_path):
    vuln_code = tmp_path / "vulnerable_app.py"
    vuln_code.write_text(
        "import os, subprocess, pickle\n"
        "def query_user(user_id):\n"
        "    cursor.execute('SELECT * FROM users WHERE id = ' + user_id)\n"
        "def run_cmd(user_cmd):\n"
        "    os.system(user_cmd)\n"
        "    subprocess.run(user_cmd, shell=True)\n"
        "def load_payload(raw_data):\n"
        "    return pickle.loads(raw_data)\n",
        encoding="utf-8",
    )

    engine = SASTEngine()
    findings = engine.scan(tmp_path, "test_sast_scan")

    assert len(findings) >= 3
    titles = [f.title for f in findings]
    assert any("SQL Injection" in t for t in titles)
    assert any("Command Injection" in t for t in titles)
    assert any("Insecure Deserialization" in t for t in titles)


def test_dependency_vulnerability_scanner(tmp_path):
    req_file = tmp_path / "requirements.txt"
    req_file.write_text("requests==2.25.1\nflask==1.1.2\n", encoding="utf-8")

    pkg_file = tmp_path / "package.json"
    pkg_file.write_text(json.dumps({"dependencies": {"lodash": "4.17.15"}}), encoding="utf-8")

    engine = DependencyEngine()
    findings = engine.scan(tmp_path, "test_dep_scan")

    assert len(findings) >= 2
    titles = " ".join(f.title for f in findings)
    assert "CVE-2023-32681" in titles or "CVE-2023-30861" in titles
    assert "CVE-2021-23337" in titles


def test_docker_security_scanner(tmp_path):
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(
        "FROM python:3.11\n"
        "USER root\n"
        "ENV SECRET_KEY=supersecret123\n"
        "COPY .env /app/.env\n"
        "EXPOSE 22\n",
        encoding="utf-8",
    )

    engine = DockerEngine()
    findings = engine.scan(tmp_path, "test_docker_scan")

    assert len(findings) >= 3
    titles = [f.title for f in findings]
    assert any("Root" in t for t in titles)
    assert any("Secret in Dockerfile ENV" in t for t in titles)
    assert any(".env" in t for t in titles)


def test_normalizer_and_risk_scorer():
    raw = [
        Finding(title="Secret 1", severity=Severity.CRITICAL, category=Category.SECRET_LEAK, file_path="app.py", line_number=10),
        Finding(title="Secret 1", severity=Severity.CRITICAL, category=Category.SECRET_LEAK, file_path="app.py", line_number=10),
        Finding(title="SQLi", severity=Severity.CRITICAL, category=Category.SAST_VULNERABILITY, file_path="db.py", line_number=25),
        Finding(title="XSS", severity=Severity.HIGH, category=Category.SAST_VULNERABILITY, file_path="view.py", line_number=14),
    ]

    normalized, summary = ResultNormalizer.normalize_findings(raw, "scan_test_123", "DemoProject")
    assert len(normalized) == 3
    assert summary.critical == 2
    assert summary.high == 1

    score, grade = RiskScorer.calculate_score_and_grade(summary)
    assert score == 60.0
    assert grade == "C"


def test_report_generators():
    scan_data = {
        "scan_id": "scan_test_rep",
        "project_name": "Test-App",
        "risk_score": 75.0,
        "security_grade": "D",
        "summary": {"total_findings": 2, "critical": 1, "high": 1, "medium": 0, "low": 0},
        "created_at": "2026-11-04T18:00:00Z",
    }
    findings = [
        {
            "finding_id": "fnd_1",
            "title": "AWS Key Leaked",
            "severity": "CRITICAL",
            "category": "SECRET_LEAK",
            "engine": "gitleaks",
            "file_path": "config.py",
            "line_number": 12,
            "description": "Hardcoded AWS Access Key",
            "evidence_redacted": "key = 'AKIA****************'",
            "recommended_remediation": "Revoke key in AWS IAM",
            "cwe": "CWE-798",
        }
    ]

    pdf_bytes = PDFReportGenerator.generate(scan_data, findings)
    assert len(pdf_bytes) > 500
    assert pdf_bytes.startswith(b"%PDF")

    json_rep = JSONReportGenerator.generate_json(scan_data, findings)
    assert json_rep["scan_id"] == "scan_test_rep"
    assert len(json_rep["findings"]) == 1

    sarif = JSONReportGenerator.generate_sarif(scan_data, findings)
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"][0]["results"]) == 1
    assert sarif["runs"][0]["results"][0]["ruleId"] == "CWE-798"

    html = HTMLReportGenerator.generate(scan_data, findings)
    assert "<html" in html
    assert "Secret Leak Guard" in html
    assert "AWS Key Leaked" in html


def test_api_health_endpoint(app_client):
    res = app_client.get("/api/v1/health")
    assert res.status_code == 200
    data = res.get_json()
    assert data["status"] == "healthy"
    assert "database" in data
    assert "engines" in data


def test_api_auth_login(app_client):
    res = app_client.post("/api/v1/auth/login", json={
        "username": "admin",
        "password": "Admin@DevSecOps2026!",
    })
    assert res.status_code == 200
    data = res.get_json()
    assert "access_token" in data
    assert data["user"]["role"] == "admin"


def test_api_local_scan_and_results(app_client, tmp_path):
    sample = tmp_path / "app.py"
    sample.write_text('API_KEY = "AKIAIOSFODNN7EXAMPLE"\n', encoding="utf-8")

    post_res = app_client.post("/api/v1/scans/local", json={
        "path": str(tmp_path),
        "project_name": "API-Test-Project",
    })
    assert post_res.status_code == 202
    scan_id = post_res.get_json()["scan_id"]

    status_res = app_client.get(f"/api/v1/scans/{scan_id}/status")
    assert status_res.status_code == 200

    results_res = app_client.get(f"/api/v1/scans/{scan_id}/results")
    assert results_res.status_code == 200
    res_data = results_res.get_json()
    assert res_data["project_name"] == "API-Test-Project"

    metrics_res = app_client.get("/api/v1/dashboard/metrics")
    assert metrics_res.status_code == 200
    assert metrics_res.get_json()["total_scans"] >= 1
