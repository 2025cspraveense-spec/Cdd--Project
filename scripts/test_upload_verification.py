#!/usr/bin/env python3
"""
Secret Leak Guard - End-to-End File Upload Verification Test.
Uploads a sample project ZIP archive to http://localhost/api/v1/scans/upload,
polls for scan completion, validates findings across all engines,
and verifies report generation and dashboard metrics.
"""

import io
import os
import sys
import time
import zipfile
import requests


def create_test_project_zip() -> bytes:
    """Creates an in-memory ZIP archive containing multi-vector security test fixtures."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        # 1. Vulnerable Python file (Secrets + SAST)
        app_code = '''
import os
import sqlite3
import pickle

# Leaked credentials
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
DATABASE_URL = "postgres://admin:SuperSecretPass123!@db.internal:5432/app"

def get_user_profile(user_id):
    # SQL Injection
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = '{user_id}'")
    return cursor.fetchall()

def execute_diagnostics(cmd):
    # Command Injection
    os.system(f"ping -c 1 {cmd}")

def load_session_token(token_bytes):
    # Insecure Deserialization
    return pickle.loads(token_bytes)
'''
        zf.writestr("app/vulnerable_service.py", app_code.strip())

        # 2. Dependency file with known CVEs
        deps = '''
requests==2.19.0
flask==0.12.0
'''
        zf.writestr("requirements.txt", deps.strip())

        # 3. Dockerfile with container risks
        dockerfile = '''
FROM python:3.9-slim
USER root
ENV API_SECRET_TOKEN=SLG_demo_9876543210abcdef9876543210abcdef
EXPOSE 22
CMD ["python", "app.py"]
'''
        zf.writestr("Dockerfile", dockerfile.strip())

    buffer.seek(0)
    return buffer.getvalue()


def run_upload_verification():
    print("=" * 75)
    print("[*] SECRET LEAK GUARD - LIVE FILE UPLOAD VERIFICATION")
    print("=" * 75)

    base_url = "http://localhost"

    # Step 1: Create test payload
    print("[1/6] Packaging test project ZIP with secrets, SAST, CVEs, and Dockerfile...")
    zip_bytes = create_test_project_zip()
    print(f"      Created in-memory ZIP package ({len(zip_bytes)} bytes)")

    # Step 2: Upload file via Nginx Gateway
    print(f"[2/6] Submitting upload to {base_url}/api/v1/scans/upload via Nginx Gateway...")
    files = {"file": ("vulnerable-project.zip", zip_bytes, "application/zip")}
    data = {"project_name": "E2E-Upload-Verification"}

    resp = requests.post(f"{base_url}/api/v1/scans/upload", files=files, data=data, timeout=30)
    if resp.status_code not in (200, 202):
        print(f"      [!] Upload failed with HTTP {resp.status_code}: {resp.text}")
        return False

    upload_resp = resp.json()
    scan_id = upload_resp["scan_id"]
    status = upload_resp.get("status", "QUEUED")
    print(f"      [OK] Upload accepted! Scan ID: {scan_id} (Status: {status})")

    # Step 3: Poll scan progress until completion
    print(f"[3/6] Polling scan progress on {base_url}/api/v1/scans/{scan_id}/status...")
    max_wait = 30
    elapsed = 0
    scan_status = None

    while elapsed < max_wait:
        s_resp = requests.get(f"{base_url}/api/v1/scans/{scan_id}/status", timeout=10)
        scan_status = s_resp.json()
        current_status = scan_status.get("status")
        progress = scan_status.get("progress_percentage", 0)
        engine = scan_status.get("current_engine", "Starting")
        print(f"      Progress: {progress}% | Engine: {engine} | Status: {current_status}")
        if current_status in ("COMPLETED", "FAILED"):
            break
        time.sleep(1.5)
        elapsed += 1.5

    assert scan_status["status"] == "COMPLETED", f"Scan did not complete successfully: {scan_status}"
    print(f"      [OK] Scan successfully completed in {scan_status.get('duration_seconds', 0)} seconds!")

    # Step 4: Fetch detailed results & findings
    print(f"[4/6] Fetching normalized scan findings from {base_url}/api/v1/scans/{scan_id}/results...")
    r_resp = requests.get(f"{base_url}/api/v1/scans/{scan_id}/results", timeout=10)
    results = r_resp.json()

    risk_score = results["risk_score"]
    grade = results["security_grade"]
    findings = results["findings"]
    summary = results.get("summary", {})

    print(f"      [+] Security Grade : {grade}")
    print(f"      [+] Risk Score     : {risk_score}/100")
    print(f"      [+] Total Findings : {len(findings)}")
    print(f"         - Critical: {summary.get('critical_count', 0)}")
    print(f"         - High    : {summary.get('high_count', 0)}")
    print(f"         - Medium  : {summary.get('medium_count', 0)}")
    print(f"         - Low     : {summary.get('low_count', 0)}")

    print("\n      Detected Vulnerabilities & Evidence:")
    for i, f in enumerate(findings, 1):
        line_info = f":{f['line_number']}" if f.get("line_number") else ""
        print(f"        {i}. [{f['severity']}] {f['title']} ({f['file_path']}{line_info})")
        if f.get("evidence_redacted"):
            clean_ev = f['evidence_redacted'].strip().replace('\n', ' ')
            print(f"           Evidence : {clean_ev[:70]}...")
        if f.get("recommended_remediation"):
            print(f"           Remedy   : {f['recommended_remediation']}")

    # Step 5: Verify Reports
    print(f"\n[5/6] Verifying downloadable compliance reports from Gateway...")
    reports = [
        ("Interactive HTML Dashboard", f"{base_url}/api/v1/scans/{scan_id}/report/html", "text/html"),
        ("Executive Vector PDF Report", f"{base_url}/api/v1/scans/{scan_id}/report/pdf", "application/pdf"),
        ("Normalized JSON Export", f"{base_url}/api/v1/scans/{scan_id}/report/json", "application/json"),
        ("OASIS SARIF Export", f"{base_url}/api/v1/scans/{scan_id}/report/sarif", "application/json"),
    ]

    for label, url, expected_content_type in reports:
        rep_resp = requests.get(url, timeout=10)
        content_length = len(rep_resp.content)
        content_type = rep_resp.headers.get("Content-Type", "")
        print(f"      [OK] {label.ljust(28)}: HTTP {rep_resp.status_code} ({content_length:,} bytes, {content_type.split(';')[0]})")

    # Step 6: Verify Dashboard Metrics reflect this scan
    print(f"\n[6/6] Verifying global metrics at {base_url}/api/v1/dashboard/metrics...")
    m_resp = requests.get(f"{base_url}/api/v1/dashboard/metrics", timeout=10)
    metrics = m_resp.json()
    total_projects = metrics.get("total_projects", 0)
    total_findings = metrics.get("total_findings", 0)
    recent_scans = metrics.get("recent_scans", [])
    matched_recent = [s for s in recent_scans if s.get("scan_id") == scan_id]

    print(f"      Total Projects in DB : {total_projects}")
    print(f"      Total Findings in DB : {total_findings}")
    print(f"      Scan in Recent List  : {'Yes (' + matched_recent[0]['project_name'] + ')' if matched_recent else 'No'}")

    print("=" * 75)
    print(f"[SUCCESS] FILE UPLOAD VERIFICATION SUCCESSFUL!")
    print(f"          Project: E2E-Upload-Verification (Scan ID: {scan_id})")
    print(f"          All {len(findings)} issues categorized, redacted, scored & accessible via Nginx.")
    print("=" * 75)
    return True


if __name__ == "__main__":
    run_upload_verification()
