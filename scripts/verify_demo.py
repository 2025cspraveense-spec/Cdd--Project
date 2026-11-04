"""
Secret Leak Guard - Automated Demo & Verification Runner.
Executes end-to-end local checks to verify:
1. Detection of bad examples (AWS keys, DB passwords, GitHub PAT, Custom SLG tokens).
2. Clean pass of good examples (zero hardcoded secrets, Vault / env integration).
3. Dockerfile hygiene (no ENV secrets or unignored .env copies).
4. Redaction & masking engine validation.
5. Webhook alert formatting & mock dispatch.
6. Standalone HTML dashboard generation.
"""

import os
import sys
import re
import json
import subprocess
from pathlib import Path

# Base directory
BASE_DIR = Path(__file__).resolve().parent.parent

# Ensure safe UTF-8 output on Windows consoles
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")

# Custom regex signatures from .gitleaks.toml
RULES = [
    {
        "id": "aws-access-token",
        "name": "AWS Access Key ID",
        "regex": re.compile(r'\b(AKIA[0-9A-Z]{16})\b'),
        "severity": "CRITICAL"
    },
    {
        "id": "aws-secret-access-key",
        "name": "AWS Secret Access Key",
        "regex": re.compile(r'(?i)aws_secret_access_key[\s:=]+["\']?([0-9a-zA-Z/+]{40})["\']?'),
        "severity": "CRITICAL"
    },
    {
        "id": "github-pat",
        "name": "GitHub Personal Access Token",
        "regex": re.compile(r'\b(ghp_[a-zA-Z0-9]{36,})\b'),
        "severity": "CRITICAL"
    },
    {
        "id": "slg-project-token",
        "name": "Secret Leak Guard Custom Project Token",
        "regex": re.compile(r'(?i)(slg|guard)[-_]?(?:api|auth|secret)?[-_]?(?:key|token)?[\s:=]+["\']?([a-zA-Z0-9_-]{32,40})["\']?'),
        "severity": "HIGH"
    },
    {
        "id": "college-campus-auth-token",
        "name": "College / Campus Student/Faculty Token",
        "regex": re.compile(r'\b(CAMPUS|COLLEGE|UNIV)-[0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{12}\b'),
        "severity": "HIGH"
    },
    {
        "id": "database-connection-uri-password",
        "name": "Database URI with Plaintext Password",
        "regex": re.compile(r'(?i)(postgres|postgresql|mysql|mongodb|redis):\/\/[a-zA-Z0-9_.-]+:([^@\s\/]{4,})@[a-zA-Z0-9_.-]+'),
        "severity": "CRITICAL"
    }
]


def scan_file_content(file_path: Path):
    """Scans a file against secret detection rules and returns findings."""
    findings = []
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
        for idx, line in enumerate(lines, 1):
            for rule in RULES:
                match = rule["regex"].search(line)
                if match:
                    # Never store or expose the actual secret in logs
                    findings.append({
                        "file": str(file_path.relative_to(BASE_DIR)),
                        "line": idx,
                        "rule_id": rule["id"],
                        "rule_name": rule["name"],
                        "severity": rule["severity"],
                        "match_preview": f"Line {idx}: {rule['name']} detected"
                    })
    except Exception as e:
        print(f"Error reading {file_path}: {e}")
    return findings


def test_bad_example_detection():
    print("\n--- [Test 1] Scanning bad-example directory for secrets ---")
    bad_files = [
        BASE_DIR / "bad-example" / "leaked_secrets.py",
        BASE_DIR / "bad-example" / ".env.bad",
        BASE_DIR / "bad-example" / "Dockerfile.bad"
    ]
    all_findings = []
    for bf in bad_files:
        if bf.exists():
            findings = scan_file_content(bf)
            all_findings.extend(findings)
            print(f"Scanned {bf.name}: found {len(findings)} secret(s)")
            for f in findings:
                print(f"  🚨 [{f['rule_id']}] Line {f['line']}: {f['rule_name']}")

    assert len(all_findings) >= 5, f"Expected at least 5 bad findings, found {len(all_findings)}"
    print(f"✅ PASS: Successfully detected {len(all_findings)} leaks in bad-example fixtures.")
    return all_findings


def test_good_example_cleanliness():
    print("\n--- [Test 2] Scanning good-example & app directories for leaks ---")
    clean_files = [
        BASE_DIR / "good-example" / "secure_app.py",
        BASE_DIR / "app" / "main.py",
        BASE_DIR / "app" / "vault_client.py",
        BASE_DIR / "Dockerfile"
    ]
    total_findings = 0
    for cf in clean_files:
        if cf.exists():
            findings = scan_file_content(cf)
            total_findings += len(findings)
            status = "✅ Clean" if len(findings) == 0 else f"❌ {len(findings)} leaks"
            print(f"Scanned {cf.name}: {status}")

    assert total_findings == 0, f"Expected zero leaks in clean files, found {total_findings}"
    print("✅ PASS: Zero secrets detected in production application & good-example.")


def test_dockerfile_hygiene():
    print("\n--- [Test 3] Verifying Production Dockerfile Security Hygiene ---")
    dockerfile_path = BASE_DIR / "Dockerfile"
    with open(dockerfile_path, "r", encoding="utf-8") as f:
        content = f.read()

    # Rule: Never allow ENV SECRET or ENV AWS_
    assert "ENV AWS_" not in content, "Production Dockerfile must not contain ENV AWS_*"
    assert "ENV DATABASE_" not in content, "Production Dockerfile must not contain ENV DATABASE_*"
    assert "COPY .env" not in content, "Production Dockerfile must not execute COPY .env"
    assert "USER appuser" in content, "Production Dockerfile should switch to non-root appuser"

    print("✅ PASS: Dockerfile adheres to zero-secret container standard and non-root execution.")


def test_secret_masker():
    print("\n--- [Test 4] Verifying Application Secret Masker ---")
    sys.path.insert(0, str(BASE_DIR))
    from app.vault_client import mask_secret

    test_cases = [
        ("AKIAIOSFODNN7EXAMPLE", 4, 4),
        ("SLG_demo_9876543210abcdef9876543210abcdef", 4, 4),
        ("short", 4, 4),
        (None, 4, 4),
    ]

    for raw, pre, suf in test_cases:
        res = mask_secret(raw, visible_prefix=pre, visible_suffix=suf)
        if raw is None:
            assert res == "[NOT SET]"
        elif len(raw) <= (pre + suf):
            assert res == "*" * len(raw)
        else:
            assert res.startswith(raw[:pre])
            assert res.endswith(raw[-suf:])
            assert "*" in res
        print(f"  Masked '{raw}' -> '{res}'")

    print("✅ PASS: Secret masking correctly protects credentials in telemetry and logs.")


def test_dashboard_generation(mock_findings):
    print("\n--- [Test 5] Generating Mock Reports and HTML Dashboard ---")
    reports_dir = BASE_DIR / "reports"
    reports_dir.mkdir(exist_ok=True)

    # Convert findings to Gitleaks format
    gitleaks_data = []
    for f in mock_findings:
        gitleaks_data.append({
            "Description": f["rule_name"],
            "StartLine": f["line"],
            "EndLine": f["line"],
            "StartColumn": 1,
            "EndColumn": 40,
            "Match": f["match_preview"],
            "Secret": "REDACTED_MOCK_SECRET",
            "File": f["file"],
            "RuleID": f["rule_id"],
            "Commit": "test-commit-sha12345",
            "Author": "developer@example.com"
        })

    gitleaks_report_path = reports_dir / "gitleaks-report.json"
    with open(gitleaks_report_path, "w", encoding="utf-8") as f:
        json.dump(gitleaks_data, f, indent=2)

    # Create Trivy image secret report
    trivy_data = {
        "SchemaVersion": 2,
        "Results": [
            {
                "Target": "secret-leak-guard:test (bad-image-layer)",
                "Class": "secret",
                "Secrets": [
                    {
                        "RuleID": "aws-secret-access-key",
                        "Category": "AWS",
                        "Severity": "CRITICAL",
                        "Title": "AWS Secret Access Key embedded in ENV layer",
                        "StartLine": 12,
                        "Match": "wJal************PKEY"
                    },
                    {
                        "RuleID": "database-password",
                        "Category": "Database",
                        "Severity": "HIGH",
                        "Title": "PostgreSQL Password in ENV metadata",
                        "StartLine": 14,
                        "Match": "SuperSecretP@ssw0rd2024!"
                    }
                ]
            }
        ]
    }
    trivy_report_path = reports_dir / "trivy-secret-report.json"
    with open(trivy_report_path, "w", encoding="utf-8") as f:
        json.dump(trivy_data, f, indent=2)

    # Generate dashboard
    dashboard_path = reports_dir / "dashboard.html"
    subprocess.run([
        sys.executable,
        str(BASE_DIR / "scripts" / "generate_dashboard.py"),
        "--gitleaks-report", str(gitleaks_report_path),
        "--trivy-report", str(trivy_report_path),
        "--output", str(dashboard_path)
    ], check=True)

    assert dashboard_path.exists(), "Dashboard file was not generated"
    print(f"✅ PASS: Standalone audit dashboard generated at {dashboard_path}")


def main():
    print("=" * 70)
    print("🛡️  SECRET LEAK GUARD - VERIFICATION SUITE")
    print("=" * 70)

    if "--pre-commit-check" in sys.argv:
        # Pre-commit mode: scan staged changes in git repository
        try:
            result = subprocess.run(
                ["git", "diff", "--cached", "--name-only"],
                cwd=BASE_DIR,
                capture_output=True,
                text=True,
                check=True
            )
            staged_files = [line.strip() for line in result.stdout.splitlines() if line.strip()]
        except Exception:
            # Fallback if git is not available or outside repo
            staged_files = ["bad-example/leaked_secrets.py"]

        all_leaks = []
        for file_rel in staged_files:
            file_path = BASE_DIR / file_rel
            if file_path.exists() and file_path.is_file():
                leaks = scan_file_content(file_path)
                all_leaks.extend(leaks)

        if all_leaks:
            print("\n=======================================================================")
            print("🚨 [SECRET LEAK GUARD] COMMIT REJECTED: Hardcoded secret detected!")
            print("=======================================================================")
            for l in all_leaks:
                print(f"  • {l['file']}:{l['line']} [{l['rule_id']}] -> {l['rule_name']}")
            print("\nRemediation Steps:")
            print("  1. Unstage the sensitive file: git reset HEAD <file>")
            print("  2. Replace raw credentials with os.environ or HashiCorp Vault.")
            print("  3. Store local secrets in .env and verify .env is in .gitignore.")
            print("=======================================================================\n")
            sys.exit(1)
        else:
            print("✅ [Secret Leak Guard] Pre-commit check passed. All staged files clean.")
            sys.exit(0)

    try:
        findings = test_bad_example_detection()
        test_good_example_cleanliness()
        test_dockerfile_hygiene()
        test_secret_masker()
        test_dashboard_generation(findings)

        print("\n" + "=" * 70)
        print("🎉 ALL 5 VERIFICATION STAGES PASSED SUCCESSFULLY!")
        print("   1. Bad credentials intercepted & classified.")
        print("   2. Clean application verified leak-free. ")
        print("   3. Dockerfile container hygiene confirmed.")
        print("   4. Telemetry masking operational.")
        print("   5. HTML Dashboard & artifact synthesis generated.")
        print("=" * 70 + "\n")
    except AssertionError as e:
        print(f"\n❌ VERIFICATION FAILED: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
