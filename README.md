# 🛡️ Secret Leak Guard — Universal Source Code Security Scanner & Pipeline Defense

> **Enterprise-Grade DevSecOps Project:** A centralized multi-engine security scanning platform and automated CI/CD pipeline defense. Scans external codebases, ZIP archives, GitHub repositories, Dockerfiles, and Git history for leaked secrets, SAST vulnerabilities, vulnerable dependencies, and container risks.

[![Python 3.12+](https://img.shields.io/badge/Python-3.12%2B-blue?logo=python&logoColor=white)](https://python.org)
[![MongoDB](https://img.shields.io/badge/MongoDB-7.0-green?logo=mongodb&logoColor=white)](https://www.mongodb.com/)
[![React](https://img.shields.io/badge/React-18-cyan?logo=react&logoColor=white)](https://react.dev/)
[![Gitleaks](https://img.shields.io/badge/Gitleaks-v8.24-blue?logo=git&logoColor=white)](https://github.com/gitleaks/gitleaks)
[![Trivy](https://img.shields.io/badge/Trivy-Container%20Scanner-purple?logo=aquasec&logoColor=white)](https://github.com/aquasecurity/trivy)
[![Pre-Commit](https://img.shields.io/badge/pre--commit-enabled-brightgreen?logo=pre-commit&logoColor=white)](https://pre-commit.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## 🌟 Universal Scanner Overview (v2.0 Architecture)

The **Universal Source Code Security Scanner** expands Secret Leak Guard into a complete web-based DevSecOps platform capable of analyzing arbitrary untrusted repositories, archives, and containers without executing code.

```mermaid
flowchart TD
    subgraph Ingestion["Untrusted Input Ingestion"]
        I1["📁 Local Project Folder"]
        I2["📦 ZIP / Archive Upload"]
        I3["🌐 GitHub Repo URL"]
        I4["🐳 Dockerfile / Compose"]
        I5["📄 Single Source File"]
    end

    subgraph Sandbox["Quarantine Sandbox & Security Boundary"]
        UM["Upload Manager (Zip Slip & Bomb Defense)"]
        RM["Repository Manager (SSRF Guard & Shallow Clone)"]
        DIR["Ephemeral Sandbox Workspace (/tmp/scanner_workspaces)"]
    end

    subgraph Core["Multi-Engine Scan Orchestration"]
        SO["Scan Orchestrator"]
        E1["Secret Detection (Gitleaks CLI + Entropy)"]
        E2["SAST Engine (Semgrep + Bandit + AST Visitor)"]
        E3["Dependency Scanner (pip-audit + OSV.dev)"]
        E4["Docker Security (Trivy + CIS Benchmarks)"]
        E5["Git History Scanner (Historic Commits)"]
    end

    subgraph Storage["Persistence & Redaction"]
        NORM["Result Normalizer & Redactor"]
        RISK["Risk Scorer (CVSS 0-100 & Grades A+ to F)"]
        MDB[("MongoDB 7.0 / In-Memory Fallback")]
    end

    subgraph UI_Reports["Dashboard & Reporting"]
        API["Flask RESTful API (Port 5050)"]
        DASH["React.js + Bootstrap + Chart.js Dashboard"]
        REP["Export Formats: PDF, JSON, SARIF, HTML"]
    end

    I1 & I2 --> UM
    I3 --> RM
    I4 & I5 --> UM
    UM & RM --> DIR --> SO
    SO --> E1 & E2 & E3 & E4 & E5 --> NORM --> RISK --> MDB
    MDB --> API --> DASH & REP
```

### Key Security Modules

1. **A. Secret Detection Engine (`Gitleaks` + Shannon Entropy + Regex)**
   - Flags AWS keys, GitHub tokens, database passwords, unencrypted private keys, JWT secrets, and Slack/Discord webhooks.
   - Shannon entropy detector flags high-entropy tokens (> 4.5 bits/char).
   - Zero-leak guarantee: all secrets are strictly masked (`AKIA****************`) in evidence, reports, and logs.

2. **B. SAST Vulnerability Detection Engine (`Semgrep` + `Bandit` + Python AST)**
   - Detects SQL injection, command injection (`shell=True`), Cross-Site Scripting (XSS), path traversal, insecure deserialization (`pickle.loads`), weak cryptography (MD5/SHA1), and unsafe file uploads.
   - Maps each finding to standard CWE and OWASP Top 10 categories.

3. **C. Dependency Vulnerability Scanner (`pip-audit` + `OSV-Scanner` + `OSV.dev`)**
   - Parses `requirements.txt`, `package.json`, `pom.xml`, `go.mod`, and `Gemfile`.
   - Cross-references package versions against Google's OSV database and local vulnerability definitions for CVE reporting.

4. **D. Docker & Container Security Scanner (`Trivy` + CIS Rules)**
   - Scans `Dockerfile` and `docker-compose.yml` for non-root execution (`USER root`), hardcoded `ENV` secrets, copying `.env` files, dangerous exposed ports (`EXPOSE 22`, `EXPOSE 2375`), and privileged mounts (`/var/run/docker.sock`).

5. **E. Git History Scanner (`Gitleaks` history mode)**
   - Inspects historic Git commits for credentials deleted from current HEAD but still present in commit history.

---

## 🚀 Quickstart Guide: Running the Universal Scanner

### 1. Launching via Python Local Server

```bash
cd secret-leak-guard

# Run the Universal Scanner API and Portal (Port 5050)
python scripts/run_scanner.py
```

- **DevSecOps Portal Dashboard:** Open [http://localhost:5050/](http://localhost:5050/) in your browser.
- **Health & Matrix Endpoint:** [http://localhost:5050/api/v1/health](http://localhost:5050/api/v1/health)
- **REST API Documentation:** [http://localhost:5050/api/v1/scans](http://localhost:5050/api/v1/scans)

### 2. Launching via Docker Compose (with MongoDB 7.0 & Vault)

```bash
cd secret-leak-guard

# Start MongoDB, Vault, Scanner API, and Demo App
docker compose up -d
```

### 3. Running Automated Test Suites

```bash
cd secret-leak-guard

# Run Universal Scanner test suite (12 tests: ZipSlip, SSRF, SAST, Docker, PDF, API)
pytest tests/test_universal_scanner.py -v

# Run existing pipeline and secret leak guard tests (9 tests)
pytest tests/test_secret_leak_guard.py -v

# Run 5-stage verification scenario
python scripts/verify_demo.py
```

---

## 📌 Why This Matters (The Problem)

Hardcoded credentials are one of the most common and devastating attack vectors in modern software delivery:

- **12.8+ Million Secrets Exposed in 2023:** According to the *GitGuardian State of Secrets Sprawl* report, over 12.8 million plaintext credentials were leaked on public GitHub commits in a single year—a 28% increase year-over-year.
- **\$4.88 Million Average Breach Cost:** The *IBM Cost of a Data Breach Report* identifies compromised credentials as the primary initial attack vector and among the most expensive to remediate.
- **Docker Layer Exposure:** Committing `.env` or using `ENV SECRET=...` in a Dockerfile bakes secrets into container layer metadata. Anyone with `docker pull` access can extract them via `docker inspect` or `docker history`.
- **Shift-Left Security Philosophy:** Fixing a credential leak in production takes an average of **several days**, requires revoking access, rotating infrastructure, and scrubbing commit logs. Intercepting the secret **at `git commit` takes 2 seconds** and costs zero downtime.

---

## 🏛️ Architecture & Defense-in-Depth Flow

```mermaid
flowchart TD
    subgraph Local_Dev["Developer Machine (Shift-Left Gate 1)"]
        Dev["Developer writes code / Dockerfile"]
        Stage["git add file.py"]
        PreCommit{"Pre-Commit Hook\n(Gitleaks)"}
        BlockLocal["❌ COMMIT BLOCKED\nPrint File, Line, Rule ID"]
        CommitOK["✅ Commit Allowed\n(No secrets found)"]
        
        Dev --> Stage --> PreCommit
        PreCommit -- "Secret Detected" --> BlockLocal
        PreCommit -- "Clean Code" --> CommitOK
    end

    subgraph CI_Pipeline["GitHub Actions CI Pipeline (Stage 1 & 2)"]
        Push["git push origin main"]
        
        subgraph Stage1["Stage 1: Repository Scan"]
            GL_Scan["Gitleaks Full Repo &\nCommit History Scan"]
            GL_Fail{"Secrets in Git?"}
        end

        subgraph Stage2["Stage 2: Container Scan"]
            DockerBuild["docker build -t app:tag ."]
            TrivyScan["Trivy Image Scanner\n(--scanners secret)"]
            TrivyFail{"Secrets in Image Layers\nor ENV metadata?"}
        end

        CommitOK --> Push --> GL_Scan
        GL_Scan --> GL_Fail
        GL_Fail -- "Passed" --> DockerBuild --> TrivyScan --> TrivyFail
    end

    subgraph Alert_Stage["Stage 3: Alert & Reporting Gate"]
        Webhook["scripts/alert.sh\n(Masked Payload)"]
        Slack["Slack Channel Alert\n(Values Redacted)"]
        Discord["Discord Channel Alert\n(Values Redacted)"]
        Dashboard["Generate HTML Audit Dashboard\n(reports/dashboard.html)"]
        FailCI["❌ Fail Pipeline Build"]
        
        GL_Fail -- "Secrets Detected" --> Webhook
        TrivyFail -- "Secrets Detected" --> Webhook
        Webhook --> Slack
        Webhook --> Discord
        Webhook --> Dashboard --> FailCI
    end

    subgraph Secure_Runtime["Secure Runtime Ingestion (Good Fix)"]
        CleanApp["Flask Web Application\n(app/main.py)"]
        RuntimeVault["HashiCorp Vault KV v2\n(/secret/data/payment-service)"]
        RuntimeEnv[".env (Gitignored) /\nGitHub Secrets Injection"]
        
        TrivyFail -- "All Gates Green" --> CleanApp
        CleanApp -.-> RuntimeVault
        CleanApp -.-> RuntimeEnv
    end

    style BlockLocal fill:#8b0000,color:#fff,stroke:#ff0000
    style FailCI fill:#8b0000,color:#fff,stroke:#ff0000
    style CommitOK fill:#006400,color:#fff,stroke:#00ff00
    style CleanApp fill:#004d40,color:#fff,stroke:#00bfa5
    style Dashboard fill:#1a237e,color:#fff,stroke:#3949ab
```

---

## 🗂️ Repository Structure

```text
secret-leak-guard/
├── .github/
│   └── workflows/
│       └── secret-scan.yml        # 3-Stage CI/CD Pipeline (Gitleaks -> Trivy -> Alert)
├── app/
│   ├── __init__.py
│   ├── main.py                   # Production Flask application with log masking
│   ├── vault_client.py           # HashiCorp Vault KV-v2 client with env fallback
│   └── requirements.txt          # App dependencies (Flask, hvac, python-dotenv)
├── bad-example/                  # ❌ INTENTIONAL TEST FIXTURES
│   ├── Dockerfile.bad            # Contains ENV AWS_SECRET_ACCESS_KEY and COPY .env
│   ├── .env.bad                  # Committed credential file anti-pattern
│   ├── leaked_secrets.py         # Hardcoded AWS, DB URI, GitHub PAT, College token
│   └── README.md                 # Explanations of flaws
├── good-example/                 # ✅ SECURE ARCHITECTURE FIXES
│   ├── .env.example              # Clean configuration template with placeholders
│   ├── docker-compose.vault.yml  # Vault dev container + app compose stack
│   ├── secure_app.py             # 12-Factor App dynamic secret injection
│   ├── vault-setup.sh            # Vault KV engine initializer script
│   ├── vault_demo.py             # Vault test client verification script
│   └── README.md
├── docs/
│   └── REMEDIATION.md            # Key rotation & git-filter-repo purging runbook
├── reports/
│   ├── dashboard.html            # Standalone DevSecOps audit dashboard
│   ├── gitleaks-report.json      # Gitleaks machine-readable findings
│   └── trivy-secret-report.json  # Trivy container secret findings
├── scripts/
│   ├── alert.sh                  # Slack & Discord webhook dispatcher (Bash/cURL)
│   ├── alert.py                  # Cross-platform alert dispatcher + Mock Server
│   ├── generate_dashboard.py     # HTML report compiler from JSON scans
│   ├── install-hooks.sh          # 1-command pre-commit installer
│   ├── pre-commit-hook.sh        # Standalone pre-commit scanner
│   └── verify_demo.py            # Automated end-to-end test suite
├── .dockerignore                 # Excludes .env, .git, bad-example from Docker context
├── .gitignore                    # Prevents git tracking of .env, keys, and tokens
├── .gitleaks.toml                # Custom detection rules & path allowlists
├── .pre-commit-config.yaml       # Official pre-commit framework config
├── Dockerfile                    # Hardened, zero-secret production Docker image
└── README.md
```

---

## 🚀 Quickstart & Installation

### Prerequisites
- Python 3.9+
- Git 2.30+
- Docker (optional for container scans & Vault dev server)

### 1. Clone & Set Up Environment
```bash
git clone https://github.com/your-username/secret-leak-guard.git
cd secret-leak-guard

# Create and activate virtual environment
python -m venv .venv
source .venv/bin/activate       # On Linux/macOS
# .venv\Scripts\activate        # On Windows PowerShell

# Install dependencies
pip install -r app/requirements.txt
```

### 2. Install Pre-Commit Hooks
Choose **Option A** (Pre-Commit Framework) or **Option B** (Standalone Hook):

#### Option A: Official Pre-Commit Framework
```bash
pip install pre-commit
pre-commit install
```

#### Option B: Standalone Native Hook (Zero Extra Dependencies)
```bash
chmod +x scripts/install-hooks.sh
./scripts/install-hooks.sh
# On Windows PowerShell:
# Copy-Item scripts\pre-commit-hook.sh .git\hooks\pre-commit
```

---

## 🧪 Demo Scenario: Bad &rarr; Blocked &rarr; Fixed

### ❌ Step 1: The Bad Example (Accidental Secret Leak)
A developer attempts to commit hardcoded cloud credentials in `bad-example/leaked_secrets.py`:
```python
# ❌ Hardcoded in bad-example/leaked_secrets.py
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
DATABASE_URI = "postgresql://dbadmin:SuperSecretP@ssw0rd2024!@postgres-prod.internal:5432/db"
SLG_PROJECT_API_TOKEN = "SLG_demo_9876543210abcdef9876543210abcdef"
CAMPUS_AUTH_TOKEN = "CAMPUS-2024-ENGG-987654321098"
```
Or attempts to bake credentials into a Dockerfile (`bad-example/Dockerfile.bad`):
```dockerfile
# ❌ Baked into image metadata and layers
ENV AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
COPY bad-example/.env.bad /app/.env
```

---

## 🛑 Step 2: The Block (Pre-Commit & CI Enforcement)

#### Local Gate: Pre-Commit Hook Interception
Stage the bad file and attempt to commit:
```bash
git add bad-example/leaked_secrets.py
git commit -m "feat: add payment gateway connector"
```

**Result:** The commit is immediately **BLOCKED** locally before touching git:
```text
=======================================================================
🚨 [SECRET LEAK GUARD] COMMIT REJECTED: Hardcoded secret detected!
=======================================================================
  • bad-example/leaked_secrets.py:17 [aws-access-token] -> AWS Access Key ID
  • bad-example/leaked_secrets.py:18 [aws-secret-access-key] -> AWS Secret Access Key
  • bad-example/leaked_secrets.py:22 [database-connection-uri-password] -> Database URI with Plaintext Password
  • bad-example/leaked_secrets.py:26 [github-pat] -> GitHub Personal Access Token
  • bad-example/leaked_secrets.py:34 [college-campus-auth-token] -> College / Campus Student/Faculty Token

Remediation Steps:
  1. Unstage the sensitive file: git reset HEAD <file>
  2. Replace raw credentials with os.environ or HashiCorp Vault.
  3. Store local secrets in .env and verify .env is in .gitignore.
=======================================================================
```

#### Remote Gate: GitHub Actions Pipeline Interception
If a developer bypassed the local hook with `git commit --no-verify`, the CI pipeline catches it in two stages:
1. **Stage 1 (Gitleaks):** Scans the entire repo and full commit history (`fetch-depth: 0`). Fails with non-zero exit code.
2. **Stage 2 (Trivy):** Scans container layers and `ENV` metadata:
   ```bash
   trivy image --scanners secret bad-app-image:test
   ```
   **Output:** Detects embedded `AWS_SECRET_ACCESS_KEY` in image layer and fails the build.
3. **Stage 3 (Alert Dispatcher):** Immediately dispatches an incident payload to Slack/Discord:

```text
🚨 Secret Leak Guard: Build Blocked
Repository: acme-corp/secret-leak-guard
Branch: feature/payment-api
Commit: a1b2c3d (devsecops-engineer)
Detected Findings (Values Redacted):
• [Gitleaks] aws-access-token in bad-example/leaked_secrets.py:17
• [Gitleaks] slg-project-token in bad-example/leaked_secrets.py:28
• [Trivy Image] AWS Secret Access Key in layer: secret-leak-guard:test
Remediation:
1. Revoke/rotate the leaked key immediately at the provider.
2. Purge from git history using git-filter-repo.
3. Inject via HashiCorp Vault or environment variables.
```

---

### ✅ Step 3: The Safe Fix (Dynamic Runtime Secret Injection)

1. **Unstage the bad file:**
   ```bash
   git reset HEAD bad-example/leaked_secrets.py
   ```
2. **Copy the environment template:**
   ```bash
   cp good-example/.env.example .env
   ```
3. **Configure application to consume secrets dynamically:**
   The application (`good-example/secure_app.py` and `app/main.py`) reads from environment variables or HashiCorp Vault:
   ```python
   # ✅ Secure runtime resolution (Zero hardcoded secrets)
   AWS_ACCESS_KEY_ID = os.getenv("AWS_ACCESS_KEY_ID")
   DATABASE_URL = os.getenv("DATABASE_URL")
   SLG_PROJECT_API_TOKEN = os.getenv("SLG_PROJECT_API_TOKEN")
   ```
4. **Enforce `.gitignore` and `.dockerignore`:**
   ```gitignore
   # .gitignore & .dockerignore
   .env
   .env.*
   !.env.example
   secrets/
   *.pem
   *.key
   ```
5. **Run the production container safely:**
   Inject credentials at runtime—**never bake them into the image**:
   ```bash
   docker build -t secret-leak-guard:latest .
   docker run -d --name slg-app -p 5000:5000 --env-file .env secret-leak-guard:latest
   ```
6. **Verify the pipeline passes 100% Green!**

---

## 🏛️ HashiCorp Vault Integration (Dev Mode)

For enterprise setups, `app/vault_client.py` natively supports HashiCorp Vault KV-v2 with automatic fallback to environment variables.

### 1. Start Vault Dev Server
```bash
docker run -d \
  --name slg-vault \
  -p 8200:8200 \
  -e 'VAULT_DEV_ROOT_TOKEN_ID=root' \
  -e 'VAULT_DEV_LISTEN_ADDRESS=0.0.0.0:8200' \
  hashicorp/vault:latest
```

### 2. Populate Vault Secrets
```bash
python good-example/vault_demo.py
# Or using the bash setup script:
# bash good-example/vault-setup.sh
```

### 3. Run Application with Vault Authentication
```bash
export VAULT_ADDR="http://127.0.0.1:8200"
export VAULT_TOKEN="root"
export VAULT_SECRET_PATH="payment-service"

python app/main.py
```
Open `http://localhost:5000` to inspect the live status card displaying dynamically loaded, masked secrets:
- `AWS_ACCESS_KEY_ID`: `AKIA************MPLE` (Source: `HASHICORP_VAULT`)
- `DATABASE_URL`: `postgresql://vault_user:********@...` (Source: `HASHICORP_VAULT`)

---

## 🎯 Custom Gitleaks Rules (`.gitleaks.toml`)

In addition to standard AWS, Azure, GCP, and GitHub patterns, this project configures specialized custom rules for organization and university tokens:

```toml
# 1. Custom Project API Token (Format: SLG_<32 alphanumeric>)
[[rules]]
id = "slg-project-token"
description = "Secret Leak Guard Internal Project API Token"
regex = '''(?i)(slg|guard)[-_]?(?:api|auth|secret)?[-_]?(?:key|token)?[\s:=]+['"]?([a-zA-Z0-9_-]{32,40})['"]?'''
keywords = ["slg", "guard"]

# 2. College / Campus Authentication Token
# Format: CAMPUS-YYYY-DEPT-XXXXXXXXXXXX
[[rules]]
id = "college-campus-auth-token"
description = "Campus University Student/Faculty Auth Token"
regex = '''\b(CAMPUS|COLLEGE|UNIV)-[0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{12}\b'''
keywords = ["CAMPUS", "COLLEGE", "UNIV"]
```

---

## 📊 Interactive HTML Audit Dashboard

The pipeline compiles JSON findings from both Gitleaks and Trivy into a unified, responsive executive report (`reports/dashboard.html`):

To generate or view the dashboard locally:
```bash
python scripts/generate_dashboard.py \
  --gitleaks-report reports/gitleaks-report.json \
  --trivy-report reports/trivy-secret-report.json \
  --output reports/dashboard.html
```
Open `reports/dashboard.html` in your browser to explore:
- **KPI Metrics:** Total findings, Critical leaks, High-severity items.
- **Interactive Filtering:** Filter by Scanner (Gitleaks vs Trivy) or Severity.
- **Live Search:** Instant filter by rule ID, file name, or line number.
- **Redacted Previews:** Inspect finding context safely without exposing plain secrets.

---

## 🧹 Secret Revocation & Git History Purging (`git-filter-repo`)

> ⚠️ **CRITICAL SECURITY NOTE:**
> Committing a deletion or removing a secret with `git rm` does **NOT** revoke it!
> Follow this two-step emergency protocol:

### Step 1: Immediate Revocation
Revoke the exposed key in the cloud provider console (AWS IAM, GitHub PAT Settings, or Database Admin) before doing anything else.

### Step 2: Purge Commit History with `git-filter-repo`
Use `git-filter-repo` (the official standard replacing deprecated `git filter-branch`):

```bash
# 1. Install git-filter-repo
pip install git-filter-repo

# 2. Clone a fresh mirror of the repository
git clone --mirror https://github.com/your-org/secret-leak-guard.git clean-repo
cd clean-repo

# 3. Create a replacement file expressions.txt
echo "AKIAIOSFODNN7EXAMPLE==>REDACTED_AWS_KEY" >> expressions.txt
echo "SuperSecretP@ssw0rd2024!==>REDACTED_DB_PASS" >> expressions.txt

# 4. Rewrite all commits across all branches
git filter-repo --replace-text expressions.txt

# 5. Force push clean history to remote
git push origin --force --all
git push origin --force --tags
```
See [docs/REMEDIATION.md](docs/REMEDIATION.md) for the full incident response runbook.

---

## 📸 Screenshots Checklist for Demos

When presenting or submitting this project, capture the following screenshots:

- [ ] **Screenshot 1: Local Pre-Commit Block**
  Terminal showing `git commit` failing with the red `[SECRET LEAK GUARD] COMMIT REJECTED` banner, identifying file, line, and rule ID.
- [ ] **Screenshot 2: GitHub Actions Pipeline Failure**
  GitHub Actions tab showing Stage 1 (`stage-1-repo-scan`) and Stage 2 (`stage-2-docker-scan`) failing on a bad commit.
- [ ] **Screenshot 3: Slack / Discord Webhook Alert**
  Notification message in Slack/Discord displaying repository, commit, author, and masked finding details.
- [ ] **Screenshot 4: Standalone HTML Dashboard (`reports/dashboard.html`)**
  Browser view of the executive dashboard with metrics cards, filter pills, and finding tables.
- [ ] **Screenshot 5: Pipeline Passing 100% Green**
  GitHub Actions showing all stages passing after applying the good-example dynamic secret configuration.
- [ ] **Screenshot 6: Flask Application Security Posture Page**
  Browser showing `http://localhost:5000` with the status table confirming secrets are loaded into memory and masked in telemetry.

---

## 🔬 Automated Test & Verification Suite

Run the full end-to-end verification script:
```bash
python scripts/verify_demo.py
```
Or run the unit test suite:
```bash
python -m unittest tests/test_secret_leak_guard.py
```

All 7 unit tests and 5 verification stages run locally with zero external network dependencies.

---

## 📜 License

MIT License &bull; Built with DevSecOps best practices for pipeline security.
