# 🛡️ Secret Leak Guard for Pipelines

> **Enterprise-Grade DevSecOps Project:** Stop passwords, API tokens, and cloud keys from leaking into Git repositories or baking into Docker container image layers.

[![Gitleaks](https://img.shields.io/badge/Gitleaks-v8.24-blue?logo=git&logoColor=white)](https://github.com/gitleaks/gitleaks)
[![Trivy](https://img.shields.io/badge/Trivy-Container%20Scanner-purple?logo=aquasec&logoColor=white)](https://github.com/aquasecurity/trivy)
[![Pre-Commit](https://img.shields.io/badge/pre--commit-enabled-brightgreen?logo=pre-commit&logoColor=white)](https://pre-commit.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Security Policy](https://img.shields.io/badge/Policy-Zero%20Hardcoded%20Secrets-red)](docs/REMEDIATION.md)

---

## 📌 Why This Matters (The Problem)

Hardcoded credentials are one of the most common and devastating attack vectors in modern software delivery:

- **12.8+ Million Secrets Exposed in 2023:** According to the *GitGuardian State of Secrets Sprawl* report, over 12.8 million plaintext credentials were leaked on public GitHub commits in a single year—a 28% increase year-over-year.
- **$4.88 Million Average Breach Cost:** The *IBM Cost of a Data Breach Report* identifies compromised credentials as the primary initial attack vector and among the most expensive to remediate.
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
git clone https://github.com/2025cspraveense-spec/Cdd--Project.git
cd Cdd--Project

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
```

---

## 🧪 Demo Scenario: Bad ➔ Blocked ➔ Fixed

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

---

### 🛑 Step 2: The Block (Pre-Commit & CI Enforcement)

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
If bypassed locally with `git commit --no-verify`:
1. **Stage 1 (Gitleaks):** Scans the entire repo and full commit history (`fetch-depth: 0`). Fails with non-zero exit code.
2. **Stage 2 (Trivy):** Scans container layers and `ENV` metadata:
   ```bash
   trivy image --scanners secret secret-leak-guard:test
   ```
   **Output:** Detects embedded `AWS_SECRET_ACCESS_KEY` in image layer and fails the build.
3. **Stage 3 (Alert Dispatcher):** Immediately dispatches an incident payload to Slack/Discord with values redacted.

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
3. **Run the production container safely:**
   Inject credentials at runtime—**never bake them into the image**:
   ```bash
   docker build -t secret-leak-guard:latest .
   docker run -d --name slg-app -p 5000:5000 --env-file .env secret-leak-guard:latest
   ```

---

## 📜 License

MIT License &bull; Built with DevSecOps best practices for pipeline security.
