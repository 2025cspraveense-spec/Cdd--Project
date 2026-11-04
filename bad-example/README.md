# Bad Example: Common Secret Leak Anti-Patterns

This directory contains intentional security anti-patterns used as test fixtures to demonstrate how **Secret Leak Guard** detects and blocks leaked credentials at both the pre-commit stage and the CI pipeline stage.

> **Note:** All credentials in this directory are dummy RFC-compliant test fixtures. No real keys or accounts are associated with these values.

---

## 🚫 Anti-Patterns Demonstrated

### 1. Hardcoded Credentials in Source Code (`leaked_secrets.py`)
- **Flaw:** Committing API keys, database connection strings, and tokens directly into source files.
- **Consequence:** Anyone with repository read access (including contractors, open-source forks, compromised collaborator accounts) obtains full access to downstream cloud environments and databases.
- **Detected By:** Gitleaks pre-commit hook and CI Stage 1.

### 2. Secrets Baked into Dockerfile `ENV` Directives (`Dockerfile.bad`)
- **Flaw:** Using `ENV AWS_SECRET_ACCESS_KEY=...` in the Dockerfile.
- **Consequence:** `ENV` instructions become part of the image metadata. Running `docker inspect <image>` or `docker history <image>` reveals secrets even to unprivileged users pulling the image.
- **Detected By:** Trivy Container Image Scanner (`--scanners secret`) in CI Stage 2.

### 3. Copying Sensitive `.env` Files into Images (`Dockerfile.bad`)
- **Flaw:** Executing `COPY .env /app/.env` inside the Dockerfile without a `.dockerignore`.
- **Consequence:** The `.env` file is embedded inside the container filesystem layers. Even if `RUN rm /app/.env` is executed later, the file persists in the prior layer's blob storage.
- **Detected By:** Trivy Secret Scanner in CI Stage 2.

### 4. Logging Secrets Unmasked (`leaked_secrets.py`)
- **Flaw:** `logging.info(f"Connecting to AWS with key {AWS_ACCESS_KEY_ID}")`.
- **Consequence:** Secrets spill into centralized logging tools (Datadog, CloudWatch, Splunk, ELK) where broad teams have query access.

---

## 🔍 How to Test Detection
Run the verification script from the project root:
```bash
python scripts/verify_demo.py
```
Or test with Gitleaks directly:
```bash
gitleaks detect --source bad-example/ --verbose
```
