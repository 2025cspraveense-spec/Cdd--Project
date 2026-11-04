# Good Example: Secure Secret Ingestion & Vault Architecture

This directory demonstrates the **remediation architecture** for Secret Leak Guard. It illustrates how to transition from risky hardcoded secrets to **12-Factor App dynamic secret injection** using environment variables, GitHub Secrets, or HashiCorp Vault.

---

## 🛡️ Core Remediation Pillars

| Flaw in Bad Example | Secure Remediation in Good Example |
| :--- | :--- |
| Hardcoded API keys in `.py` | `os.getenv("KEY")` or HashiCorp Vault API |
| `ENV SECRET=...` in `Dockerfile` | Injected at runtime (`docker run --env-file`) |
| `COPY .env /app/.env` | Ignored via `.dockerignore` and `.gitignore` |
| Plaintext logging of secrets | `mask_secret()` redacting formatter |
| Secrets exposed in Git history | Purged via `git-filter-repo` & keys rotated |

---

## 🚀 Running the Good Example

### Option A: Local Development with `.env` (Ignored by Git)
1. Copy template to local file:
   ```bash
   cp good-example/.env.example .env
   ```
2. Populate `.env` with development test values.
3. Run the secure app:
   ```bash
   python good-example/secure_app.py
   ```

### Option B: HashiCorp Vault Dev Mode
1. Start Vault dev server:
   ```bash
   docker run -d --name slg-vault -p 8200:8200 -e 'VAULT_DEV_ROOT_TOKEN_ID=root' hashicorp/vault:latest
   ```
2. Populate Vault KV secrets:
   ```bash
   python good-example/vault_demo.py
   ```
3. Run the Flask application configured with Vault:
   ```bash
   export VAULT_ADDR="http://127.0.0.1:8200"
   export VAULT_TOKEN="root"
   python app/main.py
   ```
4. Access the web dashboard at `http://localhost:5000` to verify secrets are loaded dynamically into memory while masked in all output.
