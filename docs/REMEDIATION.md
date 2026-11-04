# Secret Incident Response & Git History Remediation Guide

When a credential is leaked into a version control system (VCS), **deleting the file or committing a fix DOES NOT protect you**. The secret remains permanently readable in the Git commit object database (`.git/objects`) and can be retrieved by anyone cloning the repository.

This incident response runbook details the industry-standard remediation protocol recommended by security teams.

---

## 🚨 Phase 1: Immediate Triage & Revocation (T+0 minutes)

> **Golden Rule of Secret Leaks:**
> *Assume any credential committed to Git has already been harvested by automated scanners.*

1. **Do NOT immediately rewrite Git history before revocation.**
   If the leaked key is active in production, rewriting Git history first gives attackers hours of uninterrupted access while you troubleshoot git commands.
2. **Revoke and Rotate the Credential at the Provider Immediately:**
   - **AWS IAM Key:**
     1. Go to AWS IAM Console &rarr; Users &rarr; Security Credentials.
     2. Create a new Access Key Pair and deploy it to your secrets manager / environment.
     3. Deactivate (Disable) the old leaked `AKIA...` key.
     4. Review AWS CloudTrail for unusual API calls (e.g. `ec2:RunInstances`, `iam:CreateUser`).
     5. Permanently delete the deactivated key once rotation is validated.
   - **GitHub Personal Access Token (PAT):**
     1. Go to GitHub &rarr; Settings &rarr; Developer Settings &rarr; Personal Access Tokens.
     2. Revoke the token immediately.
     3. Generate a fine-grained PAT with minimal scope and short expiration.
   - **Database Password:**
     1. Change password on the database cluster (`ALTER USER dbuser WITH PASSWORD '...';`).
     2. Update the secret in HashiCorp Vault or AWS Secrets Manager.
     3. Restart services to load the new credentials.

---

## 🧹 Phase 2: Purging the Secret from Git History (T+15 minutes)

Standard `git rm` only creates a new commit removing the file; past commits still contain the secret. To completely purge the secret from Git history, use [`git-filter-repo`](https://github.com/newren/git-filter-repo) (the modern, official replacement for deprecated `git filter-branch` and BFG Repo-Cleaner).

### Step 1: Install `git-filter-repo`
```bash
pip install git-filter-repo
```

### Step 2: Create a Fresh Mirror Clone
Always perform history rewriting on a fresh backup copy:
```bash
git clone --mirror https://github.com/your-org/secret-leak-guard.git secret-leak-guard-clean
cd secret-leak-guard-clean
```

### Step 3: Replace the Leaked Secret Across All Commits
Create an expressions replacement file `expressions.txt`:
```text
AKIAIOSFODNN7EXAMPLE==>REDACTED_AWS_KEY
wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY==>REDACTED_AWS_SECRET
SuperSecretP@ssw0rd2024!==>REDACTED_DB_PASSWORD
SLG_demo_9876543210abcdef9876543210abcdef==>REDACTED_PROJECT_TOKEN
CAMPUS-2024-ENGG-987654321098==>REDACTED_CAMPUS_TOKEN
```

Execute the rewrite:
```bash
git filter-repo --replace-text expressions.txt
```

### Alternatively: Remove an Entire Sensitive File From History
If a `.env` file was committed accidentally:
```bash
git filter-repo --invert-paths --path .env --path bad-example/.env.bad
```

### Step 4: Force Push the Clean History
> ⚠️ **Warning:** This rewrites all commit hashes. Coordinate with your team before running:
```bash
git remote add origin https://github.com/your-org/secret-leak-guard.git
git push origin --force --all
git push origin --force --tags
```

### Step 5: Instruct Collaborators to Re-Clone
Collaborators must re-clone the repository to prevent accidentally pushing old dangling commit trees back to remote:
```bash
rm -rf old-local-repo
git clone https://github.com/your-org/secret-leak-guard.git
```

---

## 🔒 Phase 3: Long-Term Shift-Left Prevention

1. **Activate Pre-Commit Hooks:**
   ```bash
   pip install pre-commit
   pre-commit install
   ```
2. **Maintain Strict Git & Docker Ignores:**
   Ensure `.env`, `*.key`, `*.pem`, and `secrets/` are in both `.gitignore` and `.dockerignore`.
3. **Automate Secret Scanning in CI/CD:**
   Keep GitHub Actions Stage 1 (`gitleaks`) and Stage 2 (`trivy image --scanners secret`) mandatory on all pull requests.
4. **Use Dynamic Secrets (HashiCorp Vault):**
   Transition static passwords to Vault dynamic database credentials with automatic short-lived leases (e.g. 1 hour).
