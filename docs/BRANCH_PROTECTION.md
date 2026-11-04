# GitHub Branch Protection & Pull Request Security Enforcement

To guarantee zero unverified code merges into production, enforce GitHub Branch Protection rules on your default branch (`main` or `master`).

---

## 🛡️ Recommended Branch Protection Configuration

1. In your GitHub repository, navigate to **Settings &rarr; Branches &rarr; Branch protection rules &rarr; Add rule**.
2. **Branch name pattern:** `main` (or `master`)
3. Check **Require a pull request before merging**:
   - Require approvals: `1`
   - Dismiss stale pull request approvals when new commits are pushed: `Checked`
4. Check **Require status checks to pass before merging**:
   - Require branches to be up to date before merging: `Checked`
   - Add the following mandatory status checks from `.github/workflows/secret-scan.yml`:
     - `Stage 0: Unit Tests & Pre-Flight`
     - `Stage 1: Gitleaks & Trivy Filesystem Scan`
     - `Stage 2: Docker Build & Trivy Image Secret Scan`
5. Check **Do not allow bypassing the above settings** (Enforces rules on Repository Administrators as well).
6. Check **Include administrators**.

---

## 🚫 Pull Request Gate Flow

```text
[ Developer PR Opened ]
           │
           ▼
[ GitHub Actions Triggered ]
   ├── Stage 0: Unit Tests (PASS/FAIL)
   ├── Stage 1: Gitleaks Git History & Trivy FS Scan (PASS/FAIL)
   └── Stage 2: Container Image Secret Scan (PASS/FAIL)
           │
    ┌──────┴─────────────────────────┐
    │ All Status Checks Pass?        │
    ├──────────────────┬─────────────┤
    │ YES              │ NO          │
    ▼                  ▼             │
[ PR Merging Allowed ] [ PR Blocked ]◄
                       [ Webhook Alert Dispatched ]
```
