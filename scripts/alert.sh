#!/usr/bin/env bash
# ==============================================================================
# SECRET LEAK GUARD - WEBHOOK ALERT DISPATCHER (Slack & Discord)
# ==============================================================================
# Sends structured security alerts to Slack or Discord webhooks when secrets
# are detected in Git repositories or Docker images.
#
# CRITICAL SECURITY RULE:
# NEVER transmits the secret value itself! Only sends:
# - Repository, Commit SHA, Author, Branch
# - Rule / Secret Type (e.g. "AWS Access Key", "PostgreSQL Connection URI")
# - File and Line Number
# ==============================================================================

set -eo pipefail

REPO="${GITHUB_REPO:-unknown/repo}"
COMMIT="${GITHUB_COMMIT:-HEAD}"
AUTHOR="${GITHUB_AUTHOR:-developer}"
BRANCH="${GITHUB_BRANCH:-main}"
RUN_ID="${GITHUB_RUN_ID:-0}"
GITLEAKS_FILE="reports/gitleaks-report.json"
TRIVY_FILE="reports/trivy-secret-report.json"

# Parse CLI arguments
while [[ "$#" -gt 0 ]]; do
    case $1 in
        --repo) REPO="$2"; shift ;;
        --commit) COMMIT="$2"; shift ;;
        --author) AUTHOR="$2"; shift ;;
        --branch) BRANCH="$2"; shift ;;
        --run-id) RUN_ID="$2"; shift ;;
        --gitleaks) GITLEAKS_FILE="$2"; shift ;;
        --trivy) TRIVY_FILE="$2"; shift ;;
        *) echo "Unknown parameter: $1"; shift ;;
    esac
    shift
done

SHORT_COMMIT=$(echo "${COMMIT}" | cut -c1-7)
RUN_URL="https://github.com/${REPO}/actions/runs/${RUN_ID}"

echo "======================================================================"
echo "🚨 [SECRET LEAK GUARD] Processing Security Alert Dispatch"
echo "======================================================================"
echo "Repository : ${REPO}"
echo "Commit     : ${SHORT_COMMIT}"
echo "Author     : ${AUTHOR}"
echo "Branch     : ${BRANCH}"

# Extract finding summaries using python (cross-platform, reliable JSON parsing)
FINDINGS_SUMMARY=$(python3 - <<EOF
import json
import os

findings = []

# Parse Gitleaks report
if os.path.exists("${GITLEAKS_FILE}"):
    try:
        with open("${GITLEAKS_FILE}", "r", encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, list):
                for item in data[:5]:  # limit to top 5 in alert
                    rule = item.get("RuleID") or item.get("Description", "Detected Secret")
                    file_path = item.get("File", "Unknown")
                    line = item.get("StartLine", "?")
                    findings.append(f"• [Gitleaks] {rule} in {file_path}:{line}")
                if len(data) > 5:
                    findings.append(f"• ...and {len(data) - 5} additional secret(s)")
    except Exception as e:
        findings.append(f"• Error parsing Gitleaks report: {str(e)}")

# Parse Trivy report
if os.path.exists("${TRIVY_FILE}"):
    try:
        with open("${TRIVY_FILE}", "r", encoding="utf-8") as f:
            data = json.load(f)
            results = data.get("Results", [])
            for res in results:
                target = res.get("Target", "Docker Image")
                secrets = res.get("Secrets", [])
                for sec in secrets[:5]:
                    title = sec.get("Title", sec.get("RuleID", "Image Secret"))
                    findings.append(f"• [Trivy Docker] {title} in layer/target: {target}")
    except Exception as e:
        findings.append(f"• Error parsing Trivy report: {str(e)}")

if not findings:
    findings = ["• Secret detected in CI pipeline stage (Check Action logs)"]

print("\\n".join(findings))
EOF
)

echo "Findings Summary:"
echo "${FINDINGS_SUMMARY}"
echo "======================================================================"

# ------------------------------------------------------------------------------
# Dispatch to SLACK if SLACK_WEBHOOK_URL is set
# ------------------------------------------------------------------------------
if [ -n "${SLACK_WEBHOOK_URL:-}" ]; then
    echo "Sending alert to Slack webhook..."
    SLACK_PAYLOAD=$(cat <<EOF
{
  "text": "🚨 *Secret Leak Detected!* Pipeline build blocked on \`${REPO}\`",
  "blocks": [
    {
      "type": "header",
      "text": {
        "type": "plain_text",
        "text": "🚨 Secret Leak Guard: Build Blocked",
        "emoji": true
      }
    },
    {
      "type": "section",
      "text": {
        "type": "mrkdwn",
        "text": "*A secret was prevented from reaching production.* The CI pipeline detected credentials in code or container image layers."
      }
    },
    {
      "type": "section",
      "fields": [
        { "type": "mrkdwn", "text": "*Repository:*\n${REPO}" },
        { "type": "mrkdwn", "text": "*Branch:*\n${BRANCH}" },
        { "type": "mrkdwn", "text": "*Commit:*\n<https://github.com/${REPO}/commit/${COMMIT}|${SHORT_COMMIT}>" },
        { "type": "mrkdwn", "text": "*Author:*\n${AUTHOR}" }
      ]
    },
    {
      "type": "section",
      "text": {
        "type": "mrkdwn",
        "text": "*Detected Secret Findings (Values Redacted):*\n\`\`\`\n${FINDINGS_SUMMARY}\n\`\`\`"
      }
    },
    {
      "type": "context",
      "elements": [
        {
          "type": "mrkdwn",
          "text": "🛡️ *Remediation:* Revoke/rotate the leaked key immediately. Purge from git history using \`git-filter-repo\` and inject via HashiCorp Vault or environment variables."
        }
      ]
    }
  ]
}
EOF
)
    curl -s -X POST -H 'Content-type: application/json' --data "${SLACK_PAYLOAD}" "${SLACK_WEBHOOK_URL}" || true
    echo "✅ Slack notification posted."
fi

# ------------------------------------------------------------------------------
# Dispatch to DISCORD if DISCORD_WEBHOOK_URL is set
# ------------------------------------------------------------------------------
if [ -n "${DISCORD_WEBHOOK_URL:-}" ]; then
    echo "Sending alert to Discord webhook..."
    # Escape newlines for Discord JSON payload
    ESCAPED_FINDINGS=$(echo "${FINDINGS_SUMMARY}" | sed ':a;N;$!ba;s/\n/\\n/g' | sed 's/"/\\"/g')
    DISCORD_PAYLOAD=$(cat <<EOF
{
  "username": "Secret Leak Guard",
  "avatar_url": "https://raw.githubusercontent.com/gitleaks/gitleaks/master/assets/logo.png",
  "embeds": [
    {
      "title": "🚨 Build Blocked: Secret Leak Detected in CI",
      "description": "Secret Leak Guard prevented hardcoded credentials from reaching production.",
      "color": 15357993,
      "fields": [
        { "name": "Repository", "value": "${REPO}", "inline": true },
        { "name": "Branch", "value": "${BRANCH}", "inline": true },
        { "name": "Author", "value": "${AUTHOR}", "inline": true },
        { "name": "Commit", "value": "[${SHORT_COMMIT}](https://github.com/${REPO}/commit/${COMMIT})", "inline": true },
        { "name": "Detected Findings (Secrets Redacted)", "value": "\`\`\`\n${ESCAPED_FINDINGS}\n\`\`\`", "inline": false },
        { "name": "Required Remediation", "value": "1. Rotate the leaked key at the provider.\\n2. Purge secret from git using git-filter-repo.\\n3. Inject via Vault or GitHub Secrets.", "inline": false }
      ],
      "footer": { "text": "Secret Leak Guard DevSecOps • Zero Hardcoded Secrets Policy" }
    }
  ]
}
EOF
)
    curl -s -X POST -H 'Content-type: application/json' --data "${DISCORD_PAYLOAD}" "${DISCORD_WEBHOOK_URL}" || true
    echo "✅ Discord notification posted."
fi

if [ -z "${SLACK_WEBHOOK_URL:-}" ] && [ -z "${DISCORD_WEBHOOK_URL:-}" ]; then
    echo "ℹ️  Neither SLACK_WEBHOOK_URL nor DISCORD_WEBHOOK_URL configured. Alert logged to console."
fi
