"""
Cross-Platform Alert Dispatcher for Secret Leak Guard.
Sends masked, structured security alerts to Slack or Discord webhooks.
Includes a built-in mock webhook receiver for local testing and verification.
"""

import os
import sys
import json
import argparse
import logging
from http.server import HTTPServer, BaseHTTPRequestHandler
import urllib.request
import urllib.error

# Ensure safe UTF-8 output on Windows consoles
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")

logging.basicConfig(level=logging.INFO, format="[%(asctime)s] %(levelname)s %(message)s")
logger = logging.getLogger("AlertNotifier")


def extract_findings(gitleaks_path: str, trivy_path: str):
    """Parses Gitleaks and Trivy JSON reports, strictly masking secret values."""
    findings = []

    # 1. Parse Gitleaks
    if os.path.exists(gitleaks_path):
        try:
            with open(gitleaks_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, list):
                    for item in data[:6]:
                        rule = item.get("RuleID") or item.get("Description", "Detected Secret")
                        file_path = item.get("File", "Unknown")
                        line = item.get("StartLine", "?")
                        findings.append(f"[Gitleaks] {rule} in {file_path}:{line}")
                    if len(data) > 6:
                        findings.append(f"...and {len(data) - 6} additional Gitleaks finding(s)")
        except Exception as e:
            logger.warning("Could not parse Gitleaks report: %s", str(e))

    # 2. Parse Trivy
    if os.path.exists(trivy_path):
        try:
            with open(trivy_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                results = data.get("Results", [])
                for res in results:
                    target = res.get("Target", "Container Layer")
                    for sec in res.get("Secrets", [])[:4]:
                        title = sec.get("Title", sec.get("RuleID", "Image Secret"))
                        findings.append(f"[Trivy Image] {title} in layer/target: {target}")
        except Exception as e:
            logger.warning("Could not parse Trivy report: %s", str(e))

    if not findings:
        findings.append("Credentials detected by pipeline security scanners (Check logs)")

    return findings


def build_slack_payload(repo: str, commit: str, author: str, branch: str, findings: list) -> dict:
    short_commit = commit[:7] if commit else "HEAD"
    findings_text = "\n".join(f"• {f}" for f in findings)
    return {
        "text": f"🚨 *Secret Leak Detected!* Pipeline build blocked on `{repo}`",
        "blocks": [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": "🚨 Secret Leak Guard: Build Blocked", "emoji": True}
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
                    {"type": "mrkdwn", "text": f"*Repository:*\n{repo}"},
                    {"type": "mrkdwn", "text": f"*Branch:*\n{branch}"},
                    {"type": "mrkdwn", "text": f"*Commit:*\n<{short_commit}>"},
                    {"type": "mrkdwn", "text": f"*Author:*\n{author}"}
                ]
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Detected Secret Findings (Values Redacted):*\n```{findings_text}```"
                }
            },
            {
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": "🛡️ *Remediation:* Revoke/rotate the leaked key immediately. Purge from git history using `git-filter-repo` and inject via HashiCorp Vault or environment variables."
                    }
                ]
            }
        ]
    }


def build_discord_payload(repo: str, commit: str, author: str, branch: str, findings: list) -> dict:
    short_commit = commit[:7] if commit else "HEAD"
    findings_text = "\n".join(f"• {f}" for f in findings)
    return {
        "username": "Secret Leak Guard",
        "avatar_url": "https://raw.githubusercontent.com/gitleaks/gitleaks/master/assets/logo.png",
        "embeds": [
            {
                "title": "🚨 Build Blocked: Secret Leak Detected in CI",
                "description": "Secret Leak Guard prevented hardcoded credentials from reaching production.",
                "color": 15357993,
                "fields": [
                    {"name": "Repository", "value": repo, "inline": True},
                    {"name": "Branch", "value": branch, "inline": True},
                    {"name": "Author", "value": author, "inline": True},
                    {"name": "Commit", "value": short_commit, "inline": True},
                    {"name": "Detected Findings (Secrets Redacted)", "value": f"```{findings_text}```", "inline": False},
                    {"name": "Required Remediation", "value": "1. Rotate the leaked key at the provider.\n2. Purge secret from git using git-filter-repo.\n3. Inject via Vault or GitHub Secrets.", "inline": False}
                ],
                "footer": {"text": "Secret Leak Guard DevSecOps • Zero Hardcoded Secrets Policy"}
            }
        ]
    }


def post_webhook(url: str, payload: dict) -> bool:
    try:
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            logger.info("Webhook dispatched successfully (HTTP %d).", resp.status)
            return True
    except urllib.error.URLError as e:
        logger.error("Failed to dispatch webhook: %s", str(e))
        return False


class MockWebhookHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode("utf-8")
        logger.info("MOCK WEBHOOK RECEIVED PAYLOAD:")
        try:
            parsed = json.loads(body)
            print(json.dumps(parsed, indent=2))
        except Exception:
            print(body)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'{"status":"received"}')

    def log_message(self, format, *args):
        pass


def run_mock_server(port: int = 8085):
    server = HTTPServer(("127.0.0.1", port), MockWebhookHandler)
    logger.info("Started Mock Webhook Receiver at http://127.0.0.1:%d", port)
    logger.info("Send webhooks to: http://127.0.0.1:%d/webhook", port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Stopping mock webhook server.")
        server.server_close()


def main():
    parser = argparse.ArgumentParser(description="Secret Leak Guard Alert Dispatcher")
    parser.add_argument("--repo", default=os.getenv("GITHUB_REPO", "acme-corp/secret-leak-guard"))
    parser.add_argument("--commit", default=os.getenv("GITHUB_COMMIT", "a1b2c3d4e5f67890"))
    parser.add_argument("--author", default=os.getenv("GITHUB_AUTHOR", "devsecops-engineer"))
    parser.add_argument("--branch", default=os.getenv("GITHUB_BRANCH", "feature/payment-api"))
    parser.add_argument("--gitleaks", default="reports/gitleaks-report.json")
    parser.add_argument("--trivy", default="reports/trivy-secret-report.json")
    parser.add_argument("--webhook-url", default=os.getenv("SLACK_WEBHOOK_URL") or os.getenv("DISCORD_WEBHOOK_URL"))
    parser.add_argument("--type", choices=["slack", "discord"], default="slack")
    parser.add_argument("--mock-server", type=int, help="Run a mock webhook receiver on given port")
    parser.add_argument("--dry-run", action="store_true", help="Print payload without sending")

    args = parser.parse_args()

    if args.mock_server:
        run_mock_server(args.mock_server)
        return

    findings = extract_findings(args.gitleaks, args.trivy)

    if args.type == "discord" or (args.webhook_url and "discord.com" in args.webhook_url):
        payload = build_discord_payload(args.repo, args.commit, args.author, args.branch, findings)
    else:
        payload = build_slack_payload(args.repo, args.commit, args.author, args.branch, findings)

    if args.dry_run or not args.webhook_url:
        print("\n=== GENERATED ALERT PAYLOAD (DRY RUN) ===")
        print(json.dumps(payload, indent=2))
        print("=========================================\n")
        if not args.webhook_url:
            logger.info("No webhook URL configured. Pass --webhook-url or set SLACK_WEBHOOK_URL.")
    else:
        post_webhook(args.webhook_url, payload)


if __name__ == "__main__":
    main()
