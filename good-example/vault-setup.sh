#!/usr/bin/env bash
# ==============================================================================
# HashiCorp Vault Dev Mode Setup Script
# Launches Vault in lightweight dev mode, enables KV v2, and stores sample secrets.
# ==============================================================================

set -euo pipefail

VAULT_ADDR="${VAULT_ADDR:-http://127.0.0.1:8200}"
VAULT_TOKEN="${VAULT_TOKEN:-root}"
SECRET_PATH="${VAULT_SECRET_PATH:-payment-service}"

echo "============================================================"
echo "🛡️  Secret Leak Guard - HashiCorp Vault Dev Mode Initializer"
echo "============================================================"

# Check if Docker is available to launch Vault if not already running
if ! curl -s "${VAULT_ADDR}/v1/sys/health" > /dev/null 2>&1; then
    echo "Starting HashiCorp Vault in dev mode via Docker..."
    docker run -d \
        --name slg-vault-dev \
        -p 8200:8200 \
        -e 'VAULT_DEV_ROOT_TOKEN_ID=root' \
        -e 'VAULT_DEV_LISTEN_ADDRESS=0.0.0.0:8200' \
        hashicorp/vault:1.15.6 || true
    echo "Waiting for Vault to become ready..."
    sleep 3
fi

export VAULT_ADDR
export VAULT_TOKEN

echo "Writing credentials to Vault KV v2 engine: secret/data/${SECRET_PATH}..."

# Store secrets via Vault HTTP API (doesn't require vault CLI binary)
PAYLOAD=$(cat <<EOF
{
  "data": {
    "AWS_ACCESS_KEY_ID": "AKIAIOSFODNN7EXAMPLE",
    "AWS_SECRET_ACCESS_KEY": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "DATABASE_URL": "postgresql://vault_user:VaultSuperSecretP@ss!@pg-cluster.internal:5432/appdb",
    "SLG_PROJECT_API_TOKEN": "SLG_demo_9876543210abcdef9876543210abcdef",
    "SECRET_KEY": "f3b890a12e3456789abcdef012345678"
  }
}
EOF
)

RESPONSE=$(curl -s --header "X-Vault-Token: ${VAULT_TOKEN}" \
     --request POST \
     --data "${PAYLOAD}" \
     "${VAULT_ADDR}/v1/secret/data/${SECRET_PATH}")

echo "Response: ${RESPONSE}"
echo ""
echo "✅ Secrets successfully loaded into HashiCorp Vault!"
echo "Run the application with:"
echo "   export VAULT_ADDR='${VAULT_ADDR}'"
echo "   export VAULT_TOKEN='${VAULT_TOKEN}'"
echo "   python app/main.py"
