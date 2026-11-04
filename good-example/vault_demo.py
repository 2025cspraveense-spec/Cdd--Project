"""
HashiCorp Vault Dev Mode Setup & Secret Ingestion Demo.
Connects to a running Vault server in dev mode, mounts KV v2, writes sample secrets,
and prints safe masked confirmation.
"""

import os
import sys
import logging

logging.basicConfig(level=logging.INFO, format="[%(asctime)s] %(levelname)s %(message)s")
logger = logging.getLogger("VaultDemo")

VAULT_ADDR = os.getenv("VAULT_ADDR", "http://127.0.0.1:8200")
VAULT_TOKEN = os.getenv("VAULT_TOKEN", "root")
SECRET_PATH = os.getenv("VAULT_SECRET_PATH", "payment-service")
MOUNT_POINT = os.getenv("VAULT_MOUNT_POINT", "secret")


def setup_vault_secrets():
    try:
        import hvac  # type: ignore
    except ImportError:
        logger.error("hvac library not installed. Install with: pip install hvac")
        sys.exit(1)

    logger.info("Connecting to Vault at %s...", VAULT_ADDR)
    client = hvac.Client(url=VAULT_ADDR, token=VAULT_TOKEN)

    if not client.is_authenticated():
        logger.error("Failed to authenticate with Vault. Check VAULT_TOKEN.")
        sys.exit(1)

    logger.info("Authentication successful. Configuring KV-v2 engine...")

    # Define simulated production secrets to store securely in Vault
    secrets_payload = {
        "AWS_ACCESS_KEY_ID": "AKIAIOSFODNN7EXAMPLE",
        "AWS_SECRET_ACCESS_KEY": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "DATABASE_URL": "postgresql://vault_user:SuperSecretVaultP@ss!@pg-cluster.internal:5432/production_db",
        "SLG_PROJECT_API_TOKEN": "SLG_demo_9876543210abcdef9876543210abcdef",
        "SECRET_KEY": "f3b890a12e3456789abcdef012345678",
    }

    try:
        create_response = client.secrets.kv.v2.create_or_update_secret(
            path=SECRET_PATH,
            secret=secrets_payload,
            mount_point=MOUNT_POINT,
        )
        logger.info("Successfully wrote secrets to path: %s/%s", MOUNT_POINT, SECRET_PATH)
        logger.info("Vault Version Response: %s", create_response.get("data", {}).get("version"))

        # Read back to verify
        read_response = client.secrets.kv.v2.read_secret_version(
            path=SECRET_PATH,
            mount_point=MOUNT_POINT,
        )
        stored_keys = list(read_response["data"]["data"].keys())
        logger.info("Verified stored secret keys: %s", stored_keys)
        print("\n✅ Vault is ready! Export the following to your application shell:")
        print(f"   export VAULT_ADDR=\"{VAULT_ADDR}\"")
        print(f"   export VAULT_TOKEN=\"{VAULT_TOKEN}\"")
        print(f"   export VAULT_SECRET_PATH=\"{SECRET_PATH}\"")

    except Exception as e:
        logger.error("Error writing secrets to Vault: %s", str(e))
        sys.exit(1)


if __name__ == "__main__":
    setup_vault_secrets()
