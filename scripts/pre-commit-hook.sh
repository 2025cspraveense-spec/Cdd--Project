#!/usr/bin/env bash
# ==============================================================================
# Standalone Git Pre-Commit Hook for Secret Leak Guard
# Can be copied directly to .git/hooks/pre-commit
# ==============================================================================

set -eo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}🛡️  [Secret Leak Guard] Running pre-commit secret detection on staged files...${NC}"

# Check if gitleaks is installed
if command -v gitleaks >/dev/null 2>&1; then
    # Run gitleaks protect on staged changes with custom configuration
    if ! gitleaks protect --staged --verbose --redact --config=.gitleaks.toml; then
        echo ""
        echo -e "${RED}═══════════════════════════════════════════════════════════════════════${NC}"
        echo -e "${RED}🚨 COMMIT REJECTED: Hardcoded secret detected in staged changes!${NC}"
        echo -e "${RED}═══════════════════════════════════════════════════════════════════════${NC}"
        echo -e "${YELLOW}Remediation Steps:${NC}"
        echo -e "  1. Unstage the sensitive file: ${BLUE}git reset HEAD <filename>${NC}"
        echo -e "  2. Replace hardcoded credentials with ${BLUE}os.environ${NC} or HashiCorp Vault."
        echo -e "  3. Move local test credentials into a ${BLUE}.env${NC} file."
        echo -e "  4. Ensure ${BLUE}.env${NC} is listed in your ${BLUE}.gitignore${NC} and ${BLUE}.dockerignore${NC}."
        echo -e "  5. Re-run: ${BLUE}git add <filename>${NC} and retry commit."
        echo -e "${RED}═══════════════════════════════════════════════════════════════════════${NC}"
        exit 1
    fi
else
    # Fallback to python scanner if gitleaks is not on system PATH
    echo -e "${YELLOW}⚠️  gitleaks binary not found on PATH. Falling back to internal Python regex scanner...${NC}"
    if python scripts/verify_demo.py --pre-commit-check; then
        echo -e "${GREEN}✅ Secret Leak Guard pre-commit check passed.${NC}"
        exit 0
    else
        echo -e "${RED}🚨 COMMIT REJECTED: Hardcoded secret pattern detected in staged files!${NC}"
        exit 1
    fi
fi

echo -e "${GREEN}✅ No secrets detected. Commit proceeding.${NC}"
exit 0
