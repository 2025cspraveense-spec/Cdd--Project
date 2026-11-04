#!/usr/bin/env bash
# ==============================================================================
# Helper Script: Install Pre-Commit Hooks
# ==============================================================================

set -e

echo "🔧 Installing Secret Leak Guard Pre-Commit Hooks..."

# Approach 1: pre-commit framework (if installed)
if command -v pre-commit >/dev/null 2>&1; then
    echo "Running 'pre-commit install' via pre-commit framework..."
    pre-commit install
    echo "✅ pre-commit framework hook installed successfully!"
else
    echo "pre-commit Python package not found. Installing standalone Git hook directly into .git/hooks/pre-commit..."
    if [ -d ".git" ]; then
        mkdir -p .git/hooks
        cp scripts/pre-commit-hook.sh .git/hooks/pre-commit
        chmod +x .git/hooks/pre-commit
        echo "✅ Standalone hook copied to .git/hooks/pre-commit and made executable!"
    else
        echo "⚠️ .git directory not found. Initialize git first with 'git init'."
    fi
fi

echo ""
echo "Try committing a change to verify hook execution:"
echo "   git add <file> && git commit -m 'test'"
