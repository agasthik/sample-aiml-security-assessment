#!/usr/bin/env bash
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'

REPO_ROOT="$(git rev-parse --show-toplevel)"
HOOKS_DIR="$REPO_ROOT/.githooks"

verify_tools() {
    local MISSING=0

    echo "Checking prerequisites..."
    echo ""

    for tool in ruff cfn-lint sam; do
        if command -v "$tool" &> /dev/null; then
            echo -e "  ${GREEN}✓${NC} $tool"
        else
            echo -e "  ${RED}✗${NC} $tool"
            MISSING=1
        fi
    done

    if command -v pytest &> /dev/null || python -m pytest --version &> /dev/null 2>&1; then
        echo -e "  ${GREEN}✓${NC} pytest"
    else
        echo -e "  ${RED}✗${NC} pytest"
        MISSING=1
    fi

    if command -v ash &> /dev/null || command -v uvx &> /dev/null; then
        echo -e "  ${GREEN}✓${NC} ash (or uvx)"
    else
        echo -e "  ${RED}✗${NC} ash (or uvx)"
        MISSING=1
    fi

    echo ""
    if [ $MISSING -ne 0 ]; then
        echo -e "${RED}Some tools are missing. Install with:${NC}"
        echo "  pip install ruff cfn-lint"
        echo "  pip install -r tests/requirements.txt"
        echo "  pip install git+https://github.com/awslabs/automated-security-helper.git"
        echo "  SAM CLI: https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/install-sam-cli.html"
        return 1
    fi

    echo -e "${GREEN}All tools installed.${NC}"
    return 0
}

# Install hooks
echo "Configuring git to use project hooks from .githooks/..."
git config core.hooksPath "$HOOKS_DIR"
echo -e "${GREEN}Done.${NC} Pre-commit and pre-push hooks are now active."
echo ""

# Verify if requested
if [ "${1:-}" = "--verify" ]; then
    verify_tools
else
    echo "Run with --verify to check that all prerequisite tools are installed."
fi
