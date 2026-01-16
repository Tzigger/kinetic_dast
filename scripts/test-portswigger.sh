#!/bin/bash
# PortSwigger Lab Test Runner
# 
# Usage:
#   ./scripts/test-portswigger.sh <LAB_URL> [test-filter]
#
# Examples:
#   ./scripts/test-portswigger.sh https://0a1b2c3d.web-security-academy.net "SQL injection"
#   ./scripts/test-portswigger.sh https://0a1b2c3d.web-security-academy.net "XSS"
#   ./scripts/test-portswigger.sh https://0a1b2c3d.web-security-academy.net  # Run all tests

set -e

LAB_URL="${1:-}"
TEST_FILTER="${2:-}"

if [ -z "$LAB_URL" ]; then
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "🔬 PortSwigger Web Security Academy - Lab Test Runner"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    echo "Usage: $0 <LAB_URL> [test-filter]"
    echo ""
    echo "Instructions:"
    echo "  1. Go to https://portswigger.net/web-security/all-labs"
    echo "  2. Login or create a free account"
    echo "  3. Click 'ACCESS THE LAB' on any lab"
    echo "  4. Copy the lab URL (e.g., https://0a1b2c3d.web-security-academy.net)"
    echo "  5. Run this script with the lab URL"
    echo ""
    echo "Examples:"
    echo "  $0 https://0a1b.web-security-academy.net"
    echo "  $0 https://0a1b.web-security-academy.net 'SQL injection'"
    echo "  $0 https://0a1b.web-security-academy.net 'XSS'"
    echo "  $0 https://0a1b.web-security-academy.net 'Path Traversal'"
    echo ""
    echo "Available test categories:"
    echo "  - SQL Injection"
    echo "  - Cross-Site Scripting (XSS)"
    echo "  - OS Command Injection"
    echo "  - Path Traversal"
    echo "  - SSRF"
    echo "  - XXE"
    echo "  - Access Control"
    echo "  - Authentication"
    echo "  - Information Disclosure"
    echo "  - CSRF"
    echo ""
    exit 1
fi

# Validate URL format
if [[ ! "$LAB_URL" =~ \.web-security-academy\.net ]]; then
    echo "⚠️  Warning: URL doesn't look like a PortSwigger lab URL"
    echo "   Expected format: https://XXXX.web-security-academy.net"
    echo "   Got: $LAB_URL"
    echo ""
    read -p "Continue anyway? (y/n) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🔬 PortSwigger Lab Test Runner"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "📍 Lab URL: $LAB_URL"
if [ -n "$TEST_FILTER" ]; then
    echo "🔍 Filter: $TEST_FILTER"
fi
echo ""

# Build the test command
TEST_CMD="LAB_URL=\"$LAB_URL\" npx playwright test tests/portswigger-labs.spec.ts --project=chromium --reporter=line"

if [ -n "$TEST_FILTER" ]; then
    TEST_CMD="$TEST_CMD --grep=\"$TEST_FILTER\""
fi

echo "Running: $TEST_CMD"
echo ""

# Execute
eval $TEST_CMD
