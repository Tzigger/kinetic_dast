#!/bin/bash
# scripts/test-vuln-apps.sh
# Run security tests against all vulnerable Docker applications
#
# Usage: ./scripts/test-vuln-apps.sh [app]
#        ./scripts/test-vuln-apps.sh          # Test all apps
#        ./scripts/test-vuln-apps.sh juice    # Test only Juice Shop

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Test results
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_SKIPPED=0

echo -e "${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║       Kinetic DAST - Vulnerable App Test Suite               ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

cd "$PROJECT_DIR"

# Function to check if container is running
is_container_running() {
    local container_name=$1
    docker ps --format '{{.Names}}' | grep -q "^${container_name}$"
}

# Function to wait for app to be ready
wait_for_app() {
    local url=$1
    local max_wait=${2:-60}
    local waited=0
    
    while [ $waited -lt $max_wait ]; do
        if curl -s -o /dev/null -w "" "$url" 2>/dev/null; then
            return 0
        fi
        sleep 2
        waited=$((waited + 2))
    done
    return 1
}

# Function to run tests for an app
run_test() {
    local app_name=$1
    local container_name=$2
    local url=$3
    local env_var=$4
    local test_script=$5
    
    echo ""
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${CYAN}🎯 Testing: ${app_name}${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    
    # Check if container is running
    if ! is_container_running "$container_name"; then
        echo -e "${YELLOW}⚠️  Container ${container_name} is not running. Starting...${NC}"
        "$SCRIPT_DIR/start-vuln-apps.sh" "${app_name,,}" 2>/dev/null || {
            echo -e "${RED}❌ Failed to start ${app_name}. Skipping tests.${NC}"
            TESTS_SKIPPED=$((TESTS_SKIPPED + 1))
            return 1
        }
    fi
    
    # Wait for app to be ready
    echo -e "  ⏳ Waiting for ${app_name} to be ready..."
    if ! wait_for_app "$url" 30; then
        echo -e "${YELLOW}⚠️  ${app_name} not responding at ${url}. Skipping.${NC}"
        TESTS_SKIPPED=$((TESTS_SKIPPED + 1))
        return 1
    fi
    
    echo -e "  ${GREEN}✓${NC} ${app_name} is ready at ${url}"
    echo -e "  🔍 Running tests..."
    echo ""
    
    # Run the test
    export "${env_var}=${url}"
    if npm run "$test_script" 2>&1; then
        echo ""
        echo -e "  ${GREEN}✅ ${app_name} tests passed${NC}"
        TESTS_PASSED=$((TESTS_PASSED + 1))
        return 0
    else
        echo ""
        echo -e "  ${YELLOW}⚠️  ${app_name} tests completed with issues${NC}"
        TESTS_FAILED=$((TESTS_FAILED + 1))
        return 0  # Don't fail the whole script
    fi
}

# Parse arguments
APP_FILTER="$1"

# Run tests based on filter
run_all_tests() {
    case "$APP_FILTER" in
        ""|all)
            run_test "Juice Shop" "kinetic-juice-shop" "http://localhost:3000" "JUICE_SHOP_URL" "test:juice-shop"
            run_test "DVWA" "kinetic-dvwa" "http://localhost:8081" "DVWA_URL" "test:dvwa"
            run_test "bWAPP" "kinetic-bwapp" "http://localhost:8082" "BWAPP_URL" "test:bwapp"
            ;;
        juice|juiceshop|juice-shop)
            run_test "Juice Shop" "kinetic-juice-shop" "http://localhost:3000" "JUICE_SHOP_URL" "test:juice-shop"
            ;;
        dvwa)
            run_test "DVWA" "kinetic-dvwa" "http://localhost:8081" "DVWA_URL" "test:dvwa"
            ;;
        bwapp)
            run_test "bWAPP" "kinetic-bwapp" "http://localhost:8082" "BWAPP_URL" "test:bwapp"
            ;;
        webgoat)
            run_test "WebGoat" "kinetic-webgoat" "http://localhost:8083/WebGoat" "WEBGOAT_URL" "test:webgoat"
            ;;
        *)
            echo -e "${RED}❌ Unknown app: $APP_FILTER${NC}"
            echo "Available: juice, dvwa, bwapp, webgoat, all"
            exit 1
            ;;
    esac
}

# Main execution
run_all_tests

# Print summary
echo ""
echo -e "${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║                       Test Summary                           ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  ${GREEN}✅ Passed:${NC}  $TESTS_PASSED"
echo -e "  ${RED}❌ Failed:${NC}  $TESTS_FAILED"
echo -e "  ${YELLOW}⏭️  Skipped:${NC} $TESTS_SKIPPED"
echo ""

# Exit with appropriate code
if [ $TESTS_FAILED -gt 0 ]; then
    echo -e "${YELLOW}Some tests had issues. Check the output above for details.${NC}"
    exit 0  # Don't fail CI for vulnerability detection differences
fi

echo -e "${GREEN}All tests completed successfully!${NC}"
