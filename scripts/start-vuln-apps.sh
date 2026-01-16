#!/bin/bash
# scripts/start-vuln-apps.sh
# Start all vulnerable application containers for Kinetic DAST testing
#
# Usage: ./scripts/start-vuln-apps.sh [app]
#        ./scripts/start-vuln-apps.sh          # Start all apps
#        ./scripts/start-vuln-apps.sh juice    # Start only Juice Shop

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
COMPOSE_FILE="$PROJECT_DIR/docker-compose.vuln-apps.yml"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║       Kinetic DAST - Vulnerable App Environment              ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo -e "${RED}❌ Docker is not running. Please start Docker first.${NC}"
    exit 1
fi

# Check if docker-compose file exists
if [ ! -f "$COMPOSE_FILE" ]; then
    echo -e "${RED}❌ docker-compose.vuln-apps.yml not found at: $COMPOSE_FILE${NC}"
    exit 1
fi

# Function to check if an app is healthy
check_app() {
    local name=$1
    local url=$2
    local max_attempts=${3:-30}
    local attempt=1
    
    echo -ne "  ⏳ Waiting for ${name}..."
    
    while [ $attempt -le $max_attempts ]; do
        if curl -s -o /dev/null -w "%{http_code}" "$url" 2>/dev/null | grep -q "200\|302\|301"; then
            echo -e "\r  ${GREEN}✅ ${name} is running at ${url}${NC}          "
            return 0
        fi
        sleep 2
        attempt=$((attempt + 1))
        echo -ne "\r  ⏳ Waiting for ${name}... (${attempt}/${max_attempts})"
    done
    
    echo -e "\r  ${YELLOW}⚠️  ${name} may not be fully ready at ${url}${NC}          "
    return 1
}

# Parse arguments
APP_FILTER="$1"

start_apps() {
    local services=""
    
    if [ -z "$APP_FILTER" ]; then
        echo -e "${YELLOW}🚀 Starting all vulnerable applications...${NC}"
        docker-compose -f "$COMPOSE_FILE" up -d
    else
        case "$APP_FILTER" in
            juice|juiceshop|juice-shop)
                services="juice-shop"
                ;;
            dvwa)
                services="dvwa dvwa-db"
                ;;
            bwapp)
                services="bwapp"
                ;;
            webgoat)
                services="webgoat"
                ;;
            *)
                echo -e "${RED}❌ Unknown app: $APP_FILTER${NC}"
                echo "Available apps: juice, dvwa, bwapp, webgoat"
                exit 1
                ;;
        esac
        echo -e "${YELLOW}🚀 Starting: $services${NC}"
        docker-compose -f "$COMPOSE_FILE" up -d $services
    fi
}

verify_apps() {
    echo ""
    echo -e "${YELLOW}🔍 Verifying applications...${NC}"
    echo ""
    
    local all_ok=true
    
    if [ -z "$APP_FILTER" ] || [ "$APP_FILTER" = "juice" ] || [ "$APP_FILTER" = "juiceshop" ] || [ "$APP_FILTER" = "juice-shop" ]; then
        check_app "Juice Shop" "http://localhost:3000" 45 || all_ok=false
    fi
    
    if [ -z "$APP_FILTER" ] || [ "$APP_FILTER" = "dvwa" ]; then
        check_app "DVWA" "http://localhost:8081" 45 || all_ok=false
    fi
    
    if [ -z "$APP_FILTER" ] || [ "$APP_FILTER" = "bwapp" ]; then
        check_app "bWAPP" "http://localhost:8082" 30 || all_ok=false
    fi
    
    if [ -z "$APP_FILTER" ] || [ "$APP_FILTER" = "webgoat" ]; then
        check_app "WebGoat" "http://localhost:8083/WebGoat" 60 || all_ok=false
    fi
    
    echo ""
    if $all_ok; then
        echo -e "${GREEN}✅ All requested applications are ready for testing!${NC}"
    else
        echo -e "${YELLOW}⚠️  Some applications may need more time to initialize.${NC}"
    fi
}

print_urls() {
    echo ""
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}Application URLs:${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo "  • Juice Shop:  http://localhost:3000"
    echo "  • DVWA:        http://localhost:8081  (admin/password)"
    echo "  • bWAPP:       http://localhost:8082  (bee/bug)"
    echo "  • WebGoat:     http://localhost:8083/WebGoat (webgoat/webgoat)"
    echo ""
    echo -e "${BLUE}To stop all containers:${NC}"
    echo "  docker-compose -f docker-compose.vuln-apps.yml down"
    echo ""
}

# Main execution
start_apps
verify_apps
print_urls
