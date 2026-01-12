#!/bin/bash
# Script to test CI/CD pipeline locally using Docker
# This simulates the GitHub Actions environment

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
IMAGE_NAME="kinetic-ci-test"

echo "🐳 Building CI test Docker image..."
echo "   This simulates the GitHub Actions ubuntu-latest runner"
echo ""

cd "$PROJECT_DIR"

# Build the Docker image
docker build -f Dockerfile.ci-test -t "$IMAGE_NAME" .

echo ""
echo "✅ Docker image built successfully!"
echo ""

# Parse command line arguments
TEST_CMD="${1:-all}"

case "$TEST_CMD" in
  "unit")
    echo "🧪 Running unit tests..."
    docker run --rm "$IMAGE_NAME" npm run test:unit
    ;;
  "integration")
    echo "🧪 Running integration tests..."
    docker run --rm "$IMAGE_NAME" npm run test:integration
    ;;
  "e2e")
    echo "🧪 Running E2E tests..."
    docker run --rm "$IMAGE_NAME" npm run test:e2e
    ;;
  "lint")
    echo "🔍 Running lint..."
    docker run --rm "$IMAGE_NAME" npm run lint
    ;;
  "format")
    echo "🔍 Running format check..."
    docker run --rm "$IMAGE_NAME" npm run format:check
    ;;
  "sqlmap")
    echo "🔍 Testing sqlmap availability..."
    docker run --rm "$IMAGE_NAME" bash -c "sqlmap --version && echo '✅ sqlmap is available'"
    ;;
  "shell")
    echo "🐚 Opening shell in container..."
    docker run --rm -it "$IMAGE_NAME" /bin/bash
    ;;
  "all")
    echo "🧪 Running full CI pipeline simulation..."
    echo ""
    echo "Step 1/5: Lint check"
    docker run --rm "$IMAGE_NAME" npm run lint
    echo ""
    echo "Step 2/5: Format check"
    docker run --rm "$IMAGE_NAME" npm run format:check
    echo ""
    echo "Step 3/5: Unit tests"
    docker run --rm "$IMAGE_NAME" npm run test:unit
    echo ""
    echo "Step 4/5: Integration tests"
    docker run --rm "$IMAGE_NAME" npm run test:integration
    echo ""
    echo "Step 5/5: Verify sqlmap"
    docker run --rm "$IMAGE_NAME" bash -c "sqlmap --version"
    echo ""
    echo "✅ All CI checks passed!"
    ;;
  *)
    echo "Usage: $0 [command]"
    echo ""
    echo "Commands:"
    echo "  all         - Run full CI pipeline (default)"
    echo "  unit        - Run unit tests only"
    echo "  integration - Run integration tests only"
    echo "  e2e         - Run E2E tests only"
    echo "  lint        - Run ESLint only"
    echo "  format      - Run format check only"
    echo "  sqlmap      - Test sqlmap availability"
    echo "  shell       - Open interactive shell in container"
    exit 1
    ;;
esac

echo ""
echo "🎉 Done!"
