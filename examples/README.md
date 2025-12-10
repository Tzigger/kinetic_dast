# Kinetic DAST - Examples

This folder contains practical examples to help you get started with Kinetic security scanning.

## 📁 Examples

| File | Description | Run Command |
|------|-------------|-------------|
| `01-quick-start.ts` | Simplest way to run a scan | `npx ts-node examples/01-quick-start.ts` |
| `02-playwright-test-integration.spec.ts` | Integrate into Playwright tests | `npx playwright test examples/02-playwright-test-integration.spec.ts` |
| `03-bwapp-scan.ts` | Scan a local vulnerable app | `npx ts-node examples/03-bwapp-scan.ts` |
| `04-cli-usage.ts` | CLI documentation & examples | Read the file for commands |
| `dast.config.json` | Example configuration file | `npx kinetic --config examples/dast.config.json` |
| `github-actions-ci.yml` | CI/CD workflow template | Copy to `.github/workflows/` |

## 🚀 Quick Start

### Option 1: CLI (Easiest)

```bash
# Build first
npm run build

# Run a quick scan
npx kinetic http://testphp.vulnweb.com --passive

# Run a thorough scan
npx kinetic http://testphp.vulnweb.com --active --max-pages 3
```

### Option 2: Standalone Script

```bash
# Run the quick start example
npx ts-node examples/01-quick-start.ts
```

### Option 3: Playwright Test Integration

```bash
# Add security tests to your test suite
npx playwright test examples/02-playwright-test-integration.spec.ts --project=chromium
```

## 🧪 Test Targets

These are public vulnerable test sites you can safely scan:

| Site | URL | Best For |
|------|-----|----------|
| TestPHP | http://testphp.vulnweb.com | SQLi, XSS, Headers |
| TestHTML5 | http://testhtml5.vulnweb.com | SPA scanning |
| bWAPP | http://localhost:8080 | Local testing (Docker) |

### Running bWAPP Locally

```bash
# Start bWAPP container
docker run -d -p 8080:80 raesene/bwapp

# Initialize database (one time)
# Open http://localhost:8080/install.php and click "Install"

# Default credentials: bee / bug
```

## 📖 Choosing the Right Approach

| Use Case | Recommended Approach |
|----------|---------------------|
| Quick security check | CLI: `npx kinetic <url> --passive` |
| CI/CD pipeline | CLI with SARIF: `npx kinetic <url> --formats sarif` |
| E2E test suite | `02-playwright-test-integration.spec.ts` |
| Custom scanning logic | `01-quick-start.ts` or `03-bwapp-scan.ts` |
| Learning/Training | `03-bwapp-scan.ts` with bWAPP |

## 🔍 What Gets Detected

### Passive Scanning (Fast)
- Missing security headers (CSP, X-Frame-Options, etc.)
- Insecure cookies (no HttpOnly, no Secure flag)
- Sensitive data exposure (API keys, passwords in responses)
- Insecure transmissions

### Active Scanning (Thorough)
- SQL Injection (error-based, boolean-based, time-based)
- Cross-Site Scripting (XSS) - reflected, stored, DOM-based
- Command Injection
- Path Traversal
- Server-Side Request Forgery (SSRF)
- Insecure Direct Object References (IDOR)
- Error-based information disclosure

## ⚠️ Important Notes

1. **Only scan applications you have permission to test**
2. Active scanning modifies inputs - use on test environments
3. Set appropriate timeouts for your network conditions
4. Use `--max-pages` to limit scan scope during testing
