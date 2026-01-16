# AGENTS.md - AI Agent Guide for Kinetic Security Scanner

> Instructions for AI agents on how to understand, use, and extend the Kinetic DAST framework (v0.2.0).

## 🎯 Framework Overview

**Kinetic** is a high-performance Dynamic Application Security Testing (DAST) engine powered by Playwright. It provides automated security vulnerability detection for web applications, with special capabilities for Single Page Applications (SPAs).

### Key Capabilities
- **Active Scanning**: Crawls pages, discovers attack surfaces (forms, inputs, URLs, APIs), and injects payloads to detect vulnerabilities
- **Passive Scanning**: Analyzes network traffic without modification for headers, cookies, PII, and configuration issues
- **Element Scanning**: Targets specific DOM elements via Playwright locators (bypasses crawling)
- **Verification Engine**: Statistical analysis to reduce false positives (time-based, response diffing)
- **Safe Mode**: Production guardrails that filter destructive payloads automatically

### Package Information
```
Name: @tzigger/kinetic
Version: 0.2.0
Node.js: >=18.0.0
Main entry: dist/index.js
CLI: kinetic
```

---

## 📁 Project Structure

```
playwright_security/
├── src/
│   ├── cli/              # Command-line interface
│   ├── config/           # Configuration management
│   ├── core/             # ScanEngine, BrowserManager, SessionManager
│   ├── detectors/        # Active & Passive vulnerability detectors
│   │   ├── active/       # SQLi, XSS, Command Injection, etc.
│   │   └── passive/      # Headers, Cookies, Sensitive Data
│   ├── reporters/        # Output formatters (JSON, HTML, SARIF)
│   ├── scanners/         # ActiveScanner, PassiveScanner, ElementScanner
│   ├── testing/          # Playwright test helpers
│   ├── types/            # TypeScript interfaces and enums
│   └── utils/            # PayloadFilter, RateLimiter, parallel execution
├── docs/                 # Comprehensive documentation
├── tests/                # Unit, integration, and E2E tests
├── examples/             # Usage examples
├── config/               # Default configurations
└── scripts/              # Utility scripts for testing vulnerable apps
```

---

## 🚀 Quick Start Patterns

### Pattern 1: Playwright Test Integration (Most Common)

```typescript
import { test, expect } from '@playwright/test';
import { runActiveSecurityScan, assertNoVulnerabilities } from '@tzigger/kinetic/testing';

test('security scan', async ({ page }) => {
  await page.goto('https://example.com');
  
  const vulnerabilities = await runActiveSecurityScan(page, {
    detectors: 'sql',           // 'all' | 'sql' | 'xss' | 'errors'
    aggressiveness: 'medium',   // 'low' | 'medium' | 'high'
    maxPages: 3
  });
  
  assertNoVulnerabilities(vulnerabilities);
});
```

### Pattern 2: Programmatic Scanning

```typescript
import { ScanEngine, ActiveScanner } from '@tzigger/kinetic';

const engine = new ScanEngine();
engine.registerScanner(new ActiveScanner());

await engine.loadConfiguration({ 
  target: { url: 'http://localhost:3000' } 
});

const result = await engine.scan();
console.log(result.summary);
await engine.cleanup();
```

### Pattern 3: Targeted Element Scanning

```typescript
import { ElementScanner } from '@tzigger/kinetic/scanners/active/ElementScanner';
import { SqlInjectionDetector } from '@tzigger/kinetic/detectors/active/SqlInjectionDetector';
import { AttackSurfaceType, InjectionContext } from '@tzigger/kinetic/types';

const scanner = new ElementScanner({
  baseUrl: 'http://localhost:3000',
  elements: [{
    name: 'Login Username',
    locator: '#username',
    type: AttackSurfaceType.FORM_INPUT,
    context: InjectionContext.SQL,
    testCategories: ['sqli']
  }]
});

scanner.registerDetector(new SqlInjectionDetector());
await scanner.initialize({ page, ...context });
const result = await scanner.execute();
```

### Pattern 4: CLI Usage

```bash
# Basic scan
kinetic https://example.com

# Passive scan (headers, cookies, PII)
kinetic https://example.com --scan-type passive

# With authentication
kinetic https://example.com --auth "admin:password"

# Rate-limited
kinetic https://example.com --rate-limit 5

# With config file
kinetic -c kinetic.config.json
```

---

## ⚙️ Configuration Reference

### Full Configuration Object

```json
{
  "target": {
    "url": "https://example.com",
    "timeout": 30000,
    "authentication": {
      "type": "form",
      "loginPage": { "url": "/login" },
      "credentials": { "username": "admin", "password": "${env.PASS}" }
    }
  },
  "scanners": {
    "active": {
      "enabled": true,
      "safeMode": true,
      "parallelism": 2
    },
    "passive": { "enabled": true }
  },
  "detectors": {
    "enabled": ["*"],
    "disabled": ["sqlmap"],
    "tuning": {
      "sqli": {
        "booleanBased": { "minRowCountDiff": 1, "baselineSamples": 5 }
      }
    }
  },
  "reporting": {
    "formats": ["json", "html", "sarif"],
    "outputDir": "./reports"
  }
}
```

### Detector IDs Reference

| ID | Type | Description |
|----|------|-------------|
| `sql-injection` | Active | Error/Boolean/Time-based SQLi |
| `sqlmap` | Active | External sqlmap integration |
| `xss` | Active | Reflected, Stored, DOM-based XSS |
| `command-injection` | Active | OS Command Injection, SSTI, XXE |
| `path-traversal` | Active | LFI and Path Traversal |
| `ssrf` | Active | Server-Side Request Forgery |
| `error-based` | Active | Stack trace and error disclosure |
| `sensitive-data` | Passive | PII (SSN, emails, keys) |
| `header-security` | Passive | HSTS, CSP, X-Frame-Options |
| `cookie-security` | Passive | Secure, HttpOnly, SameSite |
| `insecure-transmission` | Passive | HTTP usage, Mixed Content |

---

## 🔌 Extension Points

### Creating a Custom Detector

```typescript
import { 
  IActiveDetector, 
  ActiveDetectorContext, 
  Vulnerability,
  VulnerabilitySeverity,
  VulnerabilityCategory 
} from '@tzigger/kinetic';
import { PayloadInjector } from '@tzigger/kinetic/scanners/active/PayloadInjector';

export class CustomDetector implements IActiveDetector {
  readonly id = 'custom-check';
  readonly name = 'Custom Logic Detector';
  readonly description = 'Checks for custom vulnerabilities';
  readonly version = '1.0.0';
  
  private injector = new PayloadInjector();

  async detect(context: ActiveDetectorContext): Promise<Vulnerability[]> {
    const { page, attackSurfaces, baseUrl } = context;
    const vulnerabilities: Vulnerability[] = [];

    for (const surface of attackSurfaces) {
      const result = await this.injector.inject(page, surface, 'test-payload');
      
      if (result.response?.body?.includes('vulnerable-indicator')) {
        vulnerabilities.push({
          id: `custom-${Date.now()}`,
          category: VulnerabilityCategory.INSECURE_DESIGN,
          severity: VulnerabilitySeverity.HIGH,
          title: 'Custom Vulnerability Found',
          description: 'Description of the issue',
          remediation: 'How to fix',
          evidence: { request: { body: result.payload } },
          confidence: 0.9,
          url: page.url(),
          timestamp: new Date(),
          references: []
        });
      }
    }

    return vulnerabilities;
  }
}
```

### Registering Custom Detector

```typescript
import { DetectorRegistry } from '@tzigger/kinetic';

DetectorRegistry.getInstance().registerActiveDetector(new CustomDetector(), {
  id: 'custom-check',
  name: 'Custom Logic Detector',
  category: 'custom',
  description: 'Checks for custom vulnerabilities',
  type: 'active',
  enabledByDefault: true
});
```

---

## 🛡️ Safe Mode Behavior

Safe Mode is **automatically enabled** for non-local targets and filters destructive payloads.

### Auto-Detection Rules
- **Local targets** (`localhost`, `127.0.0.1`, private IPs): Safe Mode OFF by default
- **Remote/Production targets**: Safe Mode auto-enabled

### Blocked Payloads
- Data modification: `DROP`, `DELETE`, `UPDATE`, `TRUNCATE`
- System commands: `rm`, `shutdown`, `xp_cmdshell`
- Privilege changes: `GRANT`, `REVOKE`

### Allowed Payloads
- Discovery: `' OR 1=1`, `SLEEP(5)`, `<script>alert(1)</script>`

### Disabling Safe Mode (Dangerous)
```bash
kinetic https://staging.example.com --safemode-disable
```

---

## 🏗️ Architecture Overview

```
┌─────────────────────────────────────────────────┐
│              CLI / Testing Helper                │
└─────────────────────────────────────────────────┘
                        │
┌─────────────────────────────────────────────────┐
│           Core Engine Layer                      │
│  ScanEngine │ BrowserManager │ ConfigManager    │
└─────────────────────────────────────────────────┘
                        │
        ┌───────────────┼───────────────┐
        ▼               ▼               ▼
┌──────────────┐ ┌──────────────┐ ┌──────────────┐
│ Active       │ │ Element      │ │ Passive      │
│ Scanner      │ │ Scanner      │ │ Scanner      │
└───────┬──────┘ └──────┬───────┘ └──────┬───────┘
        │               │                │
        ▼               ▼                ▼
┌──────────────────────────────────────────────────┐
│            Detector Layer (Strategy)             │
└──────────────────────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────┐
│           Verification Engine                    │
│   (Time-based Checks, Response Diffing)          │
└─────────────────────────────────────────────────┘
```

### Core Components

| Component | Purpose |
|-----------|---------|
| `ScanEngine` | Main orchestrator, manages lifecycle |
| `BrowserManager` | Playwright browser contexts |
| `ConfigurationManager` | Validates and merges configs |
| `SessionManager` | Authentication state |
| `ActiveScanner` | Crawler with payload injection |
| `ElementScanner` | Targeted DOM element scanning |
| `PassiveScanner` | Network traffic analysis |
| `DomExplorer` | DOM analysis for attack surfaces |
| `PayloadInjector` | Context-aware injection with Safe Mode |
| `VerificationEngine` | Statistical false positive reduction |

---

## 🧪 Testing Commands

```bash
# Run all tests
npm test

# Unit tests
npm run test:unit

# Integration tests
npm run test:integration

# E2E tests against vulnerable apps
npm run test:juice-shop    # OWASP Juice Shop
npm run test:dvwa          # Damn Vulnerable Web App
npm run test:bwapp         # bWAPP

# Start vulnerable apps (Docker)
./scripts/start-vuln-apps.sh

# Run specific vulnerability tests
./scripts/test-vuln-apps.sh juice
./scripts/test-vuln-apps.sh dvwa
./scripts/test-vuln-apps.sh bwapp
```

---

## 📊 Key Types and Enums

### Import Paths

```typescript
// Core classes
import { ScanEngine, ActiveScanner, PassiveScanner } from '@tzigger/kinetic';

// Testing helpers
import { runActiveSecurityScan, runPassiveSecurityScan, assertNoVulnerabilities } from '@tzigger/kinetic/testing';

// Element Scanner
import { ElementScanner } from '@tzigger/kinetic/scanners/active/ElementScanner';

// Detectors
import { SqlInjectionDetector } from '@tzigger/kinetic/detectors/active/SqlInjectionDetector';

// Types
import { 
  VulnerabilitySeverity,      // CRITICAL, HIGH, MEDIUM, LOW, INFO
  VulnerabilityCategory,      // INJECTION, XSS, DATA_EXPOSURE, etc.
  AttackSurfaceType,          // FORM_INPUT, URL_PARAMETER, JSON_BODY, API_PARAM
  InjectionContext            // SQL, HTML, JAVASCRIPT, COMMAND
} from '@tzigger/kinetic/types';

// Utilities
import { getGlobalRateLimiter } from '@tzigger/kinetic';
import { PayloadFilter } from '@tzigger/kinetic/utils';
```

### VulnerabilitySeverity
- `CRITICAL` - Immediate exploitation risk
- `HIGH` - Significant security impact
- `MEDIUM` - Moderate security concern
- `LOW` - Minor security issue
- `INFO` - Informational finding

### AttackSurfaceType
- `FORM_INPUT` - HTML form inputs
- `URL_PARAMETER` - Query string parameters
- `JSON_BODY` - JSON request body keys
- `API_PARAM` - API query parameters
- `COOKIE` - Cookie values
- `HEADER` - HTTP headers

---

## ⚠️ SPA Testing Considerations

### Known Limitations
1. **Deep Logic Discovery**: Crawler may miss inputs in complex state flows
2. **SQL Injection in APIs**: UI sanitization may prevent raw payload testing
3. **Test Timeouts**: Heavy SPAs require longer timeouts

### Recommended Strategies

```typescript
// Strategy 1: Use ElementScanner for specific components
const scanner = new ElementScanner({
  baseUrl: 'http://localhost:3000',
  elements: [{ locator: '#email', type: AttackSurfaceType.FORM_INPUT }]
});

// Strategy 2: Hybrid testing (UI + API)
test('hybrid security check', async ({ page, request }) => {
  // Test UI for XSS
  const uiVulns = await runActiveSecurityScan(page, { detectors: 'xss' });
  
  // Test API directly for SQLi
  const apiResponse = await request.get('/api/search?q=' + encodeURIComponent("' OR 1=1--"));
});

// Strategy 3: Manual state setup before scanning
test('scan after setup', async ({ page }) => {
  await page.goto('/shop');
  await page.click('.add-to-cart');
  await page.click('.checkout');
  
  // Scan only after reaching target state
  await runActiveSecurityScan(page, { maxPages: 1 });
});
```

---

## 🔧 Utilities Reference

### Rate Limiter

```typescript
import { getGlobalRateLimiter } from '@tzigger/kinetic';

const limiter = getGlobalRateLimiter();
limiter.setRateLimit(10);           // 10 requests per second
await limiter.waitForToken();       // Wait for available token
limiter.handleResponse(statusCode); // Handle 429 backoff
```

### Parallel Execution

```typescript
import { executeParallel, executeWithRetry } from '@tzigger/kinetic/utils/parallel';

// Controlled concurrency
const results = await executeParallel(tasks, { 
  concurrency: 3,
  taskTimeout: 30000,
  continueOnError: true 
});

// Automatic retry with backoff
const result = await executeWithRetry(task, {
  maxRetries: 3,
  retryDelay: 1000,
  backoffMultiplier: 2
});
```

### Request Deduplication

```typescript
import { RequestDeduplicator } from '@tzigger/kinetic/utils/dedup';

const dedup = new RequestDeduplicator({ ttlMs: 60000 });
const signature = dedup.createSignature(surface, payload);
const cached = dedup.get(signature);

if (!cached) {
  const result = await injector.inject(page, surface, payload);
  dedup.set(signature, result);
}
```

---

## 📚 Documentation References

| Document | Purpose |
|----------|---------|
| [README.md](./README.md) | Project overview and quick start |
| [docs/DEVELOPER-GUIDE.md](./docs/DEVELOPER-GUIDE.md) | Complete usage guide |
| [docs/TESTING-GUIDE.md](./docs/TESTING-GUIDE.md) | Playwright test integration |
| [docs/API-QUICK-REFERENCE.md](./docs/API-QUICK-REFERENCE.md) | API cheat sheet |
| [docs/EXAMPLES.md](./docs/EXAMPLES.md) | Real-world examples |
| [docs/ELEMENT-SCANNER.md](./docs/ELEMENT-SCANNER.md) | Targeted element scanning |
| [docs/SAFE-MODE.md](./docs/SAFE-MODE.md) | Production guardrails |
| [docs/architecture.md](./docs/architecture.md) | System design |
| [docs/plugin-development.md](./docs/plugin-development.md) | Creating custom plugins |
| [docs/DETECTOR-CONFIG-GUIDE.md](./docs/DETECTOR-CONFIG-GUIDE.md) | Detector configuration |
| [docs/SPA-TESTING-LIMITATIONS.md](./docs/SPA-TESTING-LIMITATIONS.md) | SPA testing strategies |
| [docs/MIGRATION-GUIDE.md](./docs/MIGRATION-GUIDE.md) | Version migration |

---

## 🤖 Agent Best Practices

### When Writing Security Tests
1. Use `runActiveSecurityScan()` for comprehensive page scanning
2. Use `runPassiveSecurityScan()` for fast header/cookie checks
3. Use `ElementScanner` for targeting specific components
4. Set appropriate timeouts for active scans (`test.setTimeout(300_000)`)
5. Use `assertNoVulnerabilities()` with severity threshold

### When Extending the Framework
1. Implement `IActiveDetector` or `IPassiveDetector` interfaces
2. Use `PayloadInjector` for injections (handles Safe Mode automatically)
3. Set appropriate `confidence` scores (1.0 = proven, 0.8 = strong indicators)
4. Register detectors via `DetectorRegistry.getInstance()`

### When Debugging Issues
1. Run with `DEBUG=kinetic:*` for verbose logging
2. Check `evidence` property in vulnerability reports
3. Review `VerificationEngine` logs for false positive filtering
4. Increase timeouts for SPA applications

### Common Pitfalls to Avoid
1. Don't use fixed waits (`page.waitForTimeout()`) - use Playwright's auto-waiting
2. Don't hardcode URLs or credentials in tests
3. Don't skip Safe Mode checks when scanning production
4. Don't assume `attackSurfaces` contains all page inputs in ElementScanner mode
