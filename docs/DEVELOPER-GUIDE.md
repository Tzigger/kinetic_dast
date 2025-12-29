# Kinetic Developer Guide

> The complete reference for integrating Kinetic Security Scanner into your development workflow.

## Table of Contents

1.  [Installation](#installation)
2.  [Quick Start](#quick-start)
3.  [Core Architecture](#core-architecture)
4.  [Scanning Strategies](#scanning-strategies)
    *   [Active Scanner](#active-scanner-crawler)
    *   [Element Scanner](#element-scanner-targeted)
    *   [Passive Scanner](#passive-scanner-traffic)
5.  [Verification Engine](#verification-engine)
6.  [Configuration](#configuration)
7.  [Authentication & Sessions](#authentication--sessions)
8.  [Custom Plugins](#custom-plugins)

---

## Installation

### From NPM

```bash
npm install @tzigger/kinetic --save-dev
```

### Peer Dependencies

Kinetic requires Playwright. If you haven't installed it yet:

```bash
npm install playwright @playwright/test --save-dev
npx playwright install
```

---

## Quick Start

### 1. Minimal Programmatic Scan

```typescript
import { ScanEngine, ActiveScanner } from '@tzigger/kinetic';

const engine = new ScanEngine();
engine.registerScanner(new ActiveScanner());

// Load config and run
await engine.loadConfiguration({ 
  target: { url: 'http://localhost:3000' } 
});

const result = await engine.scan();
console.log(result.summary);
await engine.cleanup();
```

### 2. Playwright Test Integration

Kinetic is designed to run *inside* your existing E2E tests.

```typescript
import { test, expect } from '@playwright/test';
import { runActiveSecurityScan, assertNoVulnerabilities } from '@tzigger/kinetic/testing';

test('login security check', async ({ page }) => {
  await page.goto('https://myapp.com/login');
  
  const vulns = await runActiveSecurityScan(page, {
    detectors: 'sql',           // Limit to SQL Injection
    aggressiveness: 'medium'
  });
  
  assertNoVulnerabilities(vulns);
});
```

---

## Core Architecture

Kinetic follows a modular pipeline architecture:

1.  **ScanEngine**: The orchestrator. Manages the browser lifecycle, loads configuration, and aggregates results.
2.  **Scanners**: Strategies for interacting with the target.
    *   *Active*: Crawls and injects payloads into discovered forms/URLs.
    *   *Passive*: Listens to network traffic for PII, headers, and config issues.
    *   *Element*: Targets specific DOM nodes (good for component testing).
3.  **Detectors**: Specific logic for vulnerability classes (e.g., `SqlInjectionDetector`, `XssDetector`).
4.  **Verification Engine**: A post-processing layer that confirms findings using statistical analysis to reduce False Positives.

---

## Scanning Strategies

### Active Scanner (Crawler)

The default scanner. It crawls the application, discovers inputs (forms, URL parameters, API endpoints via JS analysis), and injects payloads.

**Best for:** Full application audits.

```typescript
import { ActiveScanner } from '@tzigger/kinetic';

const scanner = new ActiveScanner({
  maxDepth: 3,
  maxPages: 20,
  safeMode: true // Filters destructive payloads (DROP/DELETE)
});
```

### Element Scanner (Targeted)

**New in v0.2.0**. Skips the crawling phase and targets specific elements defined by locators.

**Best for:** Unit testing specific components or reproducing a specific bug.

```typescript
import { ElementScanner } from '@tzigger/kinetic/scanners/active/ElementScanner';
import { AttackSurfaceType } from '@tzigger/kinetic/types';

const scanner = new ElementScanner({
  baseUrl: 'http://localhost:3000',
  elements: [
    {
      name: 'Search Bar',
      locator: 'input[name="q"]',
      type: AttackSurfaceType.FORM_INPUT,
      testCategories: ['xss', 'sql']
    }
  ]
});
```

### Passive Scanner (Traffic)

Analyzes HTTP/S traffic without modifying requests. It uses the `NetworkInterceptor` to inspect headers, cookies, and response bodies.

**Best for:** Production monitoring, zero-impact assessments.

```typescript
import { PassiveScanner } from '@tzigger/kinetic';

const scanner = new PassiveScanner();
// Detects: PII leaks, Missing Headers, Insecure Cookies
```

---

## Verification Engine

**New in v0.2.0**. Kinetic automatically verifies potential vulnerabilities before reporting them. This significantly reduces noise.

### Verification Techniques

1.  **Time-Based**: Uses statistical analysis (Z-score, Welch's t-test) to confirm if a delay payload (e.g., `SLEEP(5)`) actually caused a delay compared to the baseline latency.
2.  **Response Diffing**: Compares the response structure (JSON keys, DOM tree) of "True" vs "False" payloads (e.g., `OR 1=1` vs `OR 1=2`).
3.  **Replay**: Re-executes the payload to ensure the finding is reproducible.

### Configuration

You can tune verification sensitivity in your config:

```json
{
  "detectors": {
    "tuning": {
      "sqli": {
        "booleanBased": {
          "minRowCountDiff": 1,
          "baselineSamples": 5
        }
      }
    }
  }
}
```

---

## Configuration

The configuration object tells Kinetic what to scan and how.

### Full Example (`kinetic.config.json`)

```json
{
  "target": {
    "url": "https://staging.myapp.com",
    "timeout": 30000,
    "authentication": {
      "type": "form",
      "loginPage": { "url": "https://staging.myapp.com/login" },
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
      "sensitiveData": {
        "emailAllowlist": ["support@myapp.com"]
      }
    }
  },
  "reporting": {
    "formats": ["json", "html"],
    "outputDir": "./reports"
  }
}
```

---

## Authentication & Sessions

Kinetic includes a **SessionManager** that handles authentication state (Cookies, LocalStorage) across scanner threads.

### Auto-Login

For standard login forms, Kinetic can automatically authenticate using heuristics:

```typescript
const config = {
  target: {
    authentication: {
      type: 'form',
      loginPage: { url: '/login' },
      credentials: { 
        username: 'admin', 
        password: 'password123' 
      }
    }
  }
};
```

**How it works:**
1.  Navigates to `loginPage.url`.
2.  Identifies User/Pass fields (via common selectors like `input[type="password"]`).
3.  Fills credentials and submits.
4.  Waits for navigation (Network Idle).
5.  Captures storage state and applies it to all new browser contexts.

### Custom Auth (Playwright)

For complex auth (MFA, OAuth), perform login in your Playwright test setup and pass the authenticated `Page` to Kinetic.

```typescript
test('authenticated scan', async ({ page }) => {
  // 1. Perform complex login
  await performCustomLogin(page);
  
  // 2. Pass authenticated page to scanner
  await runActiveSecurityScan(page); 
});
```

---

## Custom Plugins

### Creating a Detector

Implement `IActiveDetector` or `IPassiveDetector` and register it.

```typescript
import { IActiveDetector, ActiveDetectorContext, Vulnerability } from '@tzigger/kinetic';

export class BusinessLogicDetector implements IActiveDetector {
  readonly name = 'Business Logic Check';
  readonly id = 'biz-logic-01';
  // ... metadata

  async detect(context: ActiveDetectorContext): Promise<Vulnerability[]> {
    const { page, attackSurfaces } = context;
    // Your custom logic here
    return [];
  }
}
```

### Registration

```typescript
import { DetectorRegistry } from '@tzigger/kinetic';

DetectorRegistry.getInstance().registerActiveDetector(
  new BusinessLogicDetector(), 
  {
    id: 'biz-logic-01',
    name: 'Business Logic Check',
    category: 'custom',
    description: 'Checks specific business rules',
    enabledByDefault: true,
    type: 'active'
  }
);
```

Once registered, you can reference it in your config `detectors.enabled` array.

---

## Troubleshooting

*   **Scan takes too long?**
    *   Decrease `maxPages` and `maxDepth`.
    *   Disable time-intensive detectors: `disabled: ["sql-injection", "command-injection"]`.
    *   Increase parallelism: `parallelism: 4`.
*   **False Positives?**
    *   Check `VerificationEngine` logs.
    *   Tune detector sensitivity in config.
*   **SPA not loading?**
    *   Kinetic automatically detects Angular/React/Vue. If it fails, increase `browser.timeout` or use `runActiveSecurityScan(page)` with a manually waited page.
