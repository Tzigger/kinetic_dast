# Kinetic Practical Examples

> Real-world examples for using Kinetic Security Scanner (v0.2.0+)

## Table of Contents

- [Quick Start Helpers](#quick-start-helpers)
- [Playwright Test Integration](#playwright-test-integration)
- [Element Scanner (New)](#element-scanner-targeted-testing)
- [CI/CD Integration](#cicd-integration)
- [Custom Detectors](#custom-detectors)
- [Authentication Scenarios](#authentication-scenarios)
- [Advanced Configurations](#advanced-configurations)

---

## Quick Start Helpers

Kinetic provides specific helpers for Active (injection) and Passive (traffic) scanning.

### Example 1: Passive Security Headers Check

**Use case:** Fast check for CSP, HSTS, and PII leaks. Safe for production.

```typescript
import { test, expect } from '@playwright/test';
import { runPassiveSecurityScan, VulnerabilitySeverity } from '@tzigger/kinetic/testing';

test('should have proper security headers', async () => {
  const vulnerabilities = await runPassiveSecurityScan('https://myapp.com', {
    detectors: 'headers', // Only check headers
    headless: true
  });
  
  // Check for missing HSTS header specifically
  const hstsIssues = vulnerabilities.filter(v => 
    v.title.includes('Strict-Transport-Security')
  );
  expect(hstsIssues).toHaveLength(0);
});
```

### Example 2: Active SQL Injection Test

**Use case:** Verify a login form is secure against SQLi.

```typescript
import { test } from '@playwright/test';
import { runActiveSecurityScan, assertNoVulnerabilities } from '@tzigger/kinetic/testing';

test('login form should not have SQL injection', async ({ page }) => {
  // 1. Go to page
  await page.goto('https://myapp.com/login');

  // 2. Run Active Scan on current page state
  const vulnerabilities = await runActiveSecurityScan(page, {
    detectors: 'sql',           // Focus on SQLi
    aggressiveness: 'medium',   // Standard payload set
    maxPages: 1                 // Do not crawl away from login
  });
  
  // 3. Fail test if any vulnerabilities found
  assertNoVulnerabilities(vulnerabilities);
});
```

### Example 3: SPA Security Testing

**Use case:** Testing Angular/React apps where elements load asynchronously.

```typescript
import { test, expect } from '@playwright/test';
import { runActiveSecurityScan } from '@tzigger/kinetic/testing';

test('SPA dashboard security', async ({ page }) => {
  // 1. Navigate and wait for SPA hydration
  await page.goto('https://myapp.com/#/dashboard');
  await page.waitForLoadState('networkidle');
  
  // 2. Pass the hydrated page to Kinetic
  // The engine automatically detects Angular/React/Vue and waits for stability
  const vulnerabilities = await runActiveSecurityScan(page, {
    detectors: 'xss',
    maxPages: 3 // Allow crawling hash routes (e.g. #/settings)
  });
  
  expect(vulnerabilities).toHaveLength(0);
});
```

---

## Playwright Test Integration

### Example 4: Full E2E Security Suite

```typescript
// tests/security.spec.ts
import { test } from '@playwright/test';
import { 
  runActiveSecurityScan,
  runPassiveSecurityScan,
  assertNoVulnerabilities, 
  VulnerabilitySeverity 
} from '@tzigger/kinetic/testing';

test.describe('Security Regression Suite', () => {
  
  test('public pages should be secure (Passive)', async () => {
    const vulns = await runPassiveSecurityScan('https://myapp.com', {
      detectors: 'all'
    });
    // Strict check: No issues allowed above LOW severity
    assertNoVulnerabilities(vulns, VulnerabilitySeverity.LOW);
  });
  
  test('search bar XSS check (Active)', async ({ page }) => {
    await page.goto('https://myapp.com/search');
    
    const vulns = await runActiveSecurityScan(page, {
      detectors: 'xss',
      maxDepth: 1
    });
    
    assertNoVulnerabilities(vulns);
  });
  
  test('API endpoints should validate input', async ({ request }) => {
    // Note: You can also point Kinetic at API endpoints
    const vulns = await runActiveSecurityScan('https://api.myapp.com/v1/users', {
      detectors: 'sql',
      aggressiveness: 'medium'
    });
    assertNoVulnerabilities(vulns);
  });
});
```

---

## Element Scanner (Targeted Testing)

**New in v0.2.0**: The `ElementScanner` allows you to target specific Playwright locators instead of crawling the whole page.

### Example 5: Testing a Specific Component

```typescript
import { test, expect } from '@playwright/test';
import { ElementScanner } from '@tzigger/kinetic/scanners/active/ElementScanner';
import { SqlInjectionDetector } from '@tzigger/kinetic/detectors/active/SqlInjectionDetector';
import { AttackSurfaceType, InjectionContext } from '@tzigger/kinetic/scanners/active/DomExplorer';

test('complex search component SQLi check', async ({ page }) => {
  await page.goto('https://myapp.com/advanced-search');

  // Configure specific element
  const scanner = new ElementScanner({
    baseUrl: 'https://myapp.com',
    elements: [
      {
        name: 'Advanced Filter Input',
        locator: '[data-testid="filter-input"]', // Precise targeting
        type: AttackSurfaceType.FORM_INPUT,
        context: InjectionContext.SQL,
        testCategories: ['sqli']
      }
    ]
  });

  // Register detector & run
  scanner.registerDetector(new SqlInjectionDetector());
  await scanner.initialize({ page, ...mockContext }); // *Requires ScanContext setup
  const result = await scanner.execute();

  expect(result.vulnerabilities).toHaveLength(0);
});
```

---

## CI/CD Integration

### Example 6: GitHub Actions Workflow

```yaml
# .github/workflows/security-scan.yml
name: Nightly Security Scan

on:
  schedule:
    - cron: '0 2 * * *' # Daily at 2 AM

jobs:
  kinetic-scan:
    runs-on: ubuntu-latest
    
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-node@v3
        with: { node-version: '18' }
      
      - name: Install Kinetic
        run: npm install -g @tzigger/kinetic
        
      - name: Run Active Scan
        run: |
          kinetic https://staging.myapp.com \
            --scan-type active \
            --formats sarif,json \
            --output ./security-reports
      
      - name: Upload SARIF to GitHub Security
        uses: github/codeql-action/upload-sarif@v2
        if: always()
        with:
          sarif_file: security-reports/scan-results.sarif
          category: kinetic-dast
```

---

## Custom Detectors

### Example 7: Custom Logic Detector

```typescript
// detectors/BusinessLogicDetector.ts
import { 
  IActiveDetector, 
  ActiveDetectorContext, 
  Vulnerability,
  VulnerabilitySeverity,
  VulnerabilityCategory 
} from '@tzigger/kinetic';

export class PriceManipulationDetector implements IActiveDetector {
  readonly id = 'price-manipulation';
  readonly name = 'Price Manipulation Check';
  // ... metadata

  async detect(context: ActiveDetectorContext): Promise<Vulnerability[]> {
    const { page, attackSurfaces } = context;
    const vulns: Vulnerability[] = [];

    // Find "price" inputs
    const priceInputs = attackSurfaces.filter(s => s.name.includes('price'));

    for (const surface of priceInputs) {
      // Try negative price injection
      await surface.element.fill('-100');
      await page.keyboard.press('Enter');
      
      // Check for success message (bad!)
      if (await page.getByText('Order Successful').isVisible()) {
        vulns.push({
          id: `price-${Date.now()}`,
          title: 'Negative Price Manipulation',
          severity: VulnerabilitySeverity.CRITICAL,
          category: VulnerabilityCategory.INSECURE_DESIGN,
          description: 'Application accepted a negative price.',
          remediation: 'Validate input range on server side.',
          evidence: { /* ... */ }
        });
      }
    }
    return vulns;
  }
}
```

**Registration:**

```typescript
import { DetectorRegistry } from '@tzigger/kinetic';
// Register before scan starts
DetectorRegistry.getInstance().registerActiveDetector(new PriceManipulationDetector(), metadata);
```

---

## Authentication Scenarios

### Example 8: Auto-Login via Config

Kinetic's `SessionManager` can handle standard login forms automatically.

```json
// kinetic.config.json
{
  "target": {
    "url": "https://myapp.com/dashboard",
    "authentication": {
      "type": "form",
      "loginPage": { 
        "url": "https://myapp.com/login" 
      },
      "credentials": {
        "username": "admin@example.com",
        "password": "${env.TEST_PASSWORD}"
      }
    }
  }
}
```

Run with: `kinetic -c kinetic.config.json`

### Example 9: Reusing Auth State (Playwright)

For complex auth (MFA/SSO), perform login in your `global-setup` and reuse the state.

```typescript
// tests/security.spec.ts
test.use({ storageState: 'auth.json' }); // Load cookies/storage

test('authenticated scan', async ({ page }) => {
  await page.goto('https://myapp.com/dashboard');
  // Kinetic uses the page's existing auth state
  await runActiveSecurityScan(page); 
});
```

---

## Advanced Configurations

### Example 10: Production Safe Mode

Explicitly scanning production with safety guardrails.

```typescript
const config = {
  target: { url: 'https://production.myapp.com' },
  scanners: {
    active: {
      enabled: true,
      safeMode: true, // Filters destructive payloads (DROP/DELETE)
      aggressiveness: 'low'
    }
  },
  advanced: {
    parallelism: 1 // Reduce load
  },
  detectors: {
    // Disable noisy/risky detectors
    disabled: ['command-injection', 'sqlmap']
  }
};
```

### Example 11: Verification Tuning

Adjusting the Verification Engine to reduce false positives in a noisy environment.

```typescript
const config = {
  detectors: {
    tuning: {
      sqli: {
        booleanBased: {
          // Require at least 5 chars difference in response length
          minRowCountDiff: 5,
          // Take 5 samples to establish a stable baseline
          baselineSamples: 5
        }
      }
    }
  }
};
```
