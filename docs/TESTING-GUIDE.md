# Testing Guide

## Overview

This guide explains how to write security tests using the Playwright Security framework. We provide simple helper functions and interfaces that make security testing as easy as writing regular Playwright tests.

## Table of Contents

1. [Quick Start](#quick-start)
2. [Helper Functions](#helper-functions)
3. [Test Configuration](#test-configuration)
4. [Attack Surface Types](#attack-surface-types)
5. [Advanced Patterns](#advanced-patterns)
6. [Best Practices](#best-practices)

## Quick Start

### Basic Security Test

```typescript
import { test, expect } from '@playwright/test';
import { runActiveSecurityScan } from '@tzigger/playwright-security';

test('basic security scan', async ({ page }) => {
  await page.goto('https://example.com');
  
  const vulnerabilities = await runActiveSecurityScan(page);
  
  console.log(`Found ${vulnerabilities.length} vulnerabilities`);
  expect(vulnerabilities).toHaveLength(0); // Expect no vulnerabilities
});
```

That's it! The framework will:
- ✅ Automatically discover forms, inputs, and APIs
- ✅ Test for SQL injection, XSS, and error disclosure
- ✅ Analyze responses for vulnerability indicators
- ✅ Return a list of vulnerabilities with evidence

## Helper Functions

### `runActiveSecurityScan()`

**Purpose**: Perform active vulnerability scanning on a page

**Signature**:
```typescript
async function runActiveSecurityScan(
  target: string | Page,
  options?: ActiveScanOptions
): Promise<Vulnerability[]>
```

**Parameters**:
- `target`: URL string or existing Playwright `Page` object
- `options`: Optional configuration (see [Configuration Options](#configuration-options))

**Returns**: Array of `Vulnerability` objects

**Examples**:

```typescript
// Example 1: Scan with URL
const vulns = await runActiveSecurityScan('https://example.com');

// Example 2: Scan with existing page (SPA mode)
await page.goto('https://example.com/dashboard');
const vulns = await runActiveSecurityScan(page);

// Example 3: Scan with custom options
const vulns = await runActiveSecurityScan(page, {
  aggressiveness: AggressivenessLevel.HIGH,
  maxPages: 10,
  detectors: 'sql', // Only test SQL injection
});
```

**When to Use**:
- Testing web applications for OWASP Top 10 vulnerabilities
- Automated security regression testing
- Pre-deployment security validation
- Bug bounty hunting and pentesting

**How It Works**:
1. **Discovery**: Explores DOM to find attack surfaces (forms, inputs, API endpoints)
2. **Injection**: Sends payloads targeting SQL injection, XSS, etc.
3. **Analysis**: Compares responses to detect vulnerability indicators
4. **Reporting**: Returns detailed vulnerability objects with evidence

---

### `runPassiveSecurityScan()`

**Purpose**: Perform passive security analysis without modifying the page

**Signature**:
```typescript
async function runPassiveSecurityScan(
  target: string | Page,
  options?: PassiveScanOptions
): Promise<Vulnerability[]>
```

**Parameters**:
- `target`: URL string or existing Playwright `Page` object
- `options`: Optional configuration

**Returns**: Array of `Vulnerability` objects

**Examples**:

```typescript
// Example 1: Check security headers
const vulns = await runPassiveSecurityScan('https://example.com');

// Example 2: Analyze existing page
await page.goto('https://example.com');
const vulns = await runPassiveSecurityScan(page);

// Example 3: Custom sensitivity
const vulns = await runPassiveSecurityScan(page, {
  sensitivity: 'high',
  checkHeaders: true,
  checkCookies: true,
});
```

**What It Checks**:
- ❌ Missing security headers (CSP, HSTS, X-Frame-Options)
- ❌ Insecure cookies (missing HttpOnly, Secure, SameSite)
- ❌ Information disclosure (comments, debug code)
- ❌ Outdated libraries (via version detection)
- ❌ Mixed content (HTTPS pages loading HTTP resources)

**When to Use**:
- Quick security assessment without active testing
- CI/CD pipeline integration (safe, no side effects)
- Compliance checking (CSP, cookie policies)
- Pre-scanning before active tests

---

### `combinedSecurityScan()`

**Purpose**: Run both active and passive scans in sequence

**Signature**:
```typescript
async function combinedSecurityScan(
  target: string | Page,
  options?: CombinedScanOptions
): Promise<{
  activeVulnerabilities: Vulnerability[];
  passiveVulnerabilities: Vulnerability[];
  total: number;
}>
```

**Examples**:

```typescript
const results = await combinedSecurityScan('https://example.com');

console.log(`Active vulnerabilities: ${results.activeVulnerabilities.length}`);
console.log(`Passive vulnerabilities: ${results.passiveVulnerabilities.length}`);
console.log(`Total: ${results.total}`);
```

**When to Use**:
- Comprehensive security assessment
- Pre-release security validation
- Scheduled security scans

---

## Configuration Options

### `ActiveScanOptions`

```typescript
interface ActiveScanOptions {
  // Scan aggressiveness level
  aggressiveness?: AggressivenessLevel | 'low' | 'medium' | 'high';
  
  // Maximum number of pages to crawl
  maxPages?: number; // Default: 5
  
  // Maximum crawl depth
  maxDepth?: number; // Default: 2
  
  // Which detectors to run
  detectors?: 'all' | 'sql' | 'xss' | 'errors';
  
  // Whether to submit forms
  submitForms?: boolean; // Default: true
  
  // Run in headless mode
  headless?: boolean; // Default: true
}
```

### Aggressiveness Levels

| Level | Payloads | Speed | Risk | Use Case |
|-------|----------|-------|------|----------|
| **LOW** | ~5 per test | Fast | Minimal | CI/CD, quick checks |
| **MEDIUM** | ~10 per test | Moderate | Low | Regular testing |
| **HIGH** | ~20+ per test | Slow | Medium | Comprehensive scans |

**Example**:

```typescript
// Low aggressiveness - fast, minimal payloads
const vulns = await runActiveSecurityScan(page, {
  aggressiveness: 'low',
  maxPages: 3,
});

// High aggressiveness - thorough, many payloads
const vulns = await runActiveSecurityScan(page, {
  aggressiveness: AggressivenessLevel.HIGH,
  maxPages: 10,
  maxDepth: 3,
});
```

---

## Attack Surface Types

The framework automatically discovers and tests various attack surfaces:

### 1. Form Inputs

```typescript
// Framework automatically finds and tests these:
<input type="text" name="username">
<input type="email" name="email">
<textarea name="comment"></textarea>
<select name="country"></select>
```

**Tested For**: SQL injection, XSS, command injection

---

### 2. URL Parameters

```typescript
// Framework tests query parameters:
https://example.com/search?q=test&page=1
```

**Tested For**: SQL injection, XSS, path traversal

---

### 3. API Endpoints

```typescript
// Framework intercepts and tests API calls:
POST /api/login
GET /api/products?search=query
```

**Tested For**: SQL injection in JSON bodies, XSS in API responses

---

### 4. Cookies

```typescript
// Framework tests cookie manipulation:
Cookie: session=abc123; lang=en
```

**Tested For**: XSS in cookie values, session fixation

---

### 5. JSON Request Bodies

```typescript
// Framework tests API request bodies:
POST /api/users
{
  "username": "test",
  "email": "test@example.com"
}
```

**Tested For**: SQL injection, NoSQL injection, XSS

---

## Advanced Patterns

### Pattern 1: Testing Specific Pages

```typescript
test('login page security', async ({ page }) => {
  await page.goto('https://example.com/login');
  
  const vulnerabilities = await runActiveSecurityScan(page, {
    maxPages: 1, // Don't crawl beyond login page
    detectors: 'sql', // Focus on SQL injection
  });
  
  // Verify no authentication bypass vulnerabilities
  const authBypass = vulnerabilities.filter(v => 
    v.title.includes('Authentication Bypass')
  );
  expect(authBypass).toHaveLength(0);
});
```

---

### Pattern 2: Testing API Endpoints

```typescript
test('API security - direct testing', async ({ page }) => {
  // Navigate to trigger API discovery
  await page.goto('https://example.com/products');
  
  // Framework will intercept API calls
  const vulnerabilities = await runActiveSecurityScan(page, {
    aggressiveness: 'high',
    maxPages: 2,
  });
  
  // Check for API-specific vulnerabilities
  const apiVulns = vulnerabilities.filter(v => 
    v.url?.includes('/api/')
  );
  console.log(`Found ${apiVulns.length} API vulnerabilities`);
});
```

---

### Pattern 3: Testing SPA Applications

```typescript
test('SPA security scan', async ({ page }) => {
  // Navigate to SPA route
  await page.goto('https://example.com/#/dashboard');
  await page.waitForLoadState('networkidle');
  
  // Pass existing page (SPA mode)
  const vulnerabilities = await runActiveSecurityScan(page, {
    aggressiveness: 'medium',
    maxPages: 5, // Will discover hash routes
  });
  
  expect(vulnerabilities).toHaveLength(0);
});
```

**Note**: See [SPA Testing Limitations](./SPA-TESTING-LIMITATIONS.md) for known issues with complex SPAs.

---

### Pattern 4: Testing with Authentication

```typescript
test('authenticated area security', async ({ page }) => {
  // Login first
  await page.goto('https://example.com/login');
  await page.fill('input[name="username"]', 'testuser');
  await page.fill('input[name="password"]', 'password123');
  await page.click('button[type="submit"]');
  await page.waitForURL('**/dashboard');
  
  // Scan authenticated pages
  const vulnerabilities = await runActiveSecurityScan(page, {
    maxPages: 10,
    maxDepth: 2,
  });
  
  // Should not find authentication bypass in authenticated area
  const authVulns = vulnerabilities.filter(v => v.cwe === 'CWE-89');
  expect(authVulns).toHaveLength(0);
});
```

---

### Pattern 5: Testing Specific Vulnerabilities

```typescript
test('SQL injection only', async ({ page }) => {
  await page.goto('https://example.com');
  
  const vulnerabilities = await runActiveSecurityScan(page, {
    detectors: 'sql', // Only test SQL injection
    aggressiveness: 'high',
  });
  
  // Filter by CWE
  const sqliVulns = vulnerabilities.filter(v => v.cwe === 'CWE-89');
  expect(sqliVulns).toHaveLength(0);
});

test('XSS only', async ({ page }) => {
  await page.goto('https://example.com');
  
  const vulnerabilities = await runActiveSecurityScan(page, {
    detectors: 'xss', // Only test XSS
  });
  
  const xssVulns = vulnerabilities.filter(v => v.cwe === 'CWE-79');
  expect(xssVulns).toHaveLength(0);
});
```

---

## Vulnerability Object

Every vulnerability returned has this structure:

```typescript
interface Vulnerability {
  id: string;                    // Unique identifier
  title: string;                 // "SQL Injection (error-based)"
  description: string;           // Detailed description
  severity: VulnerabilitySeverity; // CRITICAL, HIGH, MEDIUM, LOW
  category: VulnerabilityCategory; // INJECTION, XSS, etc.
  cwe: string;                   // "CWE-89"
  owasp: string;                 // "A03:2021"
  url?: string;                  // Where it was found
  evidence?: {                   // Proof of vulnerability
    request: { body: string };
    response: { body: string; status?: number };
    description?: string;
  };
  remediation: string;           // How to fix it
  references: string[];          // Links to documentation
  timestamp: Date;               // When it was found
}
```

**Example**:

```typescript
const vulnerabilities = await runActiveSecurityScan(page);

vulnerabilities.forEach(vuln => {
  console.log(`\n🔴 ${vuln.title} [${vuln.severity}]`);
  console.log(`   CWE: ${vuln.cwe} | OWASP: ${vuln.owasp}`);
  console.log(`   URL: ${vuln.url}`);
  console.log(`   Fix: ${vuln.remediation}`);
  
  if (vuln.evidence) {
    console.log(`   Payload: ${vuln.evidence.request.body}`);
  }
});
```

---

## Best Practices

### ✅ DO

1. **Start with Low Aggressiveness**
   ```typescript
   // Good: Fast feedback in development
   const vulns = await runActiveSecurityScan(page, { aggressiveness: 'low' });
   ```

2. **Use SPA Mode for Single Page Apps**
   ```typescript
   // Good: Navigate first, then scan
   await page.goto('https://app.example.com');
   const vulns = await runActiveSecurityScan(page);
   ```

3. **Test Specific Areas**
   ```typescript
   // Good: Focused testing
   const vulns = await runActiveSecurityScan(page, {
     maxPages: 2,
     detectors: 'sql',
   });
   ```

4. **Check Vulnerability Count**
   ```typescript
   // Good: Fail test if vulnerabilities found
   expect(vulnerabilities.length).toBe(0);
   ```

5. **Log Detailed Results**
   ```typescript
   // Good: Help debugging
   vulnerabilities.forEach(v => {
     console.log(`${v.title}: ${v.url}`);
     console.log(`Evidence: ${v.evidence?.request.body}`);
   });
   ```

---

### ❌ DON'T

1. **Don't Test Production Without Permission**
   ```typescript
   // BAD: Never scan production systems without authorization
   await runActiveSecurityScan('https://production.example.com');
   ```

2. **Don't Use High Aggressiveness in CI/CD**
   ```typescript
   // BAD: Too slow for CI/CD
   const vulns = await runActiveSecurityScan(page, {
     aggressiveness: 'high',
     maxPages: 50,
   });
   ```

3. **Don't Ignore Timeouts**
   ```typescript
   // BAD: Will cause test failures
   test('security scan', async ({ page }) => {
     // Needs longer timeout
     const vulns = await runActiveSecurityScan(page, {
       aggressiveness: 'high',
     });
   });
   
   // GOOD: Set appropriate timeout
   test('security scan', async ({ page }) => {
     test.setTimeout(300000); // 5 minutes
     const vulns = await runActiveSecurityScan(page, {
       aggressiveness: 'high',
     });
   });
   ```

4. **Don't Test Without Expecting Results**
   ```typescript
   // BAD: No assertion
   await runActiveSecurityScan(page);
   
   // GOOD: Check results
   const vulns = await runActiveSecurityScan(page);
   expect(vulns.length).toBe(0);
   ```

---

## Integration Examples

### CI/CD Pipeline (GitHub Actions)

```yaml
name: Security Tests

on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-node@v3
      - run: npm install
      - run: npx playwright install
      - run: npx playwright test tests/security.spec.ts
        timeout-minutes: 10
```

### Jest Integration

```typescript
import { chromium } from 'playwright';
import { runActiveSecurityScan } from '@tzigger/playwright-security';

describe('Security Tests', () => {
  let browser;
  let page;

  beforeAll(async () => {
    browser = await chromium.launch();
  });

  beforeEach(async () => {
    page = await browser.newPage();
  });

  afterEach(async () => {
    await page.close();
  });

  afterAll(async () => {
    await browser.close();
  });

  test('should have no SQL injection', async () => {
    await page.goto('http://localhost:3000');
    const vulns = await runActiveSecurityScan(page, {
      detectors: 'sql',
    });
    expect(vulns).toHaveLength(0);
  });
});
```

---

## Troubleshooting

### Issue: Tests Timeout

**Solution**: Increase timeout or reduce scope
```typescript
test.setTimeout(600000); // 10 minutes

const vulns = await runActiveSecurityScan(page, {
  maxPages: 3, // Reduce crawl scope
  aggressiveness: 'low', // Use fewer payloads
});
```

### Issue: No Vulnerabilities Found (False Negative)

**Solution**: Increase aggressiveness
```typescript
const vulns = await runActiveSecurityScan(page, {
  aggressiveness: 'high',
  maxPages: 10,
  maxDepth: 3,
});
```

### Issue: Too Many False Positives

**Solution**: Review evidence and filter
```typescript
const vulnerabilities = await runActiveSecurityScan(page);

// Filter by severity
const critical = vulnerabilities.filter(v => 
  v.severity === VulnerabilitySeverity.CRITICAL
);

// Review evidence manually
critical.forEach(v => {
  console.log(`Check this: ${v.url}`);
  console.log(`Evidence: ${v.evidence?.response.body}`);
});
```

### Issue: SPA Testing Not Working

**Solution**: See [SPA Testing Limitations](./SPA-TESTING-LIMITATIONS.md) for workarounds

---

## Next Steps

- Read [API Quick Reference](./API-QUICK-REFERENCE.md) for complete API documentation
- See [Examples](./EXAMPLES.md) for real-world test patterns
- Check [Developer Guide](./DEVELOPER-GUIDE.md) to create custom detectors
- Review [SPA Testing Limitations](./SPA-TESTING-LIMITATIONS.md) for SPA-specific issues

---

## Support

- 📖 Documentation: [docs/](./README.md)
- 🐛 Issues: [GitHub Issues](https://github.com/Tzigger/playwright-security/issues)
- 💬 Discussions: [GitHub Discussions](https://github.com/Tzigger/playwright-security/discussions)
