# Kinetic Testing Guide

## Overview

This guide explains how to integrate Kinetic Security Scanner into your Playwright test suite. We provide specialized helper functions that make security testing as seamless as writing functional tests.

## Table of Contents

1.  [Quick Start](#quick-start)
2.  [Helper Functions](#helper-functions)
3.  [Configuration Options](#configuration-options)
4.  [Advanced Patterns](#advanced-patterns)
    *   [SPA Testing](#pattern-1-testing-spas)
    *   [Authenticated Scans](#pattern-2-authenticated-scans)
    *   [Targeted Element Scanning](#pattern-3-targeted-element-scanning)
5.  [Best Practices](#best-practices)

---

## Quick Start

### Basic Security Test

```typescript
import { test, expect } from '@playwright/test';
import { runActiveSecurityScan, assertNoVulnerabilities } from '@tzigger/kinetic/testing';

test('basic security scan', async ({ page }) => {
  await page.goto('https://example.com');
  
  // Run active scan on the current page state
  const vulnerabilities = await runActiveSecurityScan(page);
  
  // Fail if any high/critical issues are found
  assertNoVulnerabilities(vulnerabilities);
});
```

That's it! The framework will:
*   ✅ Automatically discover forms, inputs, and APIs.
*   ✅ Test for SQL injection, XSS, and error disclosure.
*   ✅ Verify findings to reduce false positives.
*   ✅ Return a list of vulnerabilities.

---

## Helper Functions

Import these from `@tzigger/kinetic/testing`.

### `runActiveSecurityScan(target, options)`

**Purpose**: Performs intrusive scanning (payload injection, fuzzing).

*   **target**: `string` (URL) or `Page` (Playwright object).
*   **options**: `ActiveScanOptions`.
*   **Returns**: `Promise<Vulnerability[]>`

```typescript
const vulns = await runActiveSecurityScan(page, {
  detectors: 'sql',           // 'all' | 'sql' | 'xss' | 'errors'
  aggressiveness: 'medium',   // 'low' | 'medium' | 'high'
  maxPages: 3                 // Crawl depth
});
```

### `runPassiveSecurityScan(target, options)`

**Purpose**: Analyzes traffic and configuration without modifying requests. Safe for production.

*   **target**: `string` (URL) or `Page` (Playwright object).
*   **options**: `PassiveScanOptions`.
*   **Returns**: `Promise<Vulnerability[]>`

```typescript
const vulns = await runPassiveSecurityScan('https://example.com', {
  detectors: 'headers'        // 'all' | 'headers' | 'cookies' | 'data'
});
```

### `assertNoVulnerabilities(vulns, maxSeverity)`

**Purpose**: Assertion helper to fail tests based on severity thresholds.

*   **vulns**: Array of vulnerabilities.
*   **maxSeverity**: `VulnerabilitySeverity` (Default: `INFO`).

```typescript
import { VulnerabilitySeverity } from '@tzigger/kinetic';

// Fail if MEDIUM, HIGH, or CRITICAL found
assertNoVulnerabilities(vulns, VulnerabilitySeverity.LOW);
```

---

## Configuration Options

### ActiveScanOptions

| Option | Type | Description | Default |
| :--- | :--- | :--- | :--- |
| `detectors` | string | Which checks to run (`all`, `sql`, `xss`, `errors`). | `all` |
| `aggressiveness` | string | Payload count (`low`: ~5, `medium`: ~15, `high`: ~50). | `medium` |
| `maxPages` | number | How many links to crawl from the start page. | `5` |
| `maxDepth` | number | Crawl depth. | `2` |
| `submitForms` | boolean | Whether to auto-submit discovered forms. | `true` |

### PassiveScanOptions

| Option | Type | Description | Default |
| :--- | :--- | :--- | :--- |
| `detectors` | string | Checks (`all`, `headers`, `cookies`, `data`, `transmission`). | `all` |
| `maxPages` | number | How many pages to visit for traffic analysis. | `1` |

---

## Advanced Patterns

### Pattern 1: Testing SPAs

For Single Page Applications (Angular, React, Vue), navigate to the specific state *before* passing the page to the scanner.

```typescript
test('SPA dashboard check', async ({ page }) => {
  // 1. Navigate and wait for hydration
  await page.goto('https://myapp.com/#/dashboard');
  await page.waitForLoadState('networkidle');
  
  // 2. Scan (Kinetic will detect the framework and wait for stability)
  const vulns = await runActiveSecurityScan(page, {
    maxPages: 3 // Allow crawling internal hash routes
  });
  
  assertNoVulnerabilities(vulns);
});
```

### Pattern 2: Authenticated Scans

Kinetic reuses the authentication state of the Playwright `Page` object passed to it.

```typescript
// Define auth state in playwright.config.ts or global-setup
test.use({ storageState: 'auth.json' }); 

test('authenticated scan', async ({ page }) => {
  // Page is already logged in via storageState
  await page.goto('https://myapp.com/profile');
  
  // Scanner inherits cookies/localStorage
  await runActiveSecurityScan(page); 
});
```

### Pattern 3: Targeted Element Scanning

If the crawler fails to find a specific complex input, use the **Element Scanner** to target it directly via locator.

```typescript
import { ElementScanner } from '@tzigger/kinetic/scanners/active/ElementScanner';
import { AttackSurfaceType, InjectionContext } from '@tzigger/kinetic/types';
import { SqlInjectionDetector } from '@tzigger/kinetic/detectors/active/SqlInjectionDetector';

test('complex search bar check', async ({ page }) => {
  await page.goto('https://myapp.com/advanced-search');

  // Configure specific target
  const scanner = new ElementScanner({
    baseUrl: 'https://myapp.com',
    elements: [{
      name: 'Search Filter',
      locator: '[data-testid="filter-input"]', // Precise locator
      type: AttackSurfaceType.FORM_INPUT,
      context: InjectionContext.SQL
    }]
  });

  scanner.registerDetector(new SqlInjectionDetector());
  
  // Initialize with the current test page
  await scanner.initialize({ page, ...mockContext }); 
  
  const result = await scanner.execute();
  expect(result.vulnerabilities).toHaveLength(0);
});
```

---

## Best Practices

1.  **Separate Active and Passive**: Run passive scans on every build (fast). Run active scans nightly or on release (slower).
2.  **Increase Timeouts**: Active scans take time. Set `test.setTimeout(300_000)` (5 mins) for comprehensive scans.
3.  **Scope Properly**: Use `maxPages` and `maxDepth` to prevent the scanner from wandering into logout pages or external sites.
4.  **Review Evidence**: When a test fails, check the `evidence` property in the report. It contains the exact payload and response snippet that triggered the detection.

## Troubleshooting

*   **Test Timeout**: The scanner is waiting for stability. Increase Playwright timeout or use `aggressiveness: 'low'`.
*   **False Positives**: The Verification Engine usually filters these. If one slips through, check if `safeMode` prevented the verification payload from running, or tune the detector sensitivity in `kinetic.config.json`.
*   **0 Vulnerabilities (False Negative)**: Ensure the scanner actually found the inputs. Run with `DEBUG=kinetic:*` to see the DomExplorer logs.
