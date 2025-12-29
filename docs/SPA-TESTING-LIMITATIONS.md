# SPA Testing Limitations & Best Practices

## Overview

Modern Single Page Applications (SPAs) built with Angular, React, or Vue present unique challenges for DAST scanners. While Kinetic v0.2.0 includes significant improvements (`SPAWaitStrategy`, `TimeoutManager`), fully autonomous crawling of complex SPAs remains challenging.

## Current Capabilities (v0.2.0)

### ✅ What Works
*   **Framework Detection**: Automatically identifies Angular, React, Vue, Svelte, and Next.js.
*   **Intelligent Waiting**: Uses framework hooks (e.g., `ngZone.isStable`, `Vue.nextTick`) to wait for hydration.
*   **Hash Navigation**: Correctly identifies and crawls `/#/routes`.
*   **XSS Detection**: Highly effective at finding reflected/stored XSS in SPA inputs.

### ⚠️ Known Limitations

#### 1. Deep Logic Discovery
**Issue**: The crawler may miss inputs buried deep in complex state flows (e.g., a multi-step checkout wizard in React that requires specific Redux state).
**Impact**: Some attack surfaces might not be discovered automatically.
**Solution**: Use the **Element Scanner** to explicitly target these components.

#### 2. SQL Injection in APIs
**Issue**: On some SPAs (like OWASP Juice Shop), the UI inputs are heavily sanitized or disabled via JavaScript before the request is sent. The scanner might not trigger the underlying API call with the raw payload required to test for SQLi.
**Impact**: False negatives for SQLi if relying solely on UI interaction.
**Solution**: Use **Hybrid Testing** (see below) to test API endpoints directly.

#### 3. Test Timeouts
**Issue**: Scans on heavy SPAs can be slow due to the necessary waiting periods for stability.
**Impact**: Playwright tests might timeout before the scan completes.
**Solution**: Increase test timeouts or reduce `maxPages`.

```typescript
test.setTimeout(300_000); // 5 minutes
```

---

## Recommended Strategies

If the default `ActiveScanner` is struggling with your SPA, use these strategies:

### Strategy 1: Targeted Element Scanning (Recommended)
Instead of relying on the crawler to find a specific input, point the **Element Scanner** directly at it. This bypasses navigation complexity.

```typescript
// tests/login-security.spec.ts
import { ElementScanner } from '@tzigger/kinetic/scanners/active/ElementScanner';

const scanner = new ElementScanner({
  baseUrl: 'http://localhost:3000',
  // Manually define the target element
  elements: [{
    locator: '#email',
    type: AttackSurfaceType.FORM_INPUT,
    context: InjectionContext.SQL
  }]
});
```

### Strategy 2: Hybrid Testing (UI + API)
Test the UI for XSS and the API for Injection.

```typescript
test('hybrid security check', async ({ page, request }) => {
  // 1. Test UI for XSS (Active Scanner handles SPAs well for XSS)
  await page.goto('/#/search');
  const uiVulns = await runActiveSecurityScan(page, { detectors: 'xss' });
  
  // 2. Test API directly for SQLi (Bypass UI logic)
  const apiResponse = await request.get('/api/search?q=' + encodeURIComponent("' OR 1=1--"));
  expect(apiResponse.status()).toBe(200);
  // ... check response body ...
});
```

### Strategy 3: Manual State Setup
Use Playwright to manually navigate the SPA into the correct state before starting the scan.

```typescript
test('scan checkout', async ({ page }) => {
  // 1. Manually perform complex setup
  await page.goto('/shop');
  await page.click('.add-to-cart');
  await page.click('.checkout');
  
  // 2. Start scan ONLY after reaching the target state
  await runActiveSecurityScan(page, { 
    maxPages: 1 // Don't navigate away
  });
});
```

## Summary

| Challenge | Kinetic v0.2.0 Solution | Manual Workaround |
|-----------|-------------------------|-------------------|
| **Page Load** | `SPAWaitStrategy` (Auto) | `page.waitForSelector()` |
| **Complex State** | `ElementScanner` | Manual Playwright steps |
| **Hidden APIs** | JS Static Analysis | Direct API tests |
| **Timeouts** | `TimeoutManager` | Increase test timeout |
