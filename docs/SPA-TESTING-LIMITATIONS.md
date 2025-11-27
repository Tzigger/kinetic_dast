# SPA Testing Limitations

## Overview

While the Playwright Security framework includes SPA (Single Page Application) support, there are known limitations when testing complex JavaScript frameworks like Angular-based applications (e.g., OWASP Juice Shop).

## Current Status

### ✅ Working Features
- **SPA Mode Detection**: Framework correctly identifies SPAs (Angular, React, Vue)
- **Existing Page Support**: Tests can pass pre-loaded `Page` objects to scanners
- **Hash Route Extraction**: Discovers and navigates to hash-based routes (`/#/login`, `/#/search`)
- **Navigation Skip Logic**: Avoids unnecessary page reloads when already on target route
- **XSS Detection**: Successfully finds reflected XSS in cookies and responses
- **Multi-page Crawling**: Explores discovered routes autonomously

### ❌ Known Issues

#### 1. SQL Injection Detection in SPAs
**Problem**: Scanner fails to detect SQL injection vulnerabilities in Angular SPAs (e.g., Juice Shop search endpoint)

**Evidence**:
```
Test Results (4 autonomous tests):
- XSS Found: 5 vulnerabilities ✅
- SQLi Found: 0 vulnerabilities ❌
- Error Disclosure: 0 vulnerabilities ❌
```

**Root Causes**:
1. **API Endpoint Discovery**: Scanner may not be triggering API calls (`/rest/products/search?q=`) that execute SQL queries
2. **Search Input Interaction**: Search inputs may be disabled/hidden initially, requiring specific Angular state
3. **XHR Request Timing**: API calls happen asynchronously after input changes, scanner may not wait long enough
4. **Response Analysis**: JSON API responses may not contain clear SQL error indicators

#### 2. Test Timeouts
**Problem**: Tests timeout at 5 minutes (300s) even though scans complete

**Scan Performance**:
- Actual scan time: ~294s (4.9 minutes)
- Default timeout: 300s (5 minutes)
- Result: Tests fail despite finding vulnerabilities

**Impact**: Makes autonomous testing unreliable for comprehensive scans

#### 3. Page Closure Errors
**Problem**: Error messages during cleanup phase

```
Error checking page for errors: page.content: Target page, context or browser has been closed
```

**Cause**: Test framework closes page/context before scanner finishes cleanup
**Impact**: Non-critical, but pollutes test output

## Test Results Summary

### Juice Shop Autonomous Detection (4 tests)

| Test | Duration | Vulnerabilities | Status |
|------|----------|----------------|---------|
| Home Page Scan | ~295s | 5 XSS | ❌ Timeout |
| Search Page Scan | ~295s | 5 XSS | ❌ Timeout |
| Login Page Scan | ~295s | 1 XSS | ❌ Timeout |
| Comprehensive Scan | ~295s | 5 XSS | ❌ Timeout |

**Key Findings**:
- ✅ All tests discovered XSS vulnerabilities
- ❌ Zero SQL injection detected (expected ≥1)
- ❌ Zero error disclosure detected (expected ≥1)
- ❌ All tests hit timeout threshold

## Recommended Approach

Until SPA testing is fully optimized, use **hybrid testing strategies**:

### Option 1: API-Direct Testing
Test backend APIs directly instead of through the SPA:

```typescript
test('SQL injection in search API - direct approach', async ({ page }) => {
  // Direct API call, bypassing Angular
  const response = await page.request.get(
    'http://localhost:3000/rest/products/search?q=' + encodeURIComponent("' OR 1=1--")
  );
  
  const body = await response.text();
  expect(body).toContain('sql'); // Check for error indicators
});
```

### Option 2: Focused Configuration
Use aggressive settings and smaller scope:

```typescript
const vulnerabilities = await runActiveSecurityScan(page, {
  aggressiveness: AggressivenessLevel.HIGH,
  maxPages: 3,  // Limit crawl scope
  maxDepth: 1,  // Stay shallow
  detectors: 'sql', // Test only SQL injection
});
```

### Option 3: Manual Payload Testing
Test specific attack surfaces directly:

```typescript
test('SQL injection - manual payload approach', async ({ page }) => {
  await page.goto('http://localhost:3000/#/search');
  
  // Manually trigger search with SQLi payload
  await page.fill('input[type="text"]', "' OR 1=1--");
  await page.keyboard.press('Enter');
  await page.waitForResponse(resp => resp.url().includes('/rest/products/search'));
  
  // Check response for SQL errors
  const content = await page.content();
  expect(content.toLowerCase()).toContain('sql');
});
```

## Configuration Adjustments

### Increase Timeout for Comprehensive Scans
```typescript
test.setTimeout(600000); // 10 minutes instead of 5
```

### Reduce Scan Scope
```typescript
const config = {
  maxPages: 3,      // Default: 5
  maxDepth: 1,      // Default: 2
  timeout: 30000,   // Reduce per-page timeout
};
```

### Use Focused Detectors
```typescript
const vulnerabilities = await runActiveSecurityScan(page, {
  detectors: 'sql', // Only test SQL injection
});
```

## Future Improvements

### Planned Enhancements
1. **Smarter API Discovery**: Intercept XHR/Fetch requests to discover API endpoints
2. **Angular-Aware Testing**: Wait for Angular zone stability before testing
3. **Payload Optimization**: Reduce number of payloads for faster scans
4. **Parallel Testing**: Test multiple attack surfaces concurrently
5. **Response Streaming**: Analyze responses during scan, not after completion

### Workarounds in Progress
- [ ] Network request interception for API endpoint discovery
- [ ] Reduced time-based SQLi delay (2s → 1s)
- [ ] Smart payload selection based on context
- [ ] Incremental vulnerability reporting

## Testing Against Juice Shop

### Current Limitations
```typescript
// ❌ This approach finds XSS but misses SQLi
test('autonomous scan - limited effectiveness', async ({ page }) => {
  await page.goto('http://localhost:3000');
  const vulns = await runActiveSecurityScan(page);
  // Result: 5 XSS, 0 SQLi, 0 Error Disclosure
});
```

### Recommended Alternative
```typescript
// ✅ Hybrid approach - better coverage
test('hybrid scan - improved detection', async ({ page }) => {
  // Test UI with framework
  await page.goto('http://localhost:3000/#/search');
  const uiVulns = await runActiveSecurityScan(page, {
    maxPages: 2,
    detectors: 'xss',
  });
  
  // Test API directly
  const apiTests = await fetch('http://localhost:3000/rest/products/search?q=' + 
    encodeURIComponent("' OR 1=1--"));
  const apiBody = await apiTests.text();
  
  // Combine results
  expect(uiVulns.length + (apiBody.includes('sql') ? 1 : 0)).toBeGreaterThan(0);
});
```

## Conclusion

**Current State**: SPA support is **partially functional** - works well for simple XSS detection but struggles with complex SQL injection scenarios in modern SPAs.

**Recommendation**: Use **hybrid testing strategies** (framework + manual API tests) until autonomous SPA testing is fully optimized.

**Timeline**: SPA testing improvements are planned for future releases based on community feedback and usage patterns.
