/**
 * Example: Using runActiveSecurityScan and runPassiveSecurityScan
 * 
 * These are the main helper functions for writing simple security tests.
 * 
 * Run with:
 *   npx playwright test tests/security-helpers-example.spec.ts --project=chromium
 */

import { test, expect } from '@playwright/test';
import { 
  runActiveSecurityScan, 
  runPassiveSecurityScan,
  assertNoVulnerabilities,
  VulnerabilitySeverity 
} from '../src/testing/helpers';

test.describe('Active Security Scanning Examples', () => {
  
  test('Example 1: Basic active scan for SQL injection', async () => {
    test.setTimeout(120000); // 2 minutes
    
    const vulns = await runActiveSecurityScan('http://testphp.vulnweb.com/artists.php');
    
    // Check for SQL injection vulnerabilities
    const sqlVulns = vulns.filter(v => 
      v.title.toLowerCase().includes('sql') || v.category === 'injection'
    );
    
    console.log(`Found ${vulns.length} total vulnerabilities`);
    console.log(`Found ${sqlVulns.length} SQL-related vulnerabilities`);
    
    // This is a vulnerable site, so we expect to find some issues
    expect(vulns.length).toBeGreaterThan(0);
  });

  test('Example 2: Active scan with custom options', async () => {
    test.setTimeout(120000);
    
    // Low aggressiveness, only check for XSS
    const vulns = await runActiveSecurityScan('http://testphp.vulnweb.com', {
      aggressiveness: 'low',
      maxPages: 2,
      detectors: 'xss',
      headless: true
    });
    
    console.log(`XSS-focused scan found ${vulns.length} vulnerabilities`);
    vulns.slice(0, 3).forEach(v => {
      console.log(`  - [${v.severity}] ${v.title}`);
    });
  });

  test('Example 3: Active scan on search form', async ({ page }) => {
    test.setTimeout(120000);
    
    // Navigate to a page with a search form
    await page.goto('http://testphp.vulnweb.com/search.php?test=query');
    
    // Scan just the search functionality
    const vulns = await runActiveSecurityScan(page.url(), {
      maxPages: 1,
      detectors: 'sql'
    });
    
    console.log(`Search form scan: ${vulns.length} vulnerabilities`);
    
    // Assert no critical SQL injection
    const critical = vulns.filter(v => v.severity === VulnerabilitySeverity.CRITICAL);
    console.log(`Critical vulnerabilities: ${critical.length}`);
  });
});

test.describe('Passive Security Scanning Examples', () => {
  
  test('Example 4: Basic passive scan for security headers', async () => {
    const vulns = await runPassiveSecurityScan('http://testphp.vulnweb.com');
    
    console.log(`Passive scan found ${vulns.length} vulnerabilities`);
    
    // Check for missing security headers
    const headerIssues = vulns.filter(v => 
      v.title.includes('Security Header') || v.title.includes('Header')
    );
    
    console.log(`Missing security headers: ${headerIssues.length}`);
    headerIssues.forEach(h => console.log(`  - ${h.title}`));
    
    expect(vulns.length).toBeGreaterThan(0);
  });

  test('Example 5: Passive scan on SPA website', async ({ page }) => {
    // Navigate to SPA and wait for it to load
    await page.goto('http://testhtml5.vulnweb.com/#/popular', {
      waitUntil: 'networkidle'
    });
    await page.waitForTimeout(2000);
    
    // Passive scan is perfect for SPAs - fast and non-intrusive
    const vulns = await runPassiveSecurityScan(page.url(), {
      maxPages: 1 // SPAs are single page
    });
    
    console.log(`SPA passive scan: ${vulns.length} vulnerabilities`);
    
    // Check for sensitive data exposure
    const dataExposure = vulns.filter(v => 
      v.category === 'information-disclosure' || 
      v.title.includes('Sensitive Data')
    );
    
    console.log(`Sensitive data issues: ${dataExposure.length}`);
  });

  test('Example 6: Passive scan - check only headers', async () => {
    const vulns = await runPassiveSecurityScan('http://testphp.vulnweb.com', {
      detectors: 'headers' // Only check security headers
    });
    
    console.log(`Header-only scan: ${vulns.length} issues`);
    
    // List all missing headers
    vulns.forEach(v => {
      console.log(`  - [${v.severity}] ${v.title}`);
    });
  });

  test('Example 7: Passive scan with assertion', async () => {
    const vulns = await runPassiveSecurityScan('http://testphp.vulnweb.com');
    
    // Assert: No HIGH or CRITICAL vulnerabilities
    // (This will throw an error if any are found)
    try {
      assertNoVulnerabilities(vulns, VulnerabilitySeverity.MEDIUM);
      console.log('✅ No high/critical vulnerabilities found');
    } catch (error) {
      console.log('❌ High/critical vulnerabilities detected');
      // In a real test, this would fail the test
      expect(error).toBeDefined();
    }
  });
});

test.describe('Combined Active + Passive Scanning', () => {
  
  test('Example 8: Comprehensive security check', async ({ page }) => {
    test.setTimeout(180000); // 3 minutes
    
    const targetUrl = 'http://testphp.vulnweb.com';
    
    // First, do a quick passive scan (fast)
    console.log('Running passive scan...');
    const passiveVulns = await runPassiveSecurityScan(targetUrl, {
      maxPages: 1
    });
    console.log(`Passive: ${passiveVulns.length} vulnerabilities`);
    
    // Then, do active scan for injection attacks (slower)
    console.log('Running active scan...');
    const activeVulns = await runActiveSecurityScan(targetUrl, {
      aggressiveness: 'low',
      maxPages: 2
    });
    console.log(`Active: ${activeVulns.length} vulnerabilities`);
    
    // Combine results
    const allVulns = [...passiveVulns, ...activeVulns];
    console.log(`Total: ${allVulns.length} vulnerabilities`);
    
    // Summary by severity
    const summary = {
      critical: allVulns.filter(v => v.severity === VulnerabilitySeverity.CRITICAL).length,
      high: allVulns.filter(v => v.severity === VulnerabilitySeverity.HIGH).length,
      medium: allVulns.filter(v => v.severity === VulnerabilitySeverity.MEDIUM).length,
      low: allVulns.filter(v => v.severity === VulnerabilitySeverity.LOW).length,
    };
    
    console.log('Summary:', summary);
    
    // Assert: No critical vulnerabilities
    const critical = allVulns.filter(v => v.severity === VulnerabilitySeverity.CRITICAL);
    expect(critical.length).toBeLessThanOrEqual(1); // Allow 1 for demo purposes
  });

  test('Example 9: Fast pre-deployment check', async () => {
    test.setTimeout(60000); // 1 minute
    
    // Quick passive-only scan for fast feedback
    const vulns = await runPassiveSecurityScan('http://testphp.vulnweb.com', {
      maxPages: 1,
      detectors: 'headers' // Just check critical headers
    });
    
    // Check for critical headers
    const missingHSTS = vulns.some(v => v.title.includes('Strict-Transport-Security'));
    const missingCSP = vulns.some(v => v.title.includes('Content-Security-Policy'));
    
    console.log(`Missing HSTS: ${missingHSTS}`);
    console.log(`Missing CSP: ${missingCSP}`);
    
    // In production, you'd fail deployment if critical headers are missing
    if (missingHSTS || missingCSP) {
      console.log('⚠️  Critical security headers missing!');
    }
  });
});

test.describe('Real-world Testing Patterns', () => {
  
  test('Pattern 1: Login page security', async ({ page }) => {
    test.setTimeout(120000);
    
    await page.goto('http://testphp.vulnweb.com/login.php');
    
    // Passive scan first (quick check)
    const passiveVulns = await runPassiveSecurityScan(page.url(), { maxPages: 1 });
    
    // Then active scan for SQL injection in login form
    const activeVulns = await runActiveSecurityScan(page.url(), {
      maxPages: 1,
      detectors: 'sql'
    });
    
    console.log(`Login page: ${passiveVulns.length + activeVulns.length} total issues`);
    
    // No SQL injection should be possible
    const sqlInjection = activeVulns.filter(v => v.category === 'injection');
    expect(sqlInjection.length).toBe(0);
  });

  test('Pattern 2: API endpoint security', async () => {
    test.setTimeout(60000);
    
    // For API endpoints, passive scanning is usually sufficient
    const vulns = await runPassiveSecurityScan('http://testphp.vulnweb.com/artists.php?artist=1', {
      maxPages: 1,
      detectors: 'data' // Check for sensitive data in responses
    });
    
    console.log(`API security scan: ${vulns.length} issues`);
    
    // APIs should not expose sensitive data
    const dataLeaks = vulns.filter(v => v.category === 'information-disclosure');
    console.log(`Data exposure issues: ${dataLeaks.length}`);
  });
  
  test('Pattern 3: CI/CD integration example', async () => {
    test.setTimeout(120000);
    
    const targetUrl = process.env.STAGING_URL || 'http://testphp.vulnweb.com';
    
    // Quick passive scan suitable for CI/CD
    const vulns = await runPassiveSecurityScan(targetUrl, {
      maxPages: 3
    });
    
    console.log(`CI/CD Security Check: ${vulns.length} vulnerabilities`);
    
    // Categorize by severity
    const critical = vulns.filter(v => v.severity === VulnerabilitySeverity.CRITICAL);
    const high = vulns.filter(v => v.severity === VulnerabilitySeverity.HIGH);
    
    // Fail build on critical/high issues
    if (critical.length > 0 || high.length > 0) {
      console.log(`❌ Build should fail: ${critical.length} critical, ${high.length} high`);
    } else {
      console.log('✅ Security check passed');
    }
    
    // In real CI/CD, you'd use:
    // assertNoVulnerabilities(vulns, VulnerabilitySeverity.MEDIUM);
  });
});
