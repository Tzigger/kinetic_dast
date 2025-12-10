/**
 * Kinetic DAST - Playwright Test Integration Example
 * 
 * Shows how to integrate security scanning into your existing Playwright test suite.
 * Perfect for QA automation engineers who want to add security testing to CI/CD.
 * 
 * Run:
 *   npx playwright test examples/02-playwright-test-integration.spec.ts --project=chromium
 * 
 * What you'll learn:
 *   1. How to add security scans to your E2E tests
 *   2. How to fail tests based on severity thresholds
 *   3. How to generate reports for CI/CD
 */

import { test, expect } from '@playwright/test';
import { 
  runSecurityScan, 
  runPassiveSecurityScan,
  assertNoVulnerabilities, 
  VulnerabilitySeverity 
} from '../src/testing/helpers';

test.describe('Security Scan Examples', () => {
  
  /**
   * Example 1: Basic Security Check
   * 
   * Run a quick security scan and fail if critical issues found.
   * This is ideal for smoke tests or PR checks.
   */
  test('basic security check - fail on critical issues', async ({ page }) => {
    test.setTimeout(60000); // Security scans need more time
    
    // Navigate to your target page
    await page.goto('http://testphp.vulnweb.com');
    
    // Run a passive scan (fast, non-intrusive)
    const vulns = await runPassiveSecurityScan(page.url(), {
      headless: true
    });
    
    // Log findings for visibility
    console.log(`Found ${vulns.length} security issues`);
    
    // Fail if any CRITICAL severity issues found
    const critical = vulns.filter(v => v.severity === VulnerabilitySeverity.CRITICAL);
    expect(critical, 'No critical vulnerabilities allowed').toHaveLength(0);
  });

  /**
   * Example 2: Severity Threshold Testing
   * 
   * Different environments may have different severity thresholds:
   * - Production: No issues above INFO
   * - Staging: Allow LOW
   * - Development: Allow MEDIUM
   */
  test('severity threshold - staging environment', async ({ page }) => {
    test.setTimeout(60000);
    
    await page.goto('http://testphp.vulnweb.com');
    
    const vulns = await runSecurityScan(page.url(), {
      maxPages: 1,
      headless: true
    });
    
    // Use helper to assert severity threshold
    // This will fail if any HIGH or CRITICAL issues found
    assertNoVulnerabilities(vulns, VulnerabilitySeverity.MEDIUM);
  });

  /**
   * Example 3: Targeted Detector Scanning
   * 
   * Scan for specific vulnerability types only.
   * Useful for focused testing or when you only care about certain issues.
   */
  test('targeted scan - XSS only', async ({ page }) => {
    test.setTimeout(120000);
    
    await page.goto('http://testphp.vulnweb.com');
    
    const vulns = await runSecurityScan(page.url(), {
      detectors: 'xss',  // Only run XSS detection
      maxPages: 1,
      headless: true
    });
    
    console.log(`XSS scan found ${vulns.length} potential XSS issues`);
    
    // Log details for each finding
    vulns.forEach(v => {
      console.log(`  - ${v.title} at ${v.url}`);
    });
  });

  /**
   * Example 4: CI/CD Report Generation
   * 
   * Generate a structured report suitable for CI/CD artifacts.
   * This can be saved to a file and attached to your build.
   */
  test('generate CI/CD security report', async ({ page }) => {
    test.setTimeout(120000);
    
    await page.goto('http://testphp.vulnweb.com');
    
    const vulns = await runSecurityScan(page.url(), {
      maxPages: 2,
      headless: true
    });
    
    // Create structured report
    const report = {
      metadata: {
        timestamp: new Date().toISOString(),
        target: page.url(),
        scanType: 'security-smoke-test',
        environment: process.env.CI ? 'ci' : 'local',
      },
      summary: {
        total: vulns.length,
        critical: vulns.filter(v => v.severity === VulnerabilitySeverity.CRITICAL).length,
        high: vulns.filter(v => v.severity === VulnerabilitySeverity.HIGH).length,
        medium: vulns.filter(v => v.severity === VulnerabilitySeverity.MEDIUM).length,
        low: vulns.filter(v => v.severity === VulnerabilitySeverity.LOW).length,
      },
      findings: vulns.map(v => ({
        title: v.title,
        severity: v.severity,
        category: v.category,
        url: v.url,
        cwe: v.cwe,
        description: v.description,
      }))
    };
    
    console.log('📊 Security Report:');
    console.log(JSON.stringify(report, null, 2));
    
    // In CI/CD, save to file:
    // const fs = require('fs');
    // fs.writeFileSync('security-report.json', JSON.stringify(report, null, 2));
    
    // Fail build if security threshold exceeded
    expect(report.summary.critical).toBe(0);
    expect(report.summary.high).toBe(0);
  });

  /**
   * Example 5: Post-Login Security Scan
   * 
   * Demonstrates scanning authenticated pages.
   * Replace the login flow with your application's authentication.
   */
  test('authenticated page scan', async ({ page }) => {
    test.setTimeout(120000);
    
    // 1. Navigate to login page
    await page.goto('http://testphp.vulnweb.com/login.php');
    
    // 2. Perform login (replace with your app's login flow)
    await page.fill('input[name="uname"]', 'test');
    await page.fill('input[name="pass"]', 'test');
    await page.click('input[type="submit"]');
    await page.waitForLoadState('networkidle');
    
    // 3. Run security scan on authenticated page
    const vulns = await runSecurityScan(page.url(), {
      maxPages: 2,
      headless: true
    });
    
    console.log(`Found ${vulns.length} issues on authenticated pages`);
    
    // 4. Assert security requirements
    const critical = vulns.filter(v => v.severity === VulnerabilitySeverity.CRITICAL);
    expect(critical).toHaveLength(0);
  });
});
