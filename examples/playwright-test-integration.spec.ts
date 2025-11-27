/**
 * Example: Using Playwright Security Framework in Playwright Tests
 * 
 * This demonstrates how to integrate security scanning into your E2E test suite.
 * 
 * Usage:
 *   npx playwright test examples/playwright-test-integration.spec.ts
 * 
 * Features demonstrated:
 * - Basic vulnerability scanning
 * - Severity-based filtering
 * - Detector-specific scanning
 * - Authenticated page scanning
 * - CI/CD integration patterns
 */
import { test, expect } from '@playwright/test';
import { runSecurityScan, assertNoVulnerabilities, VulnerabilitySeverity } from '../src/testing/helpers';

test.describe('Security Testing Examples', () => {
  
  // Example 1: Basic vulnerability scan on a public page
  test('should scan login page for vulnerabilities', async ({ page }) => {
    // Navigate to your app
    await page.goto('http://testphp.vulnweb.com/login.php');
    
    // Run security scan
    const vulnerabilities = await runSecurityScan(page.url(), {
      detectors: 'all',
      maxPages: 1,
      headless: true
    });
    
    // Assert no critical vulnerabilities
    const critical = vulnerabilities.filter(v => v.severity === VulnerabilitySeverity.CRITICAL);
    expect(critical).toHaveLength(0);
    
    // Log findings for review
    if (vulnerabilities.length > 0) {
      console.log('⚠️  Vulnerabilities found:', vulnerabilities.map(v => 
        `${v.severity}: ${v.title}`
      ));
    }
  });

  // Example 2: Severity-based filtering
  test('should allow only low severity issues in staging', async ({ page }) => {
    await page.goto('http://testphp.vulnweb.com');
    
    const vulnerabilities = await runSecurityScan(page.url(), {
      maxPages: 1,
      headless: true
    });
    
    // Fail if anything above LOW severity found
    // This is useful for staging environments where some known issues exist
    assertNoVulnerabilities(vulnerabilities, VulnerabilitySeverity.LOW);
  });

  // Example 3: Targeted scanning for specific vulnerability types
  test('should scan for XSS vulnerabilities only', async ({ page }) => {
    await page.goto('http://testphp.vulnweb.com');
    
    const vulnerabilities = await runSecurityScan(page.url(), {
      detectors: 'xss', // Only XSS tests
      maxPages: 1,
      headless: true
    });
    
    // Check XSS findings
    const xssVulns = vulnerabilities.filter(v => 
      v.title.toLowerCase().includes('xss') || 
      v.category === 'xss'
    );
    
    console.log(`Found ${xssVulns.length} XSS-related issues`);
  });

  // Example 4: Multiple pages scan
  test('should scan multiple pages for security issues', async ({ page }) => {
    await page.goto('http://testphp.vulnweb.com');
    
    const vulnerabilities = await runSecurityScan(page.url(), {
      maxPages: 3, // Scan up to 3 pages
      headless: true
    });
    
    // Generate summary by severity
    const summary = {
      critical: vulnerabilities.filter(v => v.severity === VulnerabilitySeverity.CRITICAL).length,
      high: vulnerabilities.filter(v => v.severity === VulnerabilitySeverity.HIGH).length,
      medium: vulnerabilities.filter(v => v.severity === VulnerabilitySeverity.MEDIUM).length,
      low: vulnerabilities.filter(v => v.severity === VulnerabilitySeverity.LOW).length,
    };
    
    console.log('📊 Vulnerability Summary:', summary);
    
    // Fail if critical or high severity issues found
    expect(summary.critical, 'No critical vulnerabilities allowed').toBe(0);
    expect(summary.high, 'No high severity vulnerabilities allowed').toBe(0);
  });

  // Example 5: Authenticated page scanning
  test('should scan authenticated pages', async ({ page }) => {
    // This example shows scanning after authentication
    // Note: Replace with your actual authentication flow
    
    await page.goto('http://testphp.vulnweb.com/login.php');
    
    // Perform login (example - adjust for your app)
    await page.fill('input[name="uname"]', 'test');
    await page.fill('input[name="pass"]', 'test');
    await page.click('input[type="submit"]');
    
    // Wait for navigation after login
    await page.waitForLoadState('networkidle');
    
    // Now scan the authenticated page
    const vulnerabilities = await runSecurityScan(page.url(), {
      maxPages: 2,
      headless: true
    });
    
    console.log(`Found ${vulnerabilities.length} vulnerabilities on authenticated pages`);
  });

  // Example 6: CI/CD Integration - Generate artifact
  test('CI/CD - generate security report artifact', async ({ page }) => {
    await page.goto('http://testphp.vulnweb.com');
    
    const vulnerabilities = await runSecurityScan(page.url(), {
      maxPages: 3,
      headless: true
    });
    
    // Save report for CI/CD artifact
    const report = {
      timestamp: new Date().toISOString(),
      target: page.url(),
      totalVulnerabilities: vulnerabilities.length,
      summary: {
        critical: vulnerabilities.filter(v => v.severity === VulnerabilitySeverity.CRITICAL).length,
        high: vulnerabilities.filter(v => v.severity === VulnerabilitySeverity.HIGH).length,
        medium: vulnerabilities.filter(v => v.severity === VulnerabilitySeverity.MEDIUM).length,
        low: vulnerabilities.filter(v => v.severity === VulnerabilitySeverity.LOW).length,
      },
      vulnerabilities: vulnerabilities.map(v => ({
        title: v.title,
        severity: v.severity,
        category: v.category,
        url: v.url
      }))
    };
    
    console.log('📄 Security Report Generated:');
    console.log(JSON.stringify(report, null, 2));
    
    // In real CI/CD, save to file:
    // await fs.writeFile('./security-report.json', JSON.stringify(report, null, 2));
  });

  // Example 7: Quick smoke test for security headers
  test('should verify security headers are present', async ({ page }) => {
    await page.goto('http://testphp.vulnweb.com');
    
    const vulnerabilities = await runSecurityScan(page.url(), {
      detectors: 'errors', // Fast check for basic issues
      maxPages: 1,
      headless: true
    });
    
    // Check for missing security headers
    const headerIssues = vulnerabilities.filter(v => 
      v.title.toLowerCase().includes('header') ||
      v.category === 'security-misconfiguration'
    );
    
    if (headerIssues.length > 0) {
      console.log('⚠️  Missing security headers:', 
        headerIssues.map(v => v.title).join(', ')
      );
    }
  });

  // Example 8: Parallel security checks
  test('should run parallel security checks on multiple endpoints', async ({ page }) => {
    const endpoints = [
      'http://testphp.vulnweb.com',
      'http://testphp.vulnweb.com/login.php',
      'http://testphp.vulnweb.com/artists.php'
    ];
    
    // Scan each endpoint
    const results = await Promise.all(
      endpoints.map(async (url) => {
        await page.goto(url);
        const vulns = await runSecurityScan(url, {
          maxPages: 1,
          headless: true
        });
        return { url, count: vulns.length, vulnerabilities: vulns };
      })
    );
    
    // Display results
    console.log('🔍 Parallel Scan Results:');
    results.forEach(({ url, count }) => {
      console.log(`  ${url}: ${count} issues`);
    });
    
    // Assert no critical issues on any endpoint
    results.forEach(({ url, vulnerabilities }) => {
      const critical = vulnerabilities.filter(v => 
        v.severity === VulnerabilitySeverity.CRITICAL
      );
      expect(critical, `No critical issues on ${url}`).toHaveLength(0);
    });
  });
});
