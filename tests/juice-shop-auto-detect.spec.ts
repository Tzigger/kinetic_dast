import { test, expect } from '@playwright/test';
import { runActiveSecurityScan } from '../src/testing/helpers';
import { VulnerabilitySeverity } from '../src/types/enums';

/**
 * Juice Shop Autonomous Detection Test
 * 
 * Simple, autonomous tests that let the scanner discover vulnerabilities on its own.
 * No focused configurations - just point it at Juice Shop and let it work.
 * 
 * Prerequisites:
 * - OWASP Juice Shop running at http://localhost:3000
 * - Start with: docker run -p 3000:3000 bkimminich/juice-shop
 */

test.describe('Juice Shop Autonomous Vulnerability Detection', () => {
  test.setTimeout(300000); // 5 minutes for comprehensive scan

  test('scan home page - discover vulnerabilities autonomously', async ({ page }) => {
    await page.goto('http://localhost:3000');
    await page.waitForLoadState('networkidle');
    
    const vulnerabilities = await runActiveSecurityScan(page);

    console.log(`\n=== Home Page Scan Results ===`);
    console.log(`Total vulnerabilities found: ${vulnerabilities.length}`);
    
    vulnerabilities.forEach((vuln, index) => {
      console.log(`\n${index + 1}. ${vuln.title} [${vuln.severity}]`);
      console.log(`   URL: ${vuln.url}`);
      console.log(`   CWE: ${vuln.cwe}`);
    });

    expect(vulnerabilities.length).toBeGreaterThan(0);
  });

  test('scan search page - discover vulnerabilities autonomously', async ({ page }) => {
    await page.goto('http://localhost:3000/#/search');
    await page.waitForLoadState('networkidle');
    
    const vulnerabilities = await runActiveSecurityScan(page);

    console.log(`\n=== Search Page Scan Results ===`);
    console.log(`Total vulnerabilities found: ${vulnerabilities.length}`);
    
    vulnerabilities.forEach((vuln, index) => {
      console.log(`\n${index + 1}. ${vuln.title} [${vuln.severity}]`);
      console.log(`   URL: ${vuln.url}`);
      console.log(`   CWE: ${vuln.cwe}`);
    });

    expect(vulnerabilities.length).toBeGreaterThan(0);
  });

  test('scan login page - discover vulnerabilities autonomously', async ({ page }) => {
    await page.goto('http://localhost:3000/#/login');
    await page.waitForLoadState('networkidle');
    
    const vulnerabilities = await runActiveSecurityScan(page);

    console.log(`\n=== Login Page Scan Results ===`);
    console.log(`Total vulnerabilities found: ${vulnerabilities.length}`);
    
    vulnerabilities.forEach((vuln, index) => {
      console.log(`\n${index + 1}. ${vuln.title} [${vuln.severity}]`);
      console.log(`   URL: ${vuln.url}`);
      console.log(`   CWE: ${vuln.cwe}`);
    });

    expect(vulnerabilities.length).toBeGreaterThan(0);
  });

  test('comprehensive autonomous scan - all OWASP Top 10', async ({ page }) => {
    await page.goto('http://localhost:3000');
    await page.waitForLoadState('networkidle');
    
    console.log('\n=== Starting Comprehensive Autonomous Scan ===');
    console.log('Letting scanner explore and discover vulnerabilities...\n');
    
    const startTime = Date.now();
    const vulnerabilities = await runActiveSecurityScan(page);
    const duration = ((Date.now() - startTime) / 1000).toFixed(1);

    // Categorize by type
    const sqliVulns = vulnerabilities.filter(v => v.cwe === 'CWE-89');
    const xssVulns = vulnerabilities.filter(v => v.cwe === 'CWE-79');
    const errorVulns = vulnerabilities.filter(v => v.cwe === 'CWE-209');
    
    // Categorize by severity
    const criticalVulns = vulnerabilities.filter(v => v.severity === VulnerabilitySeverity.CRITICAL);
    const highVulns = vulnerabilities.filter(v => v.severity === VulnerabilitySeverity.HIGH);
    const mediumVulns = vulnerabilities.filter(v => v.severity === VulnerabilitySeverity.MEDIUM);

    console.log('\n=== Autonomous Scan Results ===');
    console.log(`Scan duration: ${duration}s`);
    console.log(`Total vulnerabilities: ${vulnerabilities.length}`);
    console.log(`\nBy Type:`);
    console.log(`  - SQL Injection (CWE-89): ${sqliVulns.length}`);
    console.log(`  - XSS (CWE-79): ${xssVulns.length}`);
    console.log(`  - Error Disclosure (CWE-209): ${errorVulns.length}`);
    console.log(`\nBy Severity:`);
    console.log(`  - Critical: ${criticalVulns.length}`);
    console.log(`  - High: ${highVulns.length}`);
    console.log(`  - Medium: ${mediumVulns.length}`);
    
    // Detailed output
    console.log('\n=== Detailed Vulnerability Report ===');
    vulnerabilities.forEach((vuln, index) => {
      console.log(`\n${index + 1}. ${vuln.title} [${vuln.severity}]`);
      console.log(`   CWE: ${vuln.cwe} | OWASP: ${vuln.owasp}`);
      console.log(`   URL: ${vuln.url}`);
      console.log(`   Description: ${vuln.description}`);
      if (vuln.evidence?.request?.body) {
        console.log(`   Payload: ${vuln.evidence.request.body.substring(0, 100)}`);
      }
    });

    // Simple success criteria - scanner should find something
    expect(vulnerabilities.length).toBeGreaterThan(0);
  });
});
