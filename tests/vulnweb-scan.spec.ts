import { test, expect } from '@playwright/test';
import { 
  runActiveSecurityScan, 
  runPassiveSecurityScan, 
  VulnerabilitySeverity,
  AggressivenessLevel 
} from '../src/testing/helpers';

// 1. Simple Scan Scenario - Regular Site
test('Scenario 1: Simple Active Scan on testphp.vulnweb.com', async () => {
  test.setTimeout(180000); // Active scans can take 2-3 mins
  
  console.log('Starting Simple Active Scan...');
  const vulnerabilities = await runActiveSecurityScan('http://testphp.vulnweb.com/', {
    detectors: 'all',
    aggressiveness: AggressivenessLevel.LOW,
    maxPages: 2, // Keep it minimal for fast feedback
    headless: true
  });

  console.log(`Simple Scan found ${vulnerabilities.length} vulnerabilities`);
  if (vulnerabilities.length > 0) {
    console.log('Sample Vulnerability:', vulnerabilities[0].title);
  }

  // Expect at least some vulnerabilities on this intentionally vulnerable site
  expect(vulnerabilities.length).toBeGreaterThan(0);
});

// 1b. SPA Site with Hash Routing - Passive Scan Only
test('Scenario 1b: Scan SPA site (testhtml5.vulnweb.com)', async () => {
  test.setTimeout(30000); // Passive scans are fast
  
  console.log('Starting SPA Passive Scan (optimized for SPAs)...');
  
  const vulnerabilities = await runPassiveSecurityScan('http://testhtml5.vulnweb.com/#/popular', {
    detectors: 'data', // Focus on sensitive data exposure
    headless: true
  });

  console.log(`SPA Scan found ${vulnerabilities.length} vulnerabilities`);
  if (vulnerabilities.length > 0) {
    vulnerabilities.slice(0, 3).forEach(v => {
      console.log(`- ${v.severity}: ${v.title}`);
    });
  }

  expect(vulnerabilities.length).toBeGreaterThan(0);
});

// 2. Advanced Scan Scenario - Combined Active + Passive
test('Scenario 2: Advanced Passive + Active Scan on testphp.vulnweb.com', async () => {
  test.setTimeout(180000); // Allow 3 mins

  console.log('Running Passive Scan first...');
  const passiveVulns = await runPassiveSecurityScan('http://testphp.vulnweb.com/', {
    detectors: 'all',
    headless: true
  });
  
  console.log(`Passive scan found ${passiveVulns.length} vulnerabilities`);

  console.log('Running Active Scan...');
  const activeVulns = await runActiveSecurityScan('http://testphp.vulnweb.com/', {
    detectors: 'all',
    aggressiveness: AggressivenessLevel.MEDIUM,
    maxPages: 3,
    headless: true
  });
  
  console.log(`Active scan found ${activeVulns.length} vulnerabilities`);

  // Combine results
  const allVulns = [...passiveVulns, ...activeVulns];
  const summary = {
    total: allVulns.length,
    critical: allVulns.filter(v => v.severity === VulnerabilitySeverity.CRITICAL).length,
    high: allVulns.filter(v => v.severity === VulnerabilitySeverity.HIGH).length,
    medium: allVulns.filter(v => v.severity === VulnerabilitySeverity.MEDIUM).length,
    low: allVulns.filter(v => v.severity === VulnerabilitySeverity.LOW).length,
  };

  console.log(`Total vulnerabilities found: ${summary.total}`);
  console.log('Summary:', JSON.stringify(summary, null, 2));

  expect(summary.total).toBeGreaterThan(0);
  expect(passiveVulns.length).toBeGreaterThan(0);
  expect(activeVulns.length).toBeGreaterThan(0);
});