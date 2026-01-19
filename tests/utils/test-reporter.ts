/**
 * Test Reporter Utilities
 * 
 * Integration helpers for recording vulnerabilities during Playwright tests
 * and generating security reports at the end of test runs.
 */

import { TestInfo } from '@playwright/test';
import { Vulnerability } from '../../src/types/vulnerability';
import { 
  SecurityReportGenerator, 
  SecurityReportGeneratorOptions,
  getSecurityReporter,
  resetSecurityReporter 
} from '../../src/reporters/SecurityReportGenerator';
import { TestContext, SecurityFinding } from '../../src/types/SecurityReport';

export { SecurityReportGenerator, getSecurityReporter, resetSecurityReporter };
export type { SecurityReportGeneratorOptions, TestContext, SecurityFinding };

/**
 * Record a vulnerability finding with Playwright test context
 */
export function recordVulnerability(
  vulnerability: Vulnerability,
  testInfo: TestInfo,
  options?: {
    scanner?: string;
    detector?: string;
  }
): SecurityFinding {
  const reporter = getSecurityReporter();
  
  return reporter.addFinding(vulnerability, {
    testName: testInfo.title,
    testFile: testInfo.file,
    scanner: options?.scanner,
    detector: options?.detector || vulnerability.detectorId,
  });
}

/**
 * Record multiple vulnerabilities from a scan result
 */
export function recordVulnerabilities(
  vulnerabilities: Vulnerability[],
  testInfo: TestInfo,
  options?: {
    scanner?: string;
    detector?: string;
  }
): SecurityFinding[] {
  return vulnerabilities.map(vuln => recordVulnerability(vuln, testInfo, options));
}

/**
 * Save reports at end of test run
 * Use this in test.afterAll() hook
 */
export async function saveSecurityReports(
  outputDir: string = 'test-results',
  baseName: string = 'security-report'
): Promise<{ json: string; html: string } | null> {
  const reporter = getSecurityReporter();
  
  if (reporter.count === 0) {
    console.log('📊 No vulnerabilities to report');
    return null;
  }
  
  const paths = await reporter.saveReports(outputDir, baseName);
  console.log(`📊 Security reports saved:`);
  console.log(`   JSON: ${paths.json}`);
  console.log(`   HTML: ${paths.html}`);
  
  return paths;
}

/**
 * Initialize a new security reporter for a test suite
 */
export function initSecurityReporter(options?: SecurityReportGeneratorOptions): SecurityReportGenerator {
  resetSecurityReporter();
  return getSecurityReporter(options);
}

/**
 * Log a summary of findings to console
 */
export function logSecuritySummary(): void {
  const reporter = getSecurityReporter();
  const report = reporter.generateReport();
  
  console.log('\n' + '='.repeat(60));
  console.log(`🛡️  SECURITY SCAN SUMMARY`);
  console.log('='.repeat(60));
  console.log(`Target: ${report.target}`);
  console.log(`Total Findings: ${report.summary.total}`);
  
  if (report.summary.total > 0) {
    console.log('\nBy Severity:');
    for (const [severity, count] of Object.entries(report.summary.bySeverity)) {
      const emoji = severity === 'critical' ? '🔴' :
                    severity === 'high' ? '🟠' :
                    severity === 'medium' ? '🟡' :
                    severity === 'low' ? '🔵' : '⚪';
      console.log(`  ${emoji} ${severity.toUpperCase()}: ${count}`);
    }
    
    if (Object.keys(report.summary.byOWASP).length > 0) {
      console.log('\nBy OWASP 2025 Category:');
      for (const [category, count] of Object.entries(report.summary.byOWASP)) {
        console.log(`  📋 ${category}: ${count}`);
      }
    }
  } else {
    console.log('\n✅ No vulnerabilities detected!');
  }
  
  console.log('='.repeat(60) + '\n');
}
