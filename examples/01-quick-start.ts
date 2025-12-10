/**
 * Kinetic DAST - Quick Start Example
 * 
 * The simplest way to run a security scan against a target URL.
 * This example uses the built-in helper functions for immediate results.
 * 
 * Prerequisites:
 *   1. Build the project: npm run build
 *   2. Run: npx ts-node examples/01-quick-start.ts
 * 
 * What it does:
 *   - Runs a passive scan (checks headers, cookies, data exposure)
 *   - Runs an active scan (tests for SQLi, XSS, etc.)
 *   - Reports findings by severity
 */

import { 
  runPassiveSecurityScan, 
  runActiveSecurityScan,
  VulnerabilitySeverity 
} from '../src/testing/helpers';

const TARGET_URL = 'http://testphp.vulnweb.com';

async function main() {
  console.log('🔒 Kinetic DAST - Quick Start Example\n');
  console.log(`Target: ${TARGET_URL}\n`);

  // Step 1: Run a fast passive scan (checks headers, cookies, insecure data)
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log('STEP 1: Passive Scan (Fast, Non-Intrusive)');
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');
  
  const passiveVulns = await runPassiveSecurityScan(TARGET_URL, {
    headless: true
  });
  
  console.log(`✅ Passive scan found ${passiveVulns.length} issues\n`);
  passiveVulns.slice(0, 5).forEach(v => {
    console.log(`  [${v.severity}] ${v.title}`);
  });

  // Step 2: Run an active scan (tests inputs for vulnerabilities)
  console.log('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log('STEP 2: Active Scan (Tests for SQLi, XSS, etc.)');
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');
  
  const activeVulns = await runActiveSecurityScan(TARGET_URL, {
    maxPages: 2,       // Limit for quick test
    aggressiveness: 'low',
    headless: true
  });
  
  console.log(`✅ Active scan found ${activeVulns.length} vulnerabilities\n`);
  activeVulns.slice(0, 5).forEach(v => {
    console.log(`  [${v.severity}] ${v.title}`);
    console.log(`     URL: ${v.url}`);
  });

  // Step 3: Generate summary
  console.log('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log('SUMMARY');
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');
  
  const allVulns = [...passiveVulns, ...activeVulns];
  const summary = {
    total: allVulns.length,
    critical: allVulns.filter(v => v.severity === VulnerabilitySeverity.CRITICAL).length,
    high: allVulns.filter(v => v.severity === VulnerabilitySeverity.HIGH).length,
    medium: allVulns.filter(v => v.severity === VulnerabilitySeverity.MEDIUM).length,
    low: allVulns.filter(v => v.severity === VulnerabilitySeverity.LOW).length,
  };

  console.log(`  Total Issues: ${summary.total}`);
  console.log(`  🔴 Critical:  ${summary.critical}`);
  console.log(`  🟠 High:      ${summary.high}`);
  console.log(`  🟡 Medium:    ${summary.medium}`);
  console.log(`  🟢 Low:       ${summary.low}`);
  console.log('\n✨ Scan complete!\n');
}

main().catch(console.error);
