/**
 * Simple example demonstrating the Playwright Security Framework
 * This file shows how to:
 * 1. Create a scan engine
 * 2. Register scanners and detectors
 * 3. Run a scan
 * 4. Process results
 */

import { ScanEngine } from '../src/core/engine/ScanEngine';
import { PassiveScanner } from '../src/scanners/passive/PassiveScanner';
import { HeaderSecurityDetector } from '../src/detectors/passive/HeaderSecurityDetector';
import { InsecureTransmissionDetector } from '../src/detectors/passive/InsecureTransmissionDetector';
import { AggressivenessLevel, SensitivityLevel, LogLevel, ReportFormat, VerbosityLevel } from '../src/types/enums';

async function main() {
  console.log('🔒 Playwright Security Framework - Simple Test\n');

  // 1. Create the scan engine
  const engine = new ScanEngine();
  
  // 2. Create and configure passive scanner
  const scanner = new PassiveScanner();
  scanner.registerDetector(new HeaderSecurityDetector());
  scanner.registerDetector(new InsecureTransmissionDetector());
  
  // 3. Register scanner (no reporter for this simple test)
  engine.registerScanner(scanner);
  
  // 4. Configure the scan
  const config = {
    target: {
      url: 'http://testphp.vulnweb.com', // Public vulnerable test site
      maxPages: 3,
      timeout: 30000
    },
    scanners: {
      passive: { 
        enabled: true,
        interceptTypes: ['document', 'xhr', 'fetch'] as ('document' | 'xhr' | 'fetch' | 'websocket')[]
      },
      active: { 
        enabled: false,
        aggressiveness: AggressivenessLevel.LOW
      },
    },
    detectors: {
      enabled: ['all'],
      sensitivity: SensitivityLevel.NORMAL
    },
    browser: {
      headless: true,
      type: 'chromium' as const
    },
    reporting: {
      formats: [ReportFormat.JSON],
      outputDir: './reports',
      verbosity: VerbosityLevel.DETAILED
    },
    advanced: {
      parallelism: 1,
      logLevel: LogLevel.INFO
    }
  };
  
  await engine.loadConfiguration(config);
  
  // 5. Run the scan
  console.log('🔍 Starting security scan...\n');
  console.log(`Target: ${config.target.url}`);
  console.log(`Max Pages: ${config.target.maxPages}`);
  console.log(`Scanner: Passive (Header Security, Insecure Transmission)\n`);
  
  const startTime = Date.now();
  const results = await engine.scan();
  const duration = ((Date.now() - startTime) / 1000).toFixed(2);
  
  // 6. Display results
  console.log('\n✅ Scan Complete!\n');
  console.log('📊 Results:');
  console.log(`  Duration: ${duration}s`);
  console.log(`  Target URL: ${results.targetUrl}`);
  console.log(`  Vulnerabilities Found: ${results.vulnerabilities.length}`);
  
  if (results.vulnerabilities.length > 0) {
    console.log('\n⚠️  Vulnerabilities Detected:');
    results.vulnerabilities.forEach((vuln: any, idx: number) => {
      console.log(`\n  ${idx + 1}. ${vuln.title}`);
      console.log(`     Severity: ${vuln.severity.toUpperCase()}`);
      console.log(`     Category: ${vuln.category}`);
      console.log(`     URL: ${vuln.url || 'N/A'}`);
    });
  } else {
    console.log('\n✨ No vulnerabilities detected!');
  }
  
  // 7. Cleanup
  await engine.cleanup();
  
  console.log('\n🎉 Test completed successfully!');
}

// Run the example
main().catch(error => {
  console.error('❌ Error:', error.message);
  process.exit(1);
});
