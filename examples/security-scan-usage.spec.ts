import { test, expect } from '@playwright/test';
import { runSecurityScan, VulnerabilitySeverity } from '../src/testing/helpers';
import { ScanEngine } from '../src/core/engine/ScanEngine';
import { ActiveScanner } from '../src/scanners/active/ActiveScanner';
import { ScanConfiguration } from '../src/types/config';
import { AuthType, BrowserType, LogLevel, ReportFormat, VerbosityLevel, AggressivenessLevel } from '../src/types/enums';

// Example 1: Simple Scan using the helper function
// This is the easiest way to add security testing to existing specs
test.describe('Simple Security Scan Example', () => {
  test('should detect vulnerabilities on a target page', async ({ page }) => {
    // 1. Navigate to the target URL
    // In a real scenario, this would be your localhost or staging URL
    // e.g., await page.goto('http://localhost:3000');
    await page.goto('https://example.com');

    // 2. Run the security scan
    // The helper abstracts away the engine setup
    const vulnerabilities = await runSecurityScan(page.url(), {
      detectors: 'all', // 'all', 'sql', 'xss', or 'errors'
      maxPages: 3       // Limit crawl depth for speed
    });

    // 3. Assert/Report results
    console.log(`Found ${vulnerabilities.length} vulnerabilities`);
    
    // Example assertion: Fail if any Critical vulnerabilities are found
    const criticals = vulnerabilities.filter(v => v.severity === VulnerabilitySeverity.CRITICAL);
    expect(criticals.length, 'Should have zero critical vulnerabilities').toBe(0);
  });
});

// Example 2: Advanced Scan using ScanEngine directly
// Use this when you need full control over configuration, plugins, and reporting
test.describe('Advanced Security Scan Example', () => {
  test('should run a custom active scan with specific configuration', async () => {
    // 1. Define comprehensive configuration
    const config: ScanConfiguration = {
      target: {
        url: 'https://example.com',
        authentication: { type: AuthType.NONE },
        crawlDepth: 2,
        maxPages: 10,
        timeout: 30000,
      },
      // Configure scanners specifically
      scanners: {
        passive: { enabled: true }, // Listen to network traffic
        active: {
          enabled: true,
          aggressiveness: AggressivenessLevel.LOW, // Be gentle
          submitForms: false, // Don't submit forms automatically in this run
        },
      },
      // Customize browser behavior
      browser: {
        type: BrowserType.CHROMIUM,
        headless: true,
        timeout: 30000,
      },
      // Setup reporting
      reporting: {
        formats: [ReportFormat.JSON, ReportFormat.CONSOLE],
        outputDir: './security-reports',
        verbosity: VerbosityLevel.NORMAL,
      },
      advanced: {
        parallelism: 2, // Run scanners in parallel
        logLevel: LogLevel.INFO,
      },
    };

    // 2. Initialize Engine and Scanners
    const engine = new ScanEngine();
    const activeScanner = new ActiveScanner();
    
    // Optionally register specific detectors if needed (default ActiveScanner includes standard set)
    // activeScanner.registerDetector(new MyCustomDetector());

    engine.registerScanner(activeScanner);

    // 3. Load Configuration
    await engine.loadConfiguration(config);

    // 4. Execute Scan
    console.log('Starting advanced scan...');
    const result = await engine.scan();
    
    // 5. Cleanup
    await engine.cleanup();

    // 6. Analyze Results
    console.log(`Scan completed. Duration: ${result.duration}ms`);
    console.log(`Total Vulnerabilities: ${result.summary.total}`);
    
    expect(result.status).toBe('completed');
  });
});
