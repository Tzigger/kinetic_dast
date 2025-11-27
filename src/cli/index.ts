#!/usr/bin/env node
import { Command } from 'commander';

import { ConfigurationManager } from '../core/config/ConfigurationManager';
import { ScanEngine } from '../core/engine/ScanEngine';
import { ErrorBasedDetector } from '../detectors/active/ErrorBasedDetector';
import { SqlInjectionDetector } from '../detectors/active/SqlInjectionDetector';
import { XssDetector } from '../detectors/active/XssDetector';
import { ActiveScanner } from '../scanners/active/ActiveScanner';
import { ScanConfiguration } from '../types/config';
import { AggressivenessLevel, AuthType, BrowserType, LogLevel, ReportFormat, VerbosityLevel } from '../types/enums';

const program = new Command();

program
  .name('dast-scan')
  .description('Run a DAST scan with Playwright Security')
  .argument('[url]', 'Target URL to scan (optional if using --config)')
  .option('-c, --config <file>', 'Load configuration from file')
  .option('-o, --output <dir>', 'Output directory for reports', 'reports')
  .option('-f, --formats <list>', 'Comma-separated report formats (console,json,html,sarif)', 'console,json,html')
  .option('--headless', 'Run headless browser', true)
  .option('--parallel <n>', 'Parallel scanners', '2')
  .action(async (url: string | undefined, options: any) => {
    const configManager = ConfigurationManager.getInstance();
    let config: ScanConfiguration;

    // Load from config file if provided
    if (options.config) {
      try {
        config = await configManager.loadFromFile(options.config);
      } catch (error) {
        // eslint-disable-next-line no-console
        console.error(`Error loading configuration: ${error}`);
        process.exit(1);
      }
      
      // CLI args override config file
      const overrides: any = {};
      if (url) {
        overrides.target = { ...config.target, url };
      }
      if (options.output) {
        overrides.reporting = { ...config.reporting, outputDir: options.output };
      }
      if (options.formats) {
        const formats = String(options.formats)
          .split(',')
          .map((s: string) => s.trim().toLowerCase()) as ReportFormat[];
        overrides.reporting = { ...config.reporting, ...overrides.reporting, formats };
      }
      if (options.parallel) {
        overrides.advanced = { ...config.advanced, parallelism: parseInt(options.parallel, 10) || 2 };
      }

      config = configManager.mergeConfig(overrides);
    } else {
      // ... build config manually as before, but ideally use ConfigurationManager for defaults/validation too
      // For now, keep existing logic but ensure it's loaded into manager
      if (!url) {
        // eslint-disable-next-line no-console
        console.error('Error: URL required when not using --config');
        process.exit(1);
      }

      const formats = String(options.formats)
        .split(',')
        .map((s: string) => s.trim().toLowerCase())
        .map((s: string) => s as unknown as ReportFormat);

      config = {
        target: {
          url,
          authentication: { type: AuthType.NONE },
          crawlDepth: 1,
          maxPages: 5,
          timeout: 30000,
        },
        scanners: {
          passive: { enabled: false },
          active: {
            enabled: true,
            aggressiveness: AggressivenessLevel.MEDIUM,
            submitForms: true,
          },
        },
        detectors: {
          enabled: [],
          sensitivity: 'normal' as any,
        },
        browser: {
          type: BrowserType.CHROMIUM,
          headless: options.headless !== false,
          timeout: 30000,
          viewport: { width: 1280, height: 800 },
        },
        reporting: {
          formats: formats,
          outputDir: options.output,
          verbosity: VerbosityLevel.NORMAL,
        },
        advanced: {
          parallelism: parseInt(options.parallel, 10) || 2,
          logLevel: LogLevel.INFO,
        },
      };
      // Validate and load manual config
      configManager.loadFromObject(config);
    }

    const engine = new ScanEngine();

    // Prepare ActiveScanner with default detectors
    const active = new ActiveScanner();
    active.registerDetectors([
      new SqlInjectionDetector(),
      new XssDetector(),
      new ErrorBasedDetector(),
    ]);

    engine.registerScanner(active);
    await engine.loadConfiguration(config);
    await engine.scan();
    await engine.cleanup();
  });

program.parseAsync(process.argv).catch((err) => {
  // eslint-disable-next-line no-console
  console.error(err);
  process.exit(1);
});
