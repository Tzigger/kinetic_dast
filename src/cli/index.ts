#!/usr/bin/env node
import { Command } from 'commander';
import * as readline from 'readline';

import { ConfigurationManager } from '../core/config/ConfigurationManager';
import { ScanEngine } from '../core/engine/ScanEngine';
import { ActiveScanner } from '../scanners/active/ActiveScanner';
import { PassiveScanner } from '../scanners/passive/PassiveScanner';
import { ScanConfiguration } from '../types/config';
import {
  AggressivenessLevel,
  AuthType,
  BrowserType,
  LogLevel,
  ReportFormat,
  VerbosityLevel,
} from '../types/enums';
import { DetectorRegistry } from '../utils/DetectorRegistry';
import { registerBuiltInDetectors } from '../utils/builtInDetectors';

type CliScanType = 'active' | 'passive' | 'both';

interface CliOptions {
  config?: string;
  output?: string;
  formats: string;
  headless: boolean;
  parallel: string;
  scanType: CliScanType;
  safemodeDisable: boolean;
  auth?: string;
}

const program = new Command();

program
  .name('kinetic')
  .version('0.2.0')
  .description('Kinetic - High-performance DAST security scanner')
  .argument('[url]', 'Target URL to scan')
  .option('-c, --config <file>', 'Load configuration from file')
  .option('-o, --output <dir>', 'Output directory for reports', 'reports')
  .option('-f, --formats <list>', 'Comma-separated report formats (console,json,html,sarif)', 'console,json,html')
  .option('--headless', 'Run headless browser', true)
  .option('--no-headless', 'Run visible browser') // Allow --no-headless flag
  .option('--parallel <n>', 'Parallel scanners count', '2')
  .option('--scan-type <type>', 'Scan type: active, passive, or both', 'active')
  .option('--safemode-disable', 'Disable Safe Mode (Allow dangerous payloads)', false)
  .option('--auth <credentials>', 'Basic auth credentials (username:password)')
  .option('--detectors <list>', 'Comma-separated list of detectors to enable (e.g. xss,sqli)')
  .action(async (url: string | undefined, options: CliOptions & { detectors?: string }) => {
    try {
      const configManager = ConfigurationManager.getInstance();
      let config: ScanConfiguration;

      // 1. Încărcare Configurație (File vs CLI)
      if (options.config) {
        await configManager.loadFromFile(options.config);
        config = configManager.getConfig();
        
        // Override URL from CLI if provided
        if (url) {
            config.target.url = url;
        }

        // Override Auth from CLI
        if (options.auth) {
             const [username, password] = options.auth.split(':');
             config.target.authentication = {
                type: AuthType.FORM,
                credentials: { username, password: password || '' }
             };
        }

        // Override Detectors from CLI
        if (options.detectors) {
            config.detectors.enabled = options.detectors.split(',').map(d => d.trim());
        }
      } else {
        if (!url) {
          console.error('Error: URL required when not using --config');
          process.exit(1);
        }

        // Construire config default din parametrii CLI
        const isPassive = options.scanType === 'passive' || options.scanType === 'both';
        const isActive = options.scanType === 'active' || options.scanType === 'both';

        config = {
          target: { 
            url,
            authentication: options.auth ? {
                type: AuthType.FORM,
                credentials: {
                    username: options.auth.split(':')[0],
                    password: options.auth.split(':')[1] || ''
                }
            } : undefined
          },
          browser: {
            type: BrowserType.CHROMIUM,
            headless: options.headless,
            slowMo: 0,
          },
          scanners: {
            active: {
              enabled: isActive,
              safeMode: !options.safemodeDisable, // CLI flag overrides default
              aggressiveness: AggressivenessLevel.MEDIUM,
              maxDepth: 2,
              maxPages: 10,
            },
            passive: {
              enabled: isPassive,
              downloads: true,
            },
          },
          reporting: {
            formats: options.formats.split(',') as ReportFormat[],
            outputDir: options.output || 'reports',
            verbosity: VerbosityLevel.NORMAL,
          },
          advanced: {
            parallelism: parseInt(options.parallel, 10) || 2,
            logLevel: LogLevel.INFO,
          },
          detectors: {
            // Keep defaults stable: only enable detectors that are enabled-by-default.
            // Optional detectors (e.g., ssrf/path-traversal/command-injection) must be enabled explicitly.
            enabled: options.detectors 
                ? options.detectors.split(',').map(d => d.trim())
                : [
                  'sql-injection',
                  'sqlmap',
                  'xss',
                  'error-based',
                  'sensitive-data',
                  'header-security',
                  'cookie-security',
                  'insecure-transmission',
                ],
            disabled: [],
            tuning: {}
          }
        };
        configManager.loadFromObject(config);
      }

      console.log(`🚀 Starting Kinetic Scan against: ${config.target.url}`);
      console.log(`Enabled Detectors: ${config.detectors.enabled.join(', ')}`);
      if (!config.scanners.active.safeMode) {
          console.warn(`⚠️  WARNING: Safe Mode is DISABLED. Destructive payloads may be used.`);
      }

      // 2. Inițializare Engine și Registri
      registerBuiltInDetectors(); // Încărcăm detectoarele disponibile (SQLi, XSS, etc.)
      const registry = DetectorRegistry.getInstance();
      const engine = new ScanEngine();

      engine.setInteractionHandler({
        askQuestion: (query: string): Promise<boolean> => {
            const rl = readline.createInterface({
                input: process.stdin,
                output: process.stdout,
            });

            return new Promise((resolve) => {
                rl.question(`${query} (y/n) `, (answer) => {
                    rl.close();
                    resolve(answer.toLowerCase() === 'y' || answer.toLowerCase() === 'yes');
                });
            });
        }
      });

      // 3. Configurare Active Scanner (The Big One)
      if (config.scanners.active?.enabled) {
        const activeScanner = new ActiveScanner();
        
        // Luăm detectoarele din registry bazat pe config (enabled/disabled)
        const activeDetectors = registry.getActiveDetectors(config.detectors);
        
        if (activeDetectors.length === 0) {
            console.warn('⚠️  Active Scanner enabled but no detectors matched configuration!');
        } else {
            activeScanner.registerDetectors(activeDetectors);
            engine.registerScanner(activeScanner);
            console.log(`✅ Loaded Active Scanner with ${activeDetectors.length} detectors`);
        }
      }

      // 4. Configurare Passive Scanner
      if (config.scanners.passive?.enabled) {
        const passiveScanner = new PassiveScanner();
        const passiveDetectors = registry.getPassiveDetectors(config.detectors);
        
        passiveScanner.registerDetectors(passiveDetectors);
        engine.registerScanner(passiveScanner);
        console.log(`✅ Loaded Passive Scanner with ${passiveDetectors.length} detectors`);
      }

      // 5. Execuție
      await engine.loadConfiguration(config);
      const results = await engine.scan();
      
      // Afișare sumară finală
      console.log(`\n🏁 Scan Completed in ${(results.duration / 1000).toFixed(2)}s`);
      console.log(`📊 Total Vulnerabilities: ${results.summary.total}`);
      console.log(`🔴 Critical: ${results.summary.critical} | 🟠 High: ${results.summary.high}`);

      await engine.cleanup();

      // Exit code bazat pe vulnerabilități critice (pentru CI/CD)
      if (results.summary.critical > 0) {
          process.exit(1);
      } else {
          process.exit(0);
      }

    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      console.error('\n💥 Critical Error:', message);
      process.exit(1);
    }
  });

void program.parseAsync(process.argv);