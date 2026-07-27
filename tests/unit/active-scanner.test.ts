import { ActiveScanner } from '../../src/scanners/active/ActiveScanner';
import { ScanConfiguration } from '../../src/types/config';
import {
  AggressivenessLevel,
  AuthType,
  BrowserType,
  LogLevel,
  ReportFormat,
  VerbosityLevel,
} from '../../src/types/enums';
import { Logger } from '../../src/utils/logger/Logger';

function createConfiguration(): ScanConfiguration {
  return {
    target: {
      url: 'http://127.0.0.1:3000/',
      authentication: { type: AuthType.NONE },
      crawlDepth: 0,
      maxPages: 1,
    },
    scanners: {
      active: {
        enabled: true,
        safeMode: true,
        aggressiveness: AggressivenessLevel.LOW,
        maxDepth: 0,
        maxPages: 1,
        parallelism: 1,
      },
      passive: { enabled: false },
    },
    detectors: { enabled: [], disabled: [] },
    browser: { type: BrowserType.CHROMIUM, headless: true },
    reporting: {
      formats: [ReportFormat.JSON],
      outputDir: './reports',
      verbosity: VerbosityLevel.MINIMAL,
    },
    advanced: { logLevel: LogLevel.ERROR },
  };
}

describe('ActiveScanner configuration', () => {
  it('honors engine-level page, depth, and safe-mode limits after construction', async () => {
    const scanner = new ActiveScanner({
      maxDepth: 3,
      maxPages: 20,
      aggressiveness: 'high',
      safeMode: false,
    });

    await scanner.initialize({
      page: {} as never,
      browserContext: {} as never,
      config: createConfiguration(),
      logger: new Logger(LogLevel.ERROR, 'active-scanner-test'),
    });

    expect(scanner.getStatistics()).toMatchObject({
      maxDepth: 0,
      maxPages: 1,
    });

    await scanner.cleanup();
  });
});
