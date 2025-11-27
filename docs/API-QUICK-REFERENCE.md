# API Quick Reference

> Quick reference for Playwright Security Framework APIs

## Installation

```bash
npm install @tzigger/playwright-security --save-dev
```

---

## Core Classes

### ScanEngine

Main orchestrator for security scans.

```typescript
import { ScanEngine } from '@tzigger/playwright-security';

const engine = new ScanEngine();
engine.registerScanner(scanner);
engine.registerReporter(reporter);
await engine.loadConfiguration(config);
const results = await engine.scan();
await engine.cleanup();
```

**Methods**:
- `registerScanner(scanner: IScanner): void`
- `registerScanners(scanners: IScanner[]): void`
- `registerReporter(reporter: IReporter): void`
- `registerReporters(reporters: IReporter[]): void`
- `loadConfiguration(config: ScanConfiguration): Promise<void>`
- `loadConfigurationFromFile(filePath: string): Promise<void>`
- `scan(): Promise<ScanResult>`
- `cleanup(): Promise<void>`

**Events**:
- `scan:start` - Fired when scan begins
- `scan:complete` - Fired when scan finishes
- `vulnerability:found` - Fired when vulnerability detected

---

## Scanners

### ActiveScanner

Performs active testing with input manipulation.

```typescript
import { ActiveScanner } from '@tzigger/playwright-security';

const scanner = new ActiveScanner();
scanner.registerDetectors([detector1, detector2]);
engine.registerScanner(scanner);
```

**Methods**:
- `registerDetector(detector: IDetector): void`
- `registerDetectors(detectors: IDetector[]): void`
- `scan(context: ScanContext): Promise<Vulnerability[]>`

### PassiveScanner

Performs passive analysis via network traffic interception.

```typescript
import { PassiveScanner } from '@tzigger/playwright-security';

const scanner = new PassiveScanner();
scanner.registerDetectors([detector1, detector2]);
engine.registerScanner(scanner);
```

**Methods**:
- `registerDetector(detector: IDetector): void`
- `registerDetectors(detectors: IDetector[]): void`
- `scan(context: ScanContext): Promise<Vulnerability[]>`

---

## Detectors

### SqlInjectionDetector

```typescript
import { SqlInjectionDetector } from '@tzigger/playwright-security';

const detector = new SqlInjectionDetector();
scanner.registerDetector(detector);
```

**Properties**:
- `id`: `'sql-injection'`
- `category`: `VulnerabilityCategory.INJECTION`

### XssDetector

```typescript
import { XssDetector } from '@tzigger/playwright-security';

const detector = new XssDetector();
scanner.registerDetector(detector);
```

**Properties**:
- `id`: `'xss'`
- `category`: `VulnerabilityCategory.XSS`

### ErrorBasedDetector

```typescript
import { ErrorBasedDetector } from '@tzigger/playwright-security';

const detector = new ErrorBasedDetector();
scanner.registerDetector(detector);
```

**Properties**:
- `id`: `'error-disclosure'`
- `category`: `VulnerabilityCategory.INFORMATION_DISCLOSURE`

### SensitiveDataDetector (Passive)

```typescript
import { SensitiveDataDetector } from '@tzigger/playwright-security';

const detector = new SensitiveDataDetector();
passiveScanner.registerDetector(detector);
```

**Properties**:
- `id`: `'sensitive-data-exposure'`
- `category`: `VulnerabilityCategory.SENSITIVE_DATA_EXPOSURE`
- Detects: Emails, phone numbers, API tokens, credentials

### HeaderSecurityDetector (Passive)

```typescript
import { HeaderSecurityDetector } from '@tzigger/playwright-security';

const detector = new HeaderSecurityDetector();
passiveScanner.registerDetector(detector);
```

**Properties**:
- `id`: `'header-security'`
- `category`: `VulnerabilityCategory.SECURITY_MISCONFIGURATION`
- Detects: Missing HSTS, CSP, X-Frame-Options, X-Content-Type-Options, etc.

### CookieSecurityDetector (Passive)

```typescript
import { CookieSecurityDetector } from '@tzigger/playwright-security';

const detector = new CookieSecurityDetector();
passiveScanner.registerDetector(detector);
```

**Properties**:
- `id`: `'cookie-security'`
- `category`: `VulnerabilityCategory.SECURITY_MISCONFIGURATION`
- Detects: Missing Secure, HttpOnly, SameSite flags

### InsecureTransmissionDetector (Passive)

```typescript
import { InsecureTransmissionDetector } from '@tzigger/playwright-security';

const detector = new InsecureTransmissionDetector();
passiveScanner.registerDetector(detector);
```

**Properties**:
- `id`: `'insecure-transmission'`
- `category`: `VulnerabilityCategory.INSECURE_COMMUNICATION`
- Detects: HTTP transmission, mixed content

---

## Reporters

### JsonReporter

```typescript
import { JsonReporter } from '@tzigger/playwright-security';

engine.registerReporter(new JsonReporter());
```

**Output**: `scan-{id}.json`

### HtmlReporter

```typescript
import { HtmlReporter } from '@tzigger/playwright-security';

engine.registerReporter(new HtmlReporter());
```

**Output**: `scan-{id}.html`

### SarifReporter

```typescript
import { SarifReporter } from '@tzigger/playwright-security';

engine.registerReporter(new SarifReporter());
```

**Output**: `scan-{id}.sarif`

### ConsoleReporter

```typescript
import { ConsoleReporter } from '@tzigger/playwright-security';

engine.registerReporter(new ConsoleReporter());
```

**Output**: Console output

---

## Testing Helpers

### runActiveSecurityScan

Tests for injection vulnerabilities (SQLi, XSS, command injection, etc.).

```typescript
import { runActiveSecurityScan } from '@tzigger/playwright-security/testing';

const vulns = await runActiveSecurityScan(url, {
  detectors: 'all' | 'sql' | 'xss' | 'errors',
  aggressiveness: 'low' | 'medium' | 'high',
  maxPages: 5,
  headless: true
});
```

**Parameters**:
- `targetUrl: string` - URL to scan
- `options?: ActiveScanOptions`
  - `detectors?: 'all' | 'sql' | 'xss' | 'errors'` - Which detectors to use
  - `aggressiveness?: 'low' | 'medium' | 'high'` - Scan aggressiveness level
  - `maxPages?: number` - Maximum pages to scan (default: 5)
  - `headless?: boolean` - Run in headless mode (default: true)

**Returns**: `Promise<Vulnerability[]>`

**Performance**: 30-120 seconds depending on aggressiveness and pages

### runPassiveSecurityScan

Analyzes traffic patterns (headers, data exposure, cookies, transmission security).

```typescript
import { runPassiveSecurityScan } from '@tzigger/playwright-security/testing';

const vulns = await runPassiveSecurityScan(url, {
  detectors: 'all' | 'headers' | 'transmission' | 'data' | 'cookies',
  headless: true
});
```

**Parameters**:
- `targetUrl: string` - URL to scan
- `options?: PassiveScanOptions`
  - `detectors?: 'all' | 'headers' | 'transmission' | 'data' | 'cookies'` - Which detectors to use
  - `headless?: boolean` - Run in headless mode (default: true)

**Returns**: `Promise<Vulnerability[]>`

**Performance**: 3-5 seconds (very fast)

### assertNoVulnerabilities

```typescript
import { assertNoVulnerabilities, VulnerabilitySeverity } from '@tzigger/playwright-security/testing';

assertNoVulnerabilities(vulnerabilities, VulnerabilitySeverity.MEDIUM);
```

**Parameters**:
- `vulnerabilities: Vulnerability[]` - Array of vulnerabilities
- `maxAllowedSeverity?: VulnerabilitySeverity` - Maximum allowed severity (default: INFO)

**Throws**: `Error` if vulnerabilities above threshold found

---

## Types & Enums

### VulnerabilitySeverity

```typescript
enum VulnerabilitySeverity {
  INFO = 'info',
  LOW = 'low',
  MEDIUM = 'medium',
  HIGH = 'high',
  CRITICAL = 'critical'
}
```

### VulnerabilityCategory

```typescript
enum VulnerabilityCategory {
  INJECTION = 'injection',
  XSS = 'xss',
  AUTHENTICATION = 'authentication',
  AUTHORIZATION = 'authorization',
  SENSITIVE_DATA_EXPOSURE = 'sensitive-data-exposure',
  SECURITY_MISCONFIGURATION = 'security-misconfiguration',
  INFORMATION_DISCLOSURE = 'information-disclosure',
  INSECURE_COMMUNICATION = 'insecure-communication',
  // ... more
}
```

### AggressivenessLevel

```typescript
enum AggressivenessLevel {
  LOW = 'low',
  MEDIUM = 'medium',
  HIGH = 'high',
  AGGRESSIVE = 'aggressive'
}
```

### ReportFormat

```typescript
enum ReportFormat {
  JSON = 'json',
  HTML = 'html',
  SARIF = 'sarif',
  CONSOLE = 'console',
  MARKDOWN = 'markdown'
}
```

---

## Configuration

### Minimal Configuration

```typescript
const config: ScanConfiguration = {
  target: {
    url: 'https://myapp.com',
  },
  scanners: {
    active: { enabled: true },
    passive: { enabled: false }
  }
};
```

### Full Configuration

```typescript
const config: ScanConfiguration = {
  target: {
    url: 'https://myapp.com',
    crawlDepth: 2,
    maxPages: 50,
    timeout: 30000,
    authentication: {
      type: 'form',
      loginUrl: 'https://myapp.com/login',
      credentials: {
        username: 'user',
        password: 'pass'
      }
    },
    scope: {
      includePatterns: ['https://myapp.com/**'],
      excludePatterns: ['**/logout']
    }
  },
  scanners: {
    passive: {
      enabled: true,
      interceptTypes: ['xhr', 'fetch', 'document']
    },
    active: {
      enabled: true,
      aggressiveness: 'medium',
      submitForms: true
    }
  },
  detectors: {
    enabled: ['sql-injection', 'xss'],
    sensitivity: 'normal'
  },
  browser: {
    type: 'chromium',
    headless: true,
    timeout: 30000,
    viewport: { width: 1920, height: 1080 }
  },
  reporting: {
    formats: ['json', 'html'],
    outputDir: './reports',
    verbosity: 'detailed'
  },
  advanced: {
    parallelism: 3,
    logLevel: 'info'
  }
};
```

---

## Common Patterns

### Pattern 1: Basic Scan

```typescript
import { ScanEngine, ActiveScanner, SqlInjectionDetector } from '@tzigger/playwright-security';

const engine = new ScanEngine();
const scanner = new ActiveScanner();
scanner.registerDetector(new SqlInjectionDetector());
engine.registerScanner(scanner);

await engine.loadConfiguration({ target: { url: 'https://myapp.com' } });
const results = await engine.scan();
await engine.cleanup();
```

### Pattern 2: Playwright Test (Active Scan)

```typescript
import { test } from '@playwright/test';
import { runActiveSecurityScan, assertNoVulnerabilities } from '@tzigger/playwright-security/testing';

test('security scan - active', async ({ page }) => {
  await page.goto('https://myapp.com');
  const vulns = await runActiveSecurityScan(page.url(), {
    detectors: 'all',
    maxPages: 3
  });
  assertNoVulnerabilities(vulns);
});
```

### Pattern 2b: Playwright Test (Passive Scan)

```typescript
import { test } from '@playwright/test';
import { runPassiveSecurityScan, assertNoVulnerabilities, VulnerabilitySeverity } from '@tzigger/playwright-security/testing';

test('security scan - passive', async () => {
  const vulns = await runPassiveSecurityScan('https://myapp.com', {
    detectors: 'headers'
  });
  assertNoVulnerabilities(vulns, VulnerabilitySeverity.HIGH);
});
```

### Pattern 2c: Playwright Test (Combined)

```typescript
import { test } from '@playwright/test';
import { 
  runActiveSecurityScan, 
  runPassiveSecurityScan,
  assertNoVulnerabilities 
} from '@tzigger/playwright-security/testing';

test('full security scan', async () => {
  // Fast passive scan first
  const passiveVulns = await runPassiveSecurityScan('https://myapp.com');
  
  // Then deeper active scan
  const activeVulns = await runActiveSecurityScan('https://myapp.com', {
    aggressiveness: 'medium',
    maxPages: 3
  });
  
  const allVulns = [...passiveVulns, ...activeVulns];
  assertNoVulnerabilities(allVulns);
});
```

### Pattern 3: Custom Detector

```typescript
import { BaseDetector, VulnerabilityCategory, VulnerabilitySeverity } from '@tzigger/playwright-security';

class MyDetector extends BaseDetector {
  readonly id = 'my-detector';
  readonly name = 'My Custom Detector';
  readonly version = '1.0.0';
  readonly category = VulnerabilityCategory.CUSTOM;
  readonly description = 'Detects custom issues';
  
  async detect(data: unknown): Promise<Vulnerability[]> {
    // Detection logic
    return [];
  }
  
  getPatterns(): RegExp[] {
    return [/pattern/gi];
  }
}
```

### Pattern 4: Event Monitoring

```typescript
engine.on('vulnerability:found', (vuln) => {
  console.log(`Found: ${vuln.severity} - ${vuln.title}`);
});

engine.on('scan:complete', (results) => {
  console.log(`Scan complete. Found ${results.vulnerabilities.length} issues.`);
});
```

### Pattern 5: Filter Results

```typescript
const results = await engine.scan();

// Filter by severity
const critical = results.vulnerabilities.filter(v => 
  v.severity === VulnerabilitySeverity.CRITICAL
);

// Filter by category
const sqlInjections = results.vulnerabilities.filter(v => 
  v.category === VulnerabilityCategory.INJECTION
);

// Filter by confidence
const highConfidence = results.vulnerabilities.filter(v => 
  (v.confidence ?? 0) > 0.8
);
```

---

## CLI Usage

**Note**: Install globally with `npm link` or `sudo npm link` first. See [MIGRATION-GUIDE.md](./MIGRATION-GUIDE.md) for setup.

```bash
# Passive scan (fast, 3-5 seconds)
dast-scan https://myapp.com --scan-type passive

# Active scan (comprehensive, 30-120 seconds)
dast-scan https://myapp.com --scan-type active

# Both passive and active
dast-scan https://myapp.com --scan-type both

# With config file
dast-scan --config ./config/default.config.json

# Multiple formats
dast-scan https://myapp.com --formats json,html,sarif

# Specify output directory
dast-scan https://myapp.com --output ./security-reports

# Parallel scanners
dast-scan https://myapp.com --parallel 4
```

**Available Flags**:
- `--scan-type <type>` - Scan type: active, passive, or both (default: active)
- `--passive` - Enable passive scanning
- `--active` - Enable active scanning (default: true)
- `-o, --output <dir>` - Output directory (default: ./reports)
- `-f, --formats <list>` - Report formats: console,json,html,sarif (default: console,json,html)
- `-c, --config <file>` - Load configuration from file
- `--headless` - Run headless browser (default: true)
- `--parallel <n>` - Number of parallel scanners (default: 2)

---

## Imports Cheat Sheet

```typescript
// Core
import { ScanEngine, BrowserManager, ConfigurationManager } from '@tzigger/playwright-security';

// Scanners
import { ActiveScanner, PassiveScanner } from '@tzigger/playwright-security';

// Active Detectors
import { SqlInjectionDetector, XssDetector, ErrorBasedDetector } from '@tzigger/playwright-security';

// Passive Detectors
import { 
  SensitiveDataDetector, 
  HeaderSecurityDetector, 
  CookieSecurityDetector, 
  InsecureTransmissionDetector 
} from '@tzigger/playwright-security';

// Reporters
import { JsonReporter, HtmlReporter, SarifReporter, ConsoleReporter } from '@tzigger/playwright-security';

// Testing Helpers
import { 
  runActiveSecurityScan, 
  runPassiveSecurityScan, 
  assertNoVulnerabilities, 
  VulnerabilitySeverity 
} from '@tzigger/playwright-security/testing';

// Types
import type { 
  Vulnerability, 
  ScanConfiguration, 
  ScanResult,
  IDetector,
  IReporter,
  IScanner 
} from '@tzigger/playwright-security';

// Enums
import { 
  VulnerabilitySeverity, 
  VulnerabilityCategory,
  AggressivenessLevel,
  ReportFormat 
} from '@tzigger/playwright-security';
```

---

## Error Handling

```typescript
try {
  const engine = new ScanEngine();
  
  // Register components
  engine.registerScanner(scanner);
  
  // Load config
  await engine.loadConfiguration(config);
  
  // Run scan
  const results = await engine.scan();
  
} catch (error) {
  if (error.message.includes('No scanners registered')) {
    console.error('Register at least one scanner');
  } else if (error.message.includes('No configuration loaded')) {
    console.error('Load configuration first');
  } else {
    console.error('Scan failed:', error);
  }
} finally {
  await engine.cleanup();
}
```

---

## Best Practices

✅ **Do**:
- Always call `cleanup()` after scanning
- Use environment variables for credentials
- Define clear scope patterns
- Start with low aggressiveness
- Filter by confidence score

❌ **Don't**:
- Hardcode credentials
- Scan production without permission
- Skip cleanup
- Run aggressive scans on live systems
- Ignore INFO/LOW severity issues

---

## Support

- 📖 Full Guide: [DEVELOPER-GUIDE.md](./DEVELOPER-GUIDE.md)
- 🐛 Issues: https://github.com/Tzigger/playwright_security/issues
- 💬 Discussions: https://github.com/Tzigger/playwright_security/discussions
