# Developer Guide: Using Playwright Security Framework

> Complete guide for integrating Playwright Security Framework into your projects

## Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [Core Concepts](#core-concepts)
- [API Reference](#api-reference)
- [Testing Integration](#testing-integration)
- [Custom Detectors](#custom-detectors)
- [Custom Reporters](#custom-reporters)
- [Advanced Usage](#advanced-usage)
- [Best Practices](#best-practices)
- [Examples](#examples)

---

## Installation

### Install from NPM

```bash
npm install @tzigger/playwright-security --save-dev
```

### Install from GitHub

```bash
npm install github:Tzigger/playwright_security --save-dev
```

### Peer Dependencies

The framework requires:
- `playwright` >= 1.40.0
- `@playwright/test` >= 1.40.0 (for testing integration)

```bash
npm install playwright @playwright/test --save-dev
```

---

## Quick Start

### 1. Basic Security Scan

```typescript
import { ScanEngine, ActiveScanner, SqlInjectionDetector, XssDetector } from '@tzigger/playwright-security';
import { ScanConfiguration, VulnerabilitySeverity } from '@tzigger/playwright-security/types';

async function scanWebsite(url: string) {
  // Create scan engine
  const engine = new ScanEngine();
  
  // Create and register scanner
  const scanner = new ActiveScanner();
  scanner.registerDetectors([
    new SqlInjectionDetector(),
    new XssDetector()
  ]);
  engine.registerScanner(scanner);
  
  // Configure scan
  const config: ScanConfiguration = {
    target: { url },
    scanners: { 
      active: { enabled: true, aggressiveness: 'medium' },
      passive: { enabled: false }
    },
    // ... other config options
  };
  
  await engine.loadConfiguration(config);
  
  // Run scan
  const result = await engine.scan();
  
  // Process results
  console.log(`Found ${result.vulnerabilities.length} vulnerabilities`);
  
  // Cleanup
  await engine.cleanup();
  
  return result;
}
```

### 2. Playwright Test Integration

```typescript
import { test, expect } from '@playwright/test';
import { 
  runActiveSecurityScan, 
  runPassiveSecurityScan,
  assertNoVulnerabilities, 
  VulnerabilitySeverity 
} from '@tzigger/playwright-security/testing';

test.describe('Security Tests', () => {
  test('login form should be secure - active scan', async ({ page }) => {
    await page.goto('https://myapp.com/login');
    
    // Run active security scan (tests for injection vulnerabilities)
    const vulnerabilities = await runActiveSecurityScan(page.url(), {
      detectors: 'all',
      maxPages: 1,
      headless: true
    });
    
    // Assert no critical vulnerabilities
    assertNoVulnerabilities(vulnerabilities, VulnerabilitySeverity.HIGH);
  });
  
  test('app should have security headers - passive scan', async () => {
    // Run passive security scan (fast, non-intrusive)
    const vulnerabilities = await runPassiveSecurityScan('https://myapp.com', {
      detectors: 'headers',
      headless: true
    });
    
    // Assert no high-severity header issues
    assertNoVulnerabilities(vulnerabilities, VulnerabilitySeverity.HIGH);
  });
  
  test('checkout page should not have XSS', async ({ page }) => {
    await page.goto('https://myapp.com/checkout');
    
    const vulnerabilities = await runActiveSecurityScan(page.url(), {
      detectors: 'xss',
      maxPages: 1
    });
    
    expect(vulnerabilities).toHaveLength(0);
  });
});
```

---

## Core Concepts

### Architecture Overview

```
┌─────────────────────────────────────────┐
│         Your Application Code            │
│  (Tests, CI/CD, Custom Scripts)          │
└──────────────┬──────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────┐
│         ScanEngine (Orchestrator)        │
│  - Coordinates scanning workflow         │
│  - Manages browser lifecycle             │
│  - Aggregates results                    │
└──────────────┬──────────────────────────┘
               │
      ┌────────┴────────┐
      ▼                 ▼
┌────────────┐    ┌────────────┐
│  Scanners  │    │ Reporters  │
│ (Active/   │    │ (JSON/     │
│  Passive)  │    │  HTML/     │
└─────┬──────┘    │  SARIF)    │
      │           └────────────┘
      ▼
┌────────────┐
│ Detectors  │
│ (SQL/XSS/  │
│  Errors)   │
└────────────┘
```

### Key Components

1. **ScanEngine**: Main orchestrator that coordinates the entire scanning workflow
2. **Scanners**: Execute scanning strategies (Active/Passive)
3. **Detectors**: Analyze data and identify specific vulnerability types
4. **Reporters**: Generate reports in various formats
5. **Configuration**: Defines scan parameters and behavior

---

## API Reference

### ScanEngine

Main class for orchestrating security scans.

```typescript
class ScanEngine {
  constructor();
  
  // Scanner Management
  registerScanner(scanner: IScanner): void;
  registerScanners(scanners: IScanner[]): void;
  
  // Reporter Management
  registerReporter(reporter: IReporter): void;
  registerReporters(reporters: IReporter[]): void;
  
  // Configuration
  loadConfiguration(config: ScanConfiguration): Promise<void>;
  loadConfigurationFromFile(filePath: string): Promise<void>;
  
  // Scanning
  scan(): Promise<ScanResult>;
  
  // Lifecycle
  cleanup(): Promise<void>;
  
  // Events
  on(event: 'scan:start' | 'scan:complete' | 'vulnerability:found', handler: Function): void;
}
```

#### Usage Example

```typescript
import { ScanEngine } from '@tzigger/playwright-security';

const engine = new ScanEngine();

// Listen to events
engine.on('vulnerability:found', (vuln) => {
  console.log(`Found: ${vuln.title}`);
});

// Load config and scan
await engine.loadConfiguration(config);
const results = await engine.scan();
await engine.cleanup();
```

---

### ActiveScanner

Performs active security testing by manipulating inputs.

```typescript
class ActiveScanner implements IScanner {
  readonly type = 'active';
  
  // Detector Management
  registerDetector(detector: IDetector): void;
  registerDetectors(detectors: IDetector[]): void;
  
  // Scanning
  scan(context: ScanContext): Promise<Vulnerability[]>;
}
```

#### Usage Example

```typescript
import { ActiveScanner, SqlInjectionDetector, XssDetector } from '@tzigger/playwright-security';

const scanner = new ActiveScanner();
scanner.registerDetectors([
  new SqlInjectionDetector(),
  new XssDetector()
]);

engine.registerScanner(scanner);
```

---

### PassiveScanner

Performs passive security analysis via network traffic interception.

```typescript
class PassiveScanner implements IScanner {
  readonly type = 'passive';
  
  // Detector Management
  registerDetector(detector: IDetector): void;
  registerDetectors(detectors: IDetector[]): void;
  
  // Scanning
  scan(context: ScanContext): Promise<Vulnerability[]>;
}
```

#### Usage Example

```typescript
import { 
  PassiveScanner, 
  SensitiveDataDetector, 
  HeaderSecurityDetector,
  CookieSecurityDetector,
  InsecureTransmissionDetector
} from '@tzigger/playwright-security';

const scanner = new PassiveScanner();
scanner.registerDetectors([
  new SensitiveDataDetector(),
  new HeaderSecurityDetector(),
  new CookieSecurityDetector(),
  new InsecureTransmissionDetector()
]);

engine.registerScanner(scanner);
```

---

### Built-in Detectors

#### SqlInjectionDetector

Detects SQL injection vulnerabilities.

```typescript
class SqlInjectionDetector extends BaseDetector {
  readonly id = 'sql-injection';
  readonly category = VulnerabilityCategory.INJECTION;
  
  detect(data: unknown): Promise<Vulnerability[]>;
  getPatterns(): RegExp[];
}
```

**Detection Patterns**:
- Database error messages
- SQL syntax in responses
- Boolean-based injection
- Time-based injection

#### XssDetector

Detects Cross-Site Scripting vulnerabilities.

```typescript
class XssDetector extends BaseDetector {
  readonly id = 'xss';
  readonly category = VulnerabilityCategory.XSS;
  
  detect(data: unknown): Promise<Vulnerability[]>;
  getPatterns(): RegExp[];
}
```

**Detection Patterns**:
- Reflected XSS
- Stored XSS
- DOM-based XSS
- Script tag injection

#### ErrorBasedDetector

Detects information disclosure through error messages.

```typescript
class ErrorBasedDetector extends BaseDetector {
  readonly id = 'error-disclosure';
  readonly category = VulnerabilityCategory.INFORMATION_DISCLOSURE;
  
  detect(data: unknown): Promise<Vulnerability[]>;
  getPatterns(): RegExp[];
}
```

#### SensitiveDataDetector (Passive)

Detects sensitive data exposure in network traffic.

```typescript
class SensitiveDataDetector extends BaseDetector {
  readonly id = 'sensitive-data-exposure';
  readonly category = VulnerabilityCategory.SENSITIVE_DATA_EXPOSURE;
  
  detect(data: unknown): Promise<Vulnerability[]>;
  getPatterns(): RegExp[];
}
```

**Detection Patterns**:
- Email addresses
- Phone numbers
- API tokens and keys
- Credit card numbers
- Social security numbers

#### HeaderSecurityDetector (Passive)

Detects missing or misconfigured security headers.

```typescript
class HeaderSecurityDetector extends BaseDetector {
  readonly id = 'header-security';
  readonly category = VulnerabilityCategory.SECURITY_MISCONFIGURATION;
  
  detect(data: unknown): Promise<Vulnerability[]>;
}
```

**Checks For**:
- Missing HSTS (Strict-Transport-Security)
- Missing CSP (Content-Security-Policy)
- Missing X-Frame-Options
- Missing X-Content-Type-Options
- Missing X-XSS-Protection
- Server/technology disclosure

#### CookieSecurityDetector (Passive)

Detects insecure cookie configurations.

```typescript
class CookieSecurityDetector extends BaseDetector {
  readonly id = 'cookie-security';
  readonly category = VulnerabilityCategory.SECURITY_MISCONFIGURATION;
  
  detect(data: unknown): Promise<Vulnerability[]>;
}
```

**Checks For**:
- Missing Secure flag
- Missing HttpOnly flag
- Missing SameSite attribute
- Overly broad cookie domains

#### InsecureTransmissionDetector (Passive)

Detects insecure data transmission.

```typescript
class InsecureTransmissionDetector extends BaseDetector {
  readonly id = 'insecure-transmission';
  readonly category = VulnerabilityCategory.INSECURE_COMMUNICATION;
  
  detect(data: unknown): Promise<Vulnerability[]>;
}
```

**Checks For**:
- HTTP instead of HTTPS
- Mixed content (HTTP resources on HTTPS pages)
- Sensitive data over unencrypted connections

---

### Reporters

#### JsonReporter

Generates machine-readable JSON reports.

```typescript
import { JsonReporter } from '@tzigger/playwright-security';

const reporter = new JsonReporter();
engine.registerReporter(reporter);
```

#### HtmlReporter

Generates human-friendly HTML reports.

```typescript
import { HtmlReporter } from '@tzigger/playwright-security';

const reporter = new HtmlReporter();
engine.registerReporter(reporter);
```

#### SarifReporter

Generates SARIF format for CI/CD integration.

```typescript
import { SarifReporter } from '@tzigger/playwright-security';

const reporter = new SarifReporter();
engine.registerReporter(reporter);
```

---

## Testing Integration

### Playwright Test Helpers

The framework provides specialized helpers for Playwright tests.

#### `runActiveSecurityScan(url, options)`

Runs an active security scan (tests for injection vulnerabilities).

```typescript
function runActiveSecurityScan(
  targetUrl: string,
  options?: ActiveScanOptions
): Promise<Vulnerability[]>

interface ActiveScanOptions {
  detectors?: 'all' | 'sql' | 'xss' | 'errors';
  aggressiveness?: 'low' | 'medium' | 'high';
  maxPages?: number;
  headless?: boolean;
}
```

**Example**:

```typescript
import { runActiveSecurityScan } from '@tzigger/playwright-security/testing';

test('API endpoint security - active', async () => {
  const vulns = await runActiveSecurityScan('https://api.myapp.com/v1/users', {
    detectors: 'sql',
    aggressiveness: 'medium',
    maxPages: 1,
    headless: true
  });
  
  expect(vulns).toHaveLength(0);
});
```

**Performance**: 30-120 seconds depending on aggressiveness and pages.

#### `runPassiveSecurityScan(url, options)`

Runs a passive security scan (analyzes traffic patterns).

```typescript
function runPassiveSecurityScan(
  targetUrl: string,
  options?: PassiveScanOptions
): Promise<Vulnerability[]>

interface PassiveScanOptions {
  detectors?: 'all' | 'headers' | 'transmission' | 'data' | 'cookies';
  headless?: boolean;
}
```

**Example**:

```typescript
import { runPassiveSecurityScan } from '@tzigger/playwright-security/testing';

test('security headers check - passive', async () => {
  const vulns = await runPassiveSecurityScan('https://myapp.com', {
    detectors: 'headers',
    headless: true
  });
  
  expect(vulns.filter(v => v.severity === 'critical')).toHaveLength(0);
});
```

**Performance**: 3-5 seconds (very fast).

#### `assertNoVulnerabilities(vulnerabilities, maxSeverity)`

Asserts that no vulnerabilities above a certain severity exist.

```typescript
function assertNoVulnerabilities(
  vulnerabilities: Vulnerability[],
  maxAllowedSeverity?: VulnerabilitySeverity
): void
```

**Example**:

```typescript
import { assertNoVulnerabilities, VulnerabilitySeverity } from '@tzigger/playwright-security/testing';

test('no critical vulnerabilities', async ({ page }) => {
  const vulns = await runSecurityScan(page.url());
  
  // Will throw if any CRITICAL or HIGH vulnerabilities found
  assertNoVulnerabilities(vulns, VulnerabilitySeverity.MEDIUM);
});
```

### Integration Patterns

#### Pattern 1: Per-Page Security Tests

```typescript
import { test } from '@playwright/test';
import { 
  runActiveSecurityScan, 
  runPassiveSecurityScan,
  assertNoVulnerabilities 
} from '@tzigger/playwright-security/testing';

test.describe('Page Security', () => {
  const pages = [
    '/login',
    '/signup',
    '/checkout',
    '/profile'
  ];
  
  for (const pagePath of pages) {
    test(`${pagePath} should be secure - passive`, async () => {
      // Fast passive scan first (3-5 seconds)
      const vulns = await runPassiveSecurityScan(`https://myapp.com${pagePath}`, {
        detectors: 'all'
      });
      assertNoVulnerabilities(vulns);
    });
    
    test(`${pagePath} should be secure - active`, async ({ page }) => {
      await page.goto(`https://myapp.com${pagePath}`);
      
      // Deeper active scan (30-120 seconds)
      const vulns = await runActiveSecurityScan(page.url(), {
        detectors: 'all',
        maxPages: 2
      });
      assertNoVulnerabilities(vulns);
    });
  }
});
```

#### Pattern 2: CI/CD Integration

```typescript
// security.spec.ts
import { test, expect } from '@playwright/test';
import { 
  runActiveSecurityScan, 
  runPassiveSecurityScan,
  VulnerabilitySeverity 
} from '@tzigger/playwright-security/testing';
import * as fs from 'fs/promises';

test('comprehensive security scan', async () => {
  const baseUrl = process.env.BASE_URL || 'http://localhost:3000';
  
  // Fast passive scan first (3-5 seconds)
  const passiveVulns = await runPassiveSecurityScan(baseUrl, {
    detectors: 'all'
  });
  
  // Deeper active scan (30-120 seconds)
  const activeVulns = await runActiveSecurityScan(baseUrl, {
    detectors: 'all',
    aggressiveness: 'medium',
    maxPages: 10
  });
  
  const allVulnerabilities = [...passiveVulns, ...activeVulns];
  
  // Save results for CI artifacts
  await fs.writeFile(
    'security-report.json',
    JSON.stringify(allVulnerabilities, null, 2)
  );
  
  // Count by severity
  const critical = allVulnerabilities.filter(v => v.severity === VulnerabilitySeverity.CRITICAL);
  const high = allVulnerabilities.filter(v => v.severity === VulnerabilitySeverity.HIGH);
  
  // Fail build on critical/high
  expect(critical, 'Critical vulnerabilities found').toHaveLength(0);
  expect(high, 'High severity vulnerabilities found').toHaveLength(0);
});
```

#### Pattern 3: Authenticated Scanning

```typescript
test('authenticated pages security', async ({ page }) => {
  // Login first
  await page.goto('https://myapp.com/login');
  await page.fill('#username', 'testuser');
  await page.fill('#password', 'testpass');
  await page.click('button[type="submit"]');
  await page.waitForURL('**/dashboard');
  
  // Now scan authenticated pages with active scanner
  const vulns = await runActiveSecurityScan(page.url(), {
    detectors: 'all',
    aggressiveness: 'low',
    maxPages: 5
  });
  
  assertNoVulnerabilities(vulns);
});

test('authenticated API security headers', async ({ request }) => {
  // Get auth token
  const loginResponse = await request.post('https://api.myapp.com/login', {
    data: { username: 'testuser', password: 'testpass' }
  });
  const { token } = await loginResponse.json();
  
  // Passive scan with authentication
  const vulns = await runPassiveSecurityScan('https://api.myapp.com/dashboard', {
    detectors: 'headers'
  });
  
  assertNoVulnerabilities(vulns);
});
```

---

## Custom Detectors

Create custom detectors to find application-specific vulnerabilities.

### Step 1: Extend BaseDetector

```typescript
import { BaseDetector, Vulnerability, VulnerabilityCategory, VulnerabilitySeverity } from '@tzigger/playwright-security';

export class CustomApiKeyDetector extends BaseDetector {
  readonly id = 'custom-api-key-leak';
  readonly name = 'API Key Leakage Detector';
  readonly version = '1.0.0';
  readonly category = VulnerabilityCategory.SENSITIVE_DATA_EXPOSURE;
  readonly description = 'Detects exposed API keys in responses';
  
  async detect(data: unknown): Promise<Vulnerability[]> {
    const vulnerabilities: Vulnerability[] = [];
    
    // Type guard
    if (!this.isHttpResponseData(data)) {
      return vulnerabilities;
    }
    
    const { response, url } = data;
    const body = response.body;
    
    // Check for API key patterns
    const patterns = this.getPatterns();
    for (const pattern of patterns) {
      const matches = body.match(pattern);
      if (matches) {
        vulnerabilities.push(
          this.createVulnerability({
            title: 'API Key Exposed in Response',
            description: `An API key was found in the HTTP response at ${url}`,
            severity: VulnerabilitySeverity.HIGH,
            evidence: {
              url,
              matches: matches.map(m => m.substring(0, 20) + '...'),
              responseSnippet: body.substring(0, 500)
            },
            remediation: 'Remove API keys from client-side code. Use environment variables and server-side proxies.',
            confidence: 0.9,
            cwe: 'CWE-798',
            references: [
              'https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password'
            ]
          })
        );
      }
    }
    
    return vulnerabilities;
  }
  
  getPatterns(): RegExp[] {
    return [
      /api[_-]?key['"]?\s*[:=]\s*['"]\w{32,}/gi,
      /secret[_-]?key['"]?\s*[:=]\s*['"]\w{32,}/gi,
      /AKIA[0-9A-Z]{16}/g, // AWS keys
      /AIza[0-9A-Za-z\\-_]{35}/g, // Google API keys
    ];
  }
  
  getCWEReferences(): string[] {
    return ['CWE-798', 'CWE-259'];
  }
  
  private isHttpResponseData(data: unknown): data is { response: { body: string }, url: string } {
    return (
      typeof data === 'object' &&
      data !== null &&
      'response' in data &&
      'url' in data
    );
  }
}
```

### Step 2: Register Custom Detector

```typescript
import { ActiveScanner } from '@tzigger/playwright-security';
import { CustomApiKeyDetector } from './custom-detectors/CustomApiKeyDetector';

const scanner = new ActiveScanner();
scanner.registerDetectors([
  new CustomApiKeyDetector(),
  // ... other detectors
]);

engine.registerScanner(scanner);
```

### Step 3: Use in Tests

```typescript
test('no API keys leaked', async ({ page }) => {
  await page.goto('https://myapp.com');
  
  const vulns = await runSecurityScan(page.url(), {
    detectors: 'all', // Includes custom detectors
    maxPages: 5
  });
  
  const apiKeyLeaks = vulns.filter(v => v.detectorId === 'custom-api-key-leak');
  expect(apiKeyLeaks).toHaveLength(0);
});
```

---

## Custom Reporters

Create custom report formats for your specific needs.

### Step 1: Extend BaseReporter

```typescript
import { BaseReporter, AggregatedScanResult, ReportFormat } from '@tzigger/playwright-security';
import * as fs from 'fs/promises';

export class MarkdownReporter extends BaseReporter {
  readonly id = 'markdown-reporter';
  readonly name = 'Markdown Reporter';
  readonly format = ReportFormat.MARKDOWN;
  readonly extension = 'md';
  
  async generate(results: AggregatedScanResult, outputPath: string): Promise<void> {
    const markdown = this.generateMarkdown(results);
    await this.writeFile(outputPath, markdown);
  }
  
  private generateMarkdown(results: AggregatedScanResult): string {
    const { scanSummary, vulnerabilities } = results;
    
    let md = `# Security Scan Report\n\n`;
    md += `**Target:** ${scanSummary.targetUrl}\n`;
    md += `**Date:** ${this.formatTimestamp(scanSummary.startTime)}\n`;
    md += `**Duration:** ${this.formatDuration(scanSummary.duration)}\n\n`;
    
    md += `## Summary\n\n`;
    md += `- **Total Vulnerabilities:** ${scanSummary.totalVulnerabilities}\n`;
    md += `- **Critical:** ${scanSummary.criticalCount}\n`;
    md += `- **High:** ${scanSummary.highCount}\n`;
    md += `- **Medium:** ${scanSummary.mediumCount}\n`;
    md += `- **Low:** ${scanSummary.lowCount}\n\n`;
    
    md += `## Vulnerabilities\n\n`;
    
    for (const vuln of vulnerabilities) {
      md += `### ${vuln.title}\n\n`;
      md += `- **Severity:** ${vuln.severity.toUpperCase()}\n`;
      md += `- **Category:** ${vuln.category}\n`;
      md += `- **CWE:** ${vuln.cwe || 'N/A'}\n`;
      md += `- **URL:** ${vuln.url || 'N/A'}\n\n`;
      md += `**Description:**\n${vuln.description}\n\n`;
      md += `**Remediation:**\n${vuln.remediation}\n\n`;
      md += `---\n\n`;
    }
    
    return md;
  }
}
```

### Step 2: Register Custom Reporter

```typescript
import { ScanEngine } from '@tzigger/playwright-security';
import { MarkdownReporter } from './custom-reporters/MarkdownReporter';

const engine = new ScanEngine();
engine.registerReporter(new MarkdownReporter());
```

---

## Advanced Usage

### Configuration Builder Pattern

```typescript
import { ScanConfiguration, AggressivenessLevel, VulnerabilitySeverity } from '@tzigger/playwright-security/types';

function createSecurityConfig(targetUrl: string): ScanConfiguration {
  return {
    target: {
      url: targetUrl,
      crawlDepth: 2,
      maxPages: 20,
      timeout: 30000,
      scope: {
        includePatterns: [
          `${new URL(targetUrl).origin}/**`
        ],
        excludePatterns: [
          '**/logout',
          '**/signout',
          '**/*.pdf'
        ]
      }
    },
    scanners: {
      passive: {
        enabled: true,
        interceptTypes: ['xhr', 'fetch', 'document']
      },
      active: {
        enabled: true,
        aggressiveness: AggressivenessLevel.MEDIUM,
        submitForms: true,
        followRedirects: true,
        maxPayloadsPerInput: 10
      }
    },
    detectors: {
      enabled: ['sql-injection', 'xss', 'error-disclosure'],
      sensitivity: 'normal'
    },
    browser: {
      type: 'chromium',
      headless: true,
      timeout: 30000,
      viewport: { width: 1920, height: 1080 }
    },
    reporting: {
      formats: ['json', 'html', 'sarif'],
      outputDir: './security-reports',
      verbosity: 'detailed'
    },
    advanced: {
      parallelism: 3,
      logLevel: 'info',
      retryFailedRequests: true
    }
  };
}
```

### Event-Driven Architecture

```typescript
import { ScanEngine } from '@tzigger/playwright-security';

const engine = new ScanEngine();

// Track progress
let vulnerabilitiesFound = 0;

engine.on('scan:start', () => {
  console.log('🔍 Scan started...');
});

engine.on('vulnerability:found', (vuln) => {
  vulnerabilitiesFound++;
  console.log(`⚠️  [${vuln.severity}] ${vuln.title}`);
});

engine.on('scan:complete', (results) => {
  console.log(`✅ Scan complete. Found ${vulnerabilitiesFound} vulnerabilities.`);
});

await engine.scan();
```

### Authentication Examples

#### Form-Based Authentication

```typescript
const config: ScanConfiguration = {
  target: {
    url: 'https://myapp.com/dashboard',
    authentication: {
      type: 'form',
      loginUrl: 'https://myapp.com/login',
      credentials: {
        username: process.env.TEST_USERNAME,
        password: process.env.TEST_PASSWORD
      },
      formSelectors: {
        usernameField: '#username',
        passwordField: '#password',
        submitButton: 'button[type="submit"]'
      },
      successIndicator: 'text=Dashboard'
    }
  },
  // ... rest of config
};
```

#### Token-Based Authentication

```typescript
const config: ScanConfiguration = {
  target: {
    url: 'https://api.myapp.com',
    authentication: {
      type: 'bearer',
      credentials: {
        token: process.env.API_TOKEN
      }
    },
    customHeaders: {
      'Authorization': `Bearer ${process.env.API_TOKEN}`
    }
  },
  // ... rest of config
};
```

---

## Best Practices

### 1. **Scope Your Scans**

Always define clear scope to avoid testing unintended targets:

```typescript
target: {
  scope: {
    includePatterns: [
      'https://myapp.com/**',
      'https://api.myapp.com/**'
    ],
    excludePatterns: [
      '**/logout',
      '**/delete-account',
      '**/*.pdf',
      '**/analytics/**'
    ]
  }
}
```

### 2. **Use Environment Variables**

Never hardcode credentials:

```typescript
// ❌ Bad
credentials: {
  username: 'admin',
  password: 'password123'
}

// ✅ Good
credentials: {
  username: process.env.TEST_USERNAME!,
  password: process.env.TEST_PASSWORD!
}
```

### 3. **Progressive Testing**

Start with low aggressiveness, increase gradually:

```typescript
// Development
aggressiveness: AggressivenessLevel.LOW

// Staging
aggressiveness: AggressivenessLevel.MEDIUM

// Pre-production (with approval)
aggressiveness: AggressivenessLevel.HIGH
```

### 4. **Filter False Positives**

```typescript
const vulnerabilities = await runSecurityScan(url);

// Filter by confidence
const highConfidence = vulnerabilities.filter(v => (v.confidence ?? 0) > 0.7);

// Filter by severity
const critical = vulnerabilities.filter(v => 
  v.severity === VulnerabilitySeverity.CRITICAL ||
  v.severity === VulnerabilitySeverity.HIGH
);
```

### 5. **Parallel Test Execution**

```typescript
test.describe.parallel('Security Scans', () => {
  const endpoints = ['/api/users', '/api/products', '/api/orders'];
  
  for (const endpoint of endpoints) {
    test(`${endpoint} security`, async () => {
      const vulns = await runSecurityScan(`https://api.myapp.com${endpoint}`);
      assertNoVulnerabilities(vulns);
    });
  }
});
```

---

## Examples

### Example 1: Full E2E Security Test Suite

```typescript
import { test, expect } from '@playwright/test';
import { 
  ScanEngine, 
  ActiveScanner, 
  SqlInjectionDetector, 
  XssDetector,
  ErrorBasedDetector,
  JsonReporter,
  HtmlReporter 
} from '@tzigger/playwright-security';

test.describe('E2E Security Testing', () => {
  let engine: ScanEngine;
  
  test.beforeAll(async () => {
    engine = new ScanEngine();
    
    const scanner = new ActiveScanner();
    scanner.registerDetectors([
      new SqlInjectionDetector(),
      new XssDetector(),
      new ErrorBasedDetector()
    ]);
    
    engine.registerScanner(scanner);
    engine.registerReporters([
      new JsonReporter(),
      new HtmlReporter()
    ]);
  });
  
  test.afterAll(async () => {
    await engine.cleanup();
  });
  
  test('comprehensive application scan', async () => {
    const config = {
      target: {
        url: 'https://myapp.com',
        crawlDepth: 3,
        maxPages: 50,
        scope: {
          includePatterns: ['https://myapp.com/**'],
          excludePatterns: ['**/logout']
        }
      },
      scanners: {
        active: { enabled: true, aggressiveness: 'medium' },
        passive: { enabled: true }
      },
      reporting: {
        formats: ['json', 'html'],
        outputDir: './security-reports'
      }
    };
    
    await engine.loadConfiguration(config);
    const results = await engine.scan();
    
    // Assertions
    expect(results.vulnerabilities).toBeDefined();
    
    const critical = results.vulnerabilities.filter(v => v.severity === 'critical');
    expect(critical, 'No critical vulnerabilities allowed').toHaveLength(0);
  });
});
```

### Example 2: API Security Testing

```typescript
import { test } from '@playwright/test';
import { 
  runActiveSecurityScan, 
  runPassiveSecurityScan,
  assertNoVulnerabilities,
  VulnerabilitySeverity
} from '@tzigger/playwright-security/testing';

test.describe('API Security', () => {
  const baseUrl = 'https://api.myapp.com/v1';
  
  const endpoints = [
    { path: '/users', method: 'GET' },
    { path: '/users/1', method: 'GET' },
    { path: '/products', method: 'GET' },
    { path: '/orders', method: 'POST' }
  ];
  
  for (const endpoint of endpoints) {
    test(`${endpoint.method} ${endpoint.path} - passive scan`, async () => {
      // Fast passive scan for headers, transmission security
      const vulns = await runPassiveSecurityScan(`${baseUrl}${endpoint.path}`, {
        detectors: 'all'
      });
      
      assertNoVulnerabilities(vulns, VulnerabilitySeverity.HIGH);
    });
    
    test(`${endpoint.method} ${endpoint.path} - active scan`, async () => {
      // Active scan for SQL injection
      const vulns = await runActiveSecurityScan(`${baseUrl}${endpoint.path}`, {
        detectors: 'sql',
        aggressiveness: 'low',
        maxPages: 1
      });
      
      assertNoVulnerabilities(vulns);
    });
  }
});
```

### Example 3: GitHub Actions Integration

```yaml
# .github/workflows/security-scan.yml
name: Security Scan

on:
  pull_request:
  push:
    branches: [main, develop]

jobs:
  security-test:
    runs-on: ubuntu-latest
    
    steps:
      - uses: actions/checkout@v3
      
      - uses: actions/setup-node@v3
        with:
          node-version: '18'
      
      - name: Install dependencies
        run: npm ci
      
      - name: Run security scan
        run: npx playwright test security.spec.ts
        env:
          BASE_URL: ${{ secrets.STAGING_URL }}
      
      - name: Upload security report
        if: always()
        uses: actions/upload-artifact@v3
        with:
          name: security-report
          path: security-reports/
      
      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: security-reports/scan.sarif
```

---

## TypeScript Type Definitions

The framework is fully typed. Import types as needed:

```typescript
import type {
  Vulnerability,
  VulnerabilityCategory,
  VulnerabilitySeverity,
  ScanConfiguration,
  ScanResult,
  Evidence,
  IDetector,
  IReporter,
  IScanner
} from '@tzigger/playwright-security';
```

---

## Troubleshooting

### Common Issues

#### Issue: "No scanners registered"

```typescript
// ❌ Forgot to register scanner
const engine = new ScanEngine();
await engine.scan(); // Error!

// ✅ Register scanner first
const scanner = new ActiveScanner();
scanner.registerDetectors([new SqlInjectionDetector()]);
engine.registerScanner(scanner);
await engine.scan(); // Works
```

#### Issue: "runSecurityScan is not a function"

```typescript
// ❌ Old API (deprecated)
import { runSecurityScan } from '@tzigger/playwright-security/testing';

// ✅ New API (use specific scan types)
import { 
  runActiveSecurityScan,   // For injection testing
  runPassiveSecurityScan   // For traffic analysis
} from '@tzigger/playwright-security/testing';
```

#### Issue: "Configuration not loaded"

```typescript
// ❌ Forgot to load config
const engine = new ScanEngine();
await engine.scan(); // Error!

// ✅ Load config first
await engine.loadConfiguration(config);
await engine.scan(); // Works
```

#### Issue: Browser timeout

```typescript
// Increase timeout in config
browser: {
  timeout: 60000, // 60 seconds
}
```

---

## CLI Tool Usage

### Installation

To use the `dast-scan` CLI command:

```bash
# Clone and setup
git clone https://github.com/Tzigger/playwright_security.git
cd playwright_security
npm install

# Build the project
npm run build

# Link globally (may require sudo on macOS/Linux)
npm link
# or
sudo npm link
```

### Basic Usage

```bash
# Passive scan (fast, 3-5 seconds)
dast-scan https://myapp.com --scan-type passive

# Active scan (comprehensive, 30-120 seconds)
dast-scan https://myapp.com --scan-type active

# Both passive and active
dast-scan https://myapp.com --scan-type both

# With custom output
dast-scan https://myapp.com --output ./reports --formats html,json,sarif

# Using a configuration file
dast-scan --config ./config/default.config.json
```

### Available Flags

- `--scan-type <type>` - Scan type: active, passive, or both (default: active)
- `--passive` - Enable passive scanning
- `--active` - Enable active scanning (default: true)
- `-o, --output <dir>` - Output directory (default: ./reports)
- `-f, --formats <list>` - Report formats: console,json,html,sarif
- `-c, --config <file>` - Load configuration from file
- `--headless` - Run headless browser (default: true)
- `--parallel <n>` - Number of parallel scanners (default: 2)

See [MIGRATION-GUIDE.md](./MIGRATION-GUIDE.md) for more CLI details.

---

## Support

- **Issues**: https://github.com/Tzigger/playwright_security/issues
- **Discussions**: https://github.com/Tzigger/playwright_security/discussions
- **Documentation**: https://github.com/Tzigger/playwright_security/docs

---

## License

MIT License - see LICENSE file for details.

---

**Happy Secure Testing! 🔒**
