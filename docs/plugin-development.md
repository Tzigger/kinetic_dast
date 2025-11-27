# Plugin Development Guide

# Plugin Development Guide

## Overview

The DAST Engine supports custom plugins for extending functionality. You can create:

- **Custom active detectors** (currently supported)
- **Custom passive detectors** (interface ready, partial implementation)
- **Custom reporters** (fully supported)
- **Custom helper functions** (wrapper utilities)

## Creating a Custom Active Detector

### 1. Basic Structure

```typescript
import { IActiveDetector, ActiveDetectorContext } from '../src/core/interfaces/IActiveDetector';
import { Vulnerability, VulnerabilitySeverity, VulnerabilityCategory } from '../src/types';
import { AttackSurface } from '../src/scanners/active/DomExplorer';
import { PayloadInjector } from '../src/scanners/active/PayloadInjector';
import { getOWASP2025Category } from '../src/utils/cwe/owasp-2025-mapping';

export class MyCustomDetector implements IActiveDetector {
  readonly name = 'My Custom Detector';
  readonly description = 'Detects custom security issues';
  readonly version = '1.0.0';

  private injector: PayloadInjector;

  constructor() {
    this.injector = new PayloadInjector();
  }
  
  async detect(context: ActiveDetectorContext): Promise<Vulnerability[]> {
    const vulnerabilities: Vulnerability[] = [];
    const { page, attackSurfaces, baseUrl } = context;
    
    // Filter for relevant attack surfaces
    const targets = attackSurfaces.filter(surface => 
      surface.name.toLowerCase().includes('custom')
    );
    
    // Test each surface
    for (const surface of targets) {
      const vuln = await this.testSurface(page, surface, baseUrl);
      if (vuln) vulnerabilities.push(vuln);
    }
    
    return vulnerabilities;
  }

  private async testSurface(
    page: any,
    surface: AttackSurface,
    baseUrl: string
  ): Promise<Vulnerability | null> {
    const payloads = ['test1', 'test2'];
    
    const results = await this.injector.injectMultiple(page, surface, payloads, {
      encoding: 'none' as any,
      submit: true,
      baseUrl,
    });
    
    for (const result of results) {
      if (result.response?.body?.includes('vulnerable')) {
        return this.createVulnerability(surface, result, baseUrl);
      }
    }
    
    return null;
  }

  private createVulnerability(surface: AttackSurface, result: any, baseUrl: string): Vulnerability {
    const cwe = 'CWE-200';
    const owasp = getOWASP2025Category(cwe);
    
    return {
      id: `custom-${Date.now()}`,
      title: 'Custom Vulnerability',
      description: `Custom vulnerability in ${surface.type} '${surface.name}'`,
      severity: VulnerabilitySeverity.HIGH,
      category: VulnerabilityCategory.CUSTOM,
      cwe,
      owasp: owasp || 'A01:2021',
      url: result.response?.url || baseUrl,
      evidence: {
        request: { body: result.payload },
        response: { body: result.response?.body?.substring(0, 500) || '' },
      },
      remediation: 'Fix the custom vulnerability',
      references: ['https://example.com/docs'],
      timestamp: new Date(),
    };
  }
}
```

### 2. Registration and Usage

```typescript
import { test, expect } from '@playwright/test';
import { ScanEngine } from '../src/core/engine/ScanEngine';
import { ActiveScanner } from '../src/scanners/active/ActiveScanner';
import { MyCustomDetector } from './MyCustomDetector';

test('use custom detector', async ({ page }) => {
  await page.goto('https://example.com');
  
  // Create engine and scanner
  const engine = new ScanEngine();
  const scanner = new ActiveScanner();
  
  // Register your custom detector
  scanner.registerDetectors([new MyCustomDetector()]);
  engine.registerScanner(scanner);
  
  // Configure and run
  await engine.loadConfiguration({
    target: { url: 'https://example.com' },
    scanners: { active: { enabled: true } },
    // ... other config
  });
  
  const result = await engine.scan();
  const customVulns = result.vulnerabilities.filter(v => 
    v.title.includes('Custom')
  );
  
  console.log(`Found ${customVulns.length} custom vulnerabilities`);
});
```

### 3. Using with Helper Functions

```typescript
import { runActiveSecurityScan } from '../src/testing/helpers';

// Unfortunately, helper functions use predefined detectors
// For custom detectors, use the full ScanEngine approach above
// OR create a custom wrapper:

export async function runCustomSecurityScan(
  page: Page,
  options?: any
): Promise<Vulnerability[]> {
  const engine = new ScanEngine();
  const scanner = new ActiveScanner();
  
  scanner.registerDetectors([
    new MyCustomDetector(),
    // ... other detectors if needed
  ]);
  
  engine.registerScanner(scanner);
  engine.setExistingPage(page);
  
  await engine.loadConfiguration({
    target: { url: page.url() },
    scanners: {
      active: {
        enabled: true,
        aggressiveness: options?.aggressiveness || 'medium',
      },
    },
    crawling: {
      maxDepth: options?.maxDepth || 2,
      maxPages: options?.maxPages || 5,
    },
    // ... other config
  });
  
  const result = await engine.scan();
  return result.vulnerabilities;
}
```

## Creating a Custom Reporter

### 1. Basic Structure

```typescript
import { IReporter } from '../src/core/interfaces/IReporter';
import { AggregatedScanResult, ReportFormat } from '../src/types';
import * as fs from 'fs/promises';
import * as path from 'path';

export class MyCustomReporter implements IReporter {
  readonly id = 'my-custom-reporter';
  readonly name = 'My Custom Reporter';
  readonly format = 'custom' as ReportFormat;
  readonly extension = 'custom';
  
  async generate(results: AggregatedScanResult, outputPath: string): Promise<void> {
    // Ensure output directory exists
    const dir = path.dirname(outputPath);
    await fs.mkdir(dir, { recursive: true });
    
    // Generate report content
    const reportContent = this.generateReportContent(results);
    
    // Write to file
    const fullPath = outputPath.endsWith(`.${this.extension}`)
      ? outputPath
      : `${outputPath}.${this.extension}`;
    
    await fs.writeFile(fullPath, reportContent, 'utf-8');
  }
  
  private generateReportContent(results: AggregatedScanResult): string {
    // Custom format - example: simple text report
    let content = `Security Scan Report\n`;
    content += `===================\n\n`;
    content += `Target: ${results.targetUrl}\n`;
    content += `Scan ID: ${results.scanId}\n`;
    content += `Duration: ${results.duration}ms\n\n`;
    content += `Vulnerabilities Found: ${results.totalVulnerabilities}\n`;
    content += `Critical: ${results.summary.critical}\n`;
    content += `High: ${results.summary.high}\n`;
    content += `Medium: ${results.summary.medium}\n`;
    content += `Low: ${results.summary.low}\n\n`;
    
    content += `Details:\n`;
    content += `--------\n`;
    results.vulnerabilities.forEach((vuln, i) => {
      content += `${i + 1}. ${vuln.title} [${vuln.severity}]\n`;
      content += `   CWE: ${vuln.cwe}\n`;
      content += `   URL: ${vuln.url}\n`;
      content += `   ${vuln.description}\n\n`;
    });
    
    return content;
  }
}
```

### 2. Usage

```typescript
import { ScanEngine } from '../src/core/engine/ScanEngine';
import { MyCustomReporter } from './MyCustomReporter';

const engine = new ScanEngine();
// ... setup scanners and config ...

const result = await engine.scan();

// Use custom reporter
const reporter = new MyCustomReporter();
await reporter.generate(result, './reports/custom-report');
```

## Testing Your Plugin

### Unit Testing

```typescript
import { describe, it, expect, beforeEach } from '@jest/globals';
import { MyCustomDetector } from './MyCustomDetector';
import { AttackSurface, InjectionContext } from '../src/scanners/active/DomExplorer';

describe('MyCustomDetector', () => {
  let detector: MyCustomDetector;
  
  beforeEach(() => {
    detector = new MyCustomDetector();
  });
  
  it('should detect vulnerabilities', async () => {
    const mockContext = {
      page: {} as any,
      attackSurfaces: [
        {
          type: 'form-input',
          name: 'custom-input',
          value: 'test',
          selector: '#custom',
          context: InjectionContext.SQL,
          metadata: {},
        } as AttackSurface,
      ],
      baseUrl: 'https://example.com',
      logger: console as any,
    };
    
    const results = await detector.detect(mockContext);
    
    expect(Array.isArray(results)).toBe(true);
  });
  
  it('should have correct metadata', () => {
    expect(detector.name).toBe('My Custom Detector');
    expect(detector.version).toBe('1.0.0');
  });
});
```

### Integration Testing

```typescript
import { test, expect } from '@playwright/test';
import { ScanEngine } from '../src/core/engine/ScanEngine';
import { ActiveScanner } from '../src/scanners/active/ActiveScanner';
import { MyCustomDetector } from './MyCustomDetector';

test('custom detector integration', async ({ page }) => {
  await page.goto('https://example.com');
  
  const engine = new ScanEngine();
  const scanner = new ActiveScanner();
  
  scanner.registerDetectors([new MyCustomDetector()]);
  engine.registerScanner(scanner);
  engine.setExistingPage(page);
  
  await engine.loadConfiguration({
    target: { url: page.url() },
    scanners: { active: { enabled: true } },
    crawling: { maxPages: 1 },
  } as any);
  
  const result = await engine.scan();
  
  expect(result.vulnerabilities).toBeDefined();
  console.log(`Found ${result.vulnerabilities.length} vulnerabilities`);
});
```

## Best Practices

1. **Error Handling**: Always wrap detection logic in try-catch blocks
2. **Performance**: Avoid expensive operations; use caching where possible
3. **Payload Selection**: Choose context-appropriate payloads
4. **Documentation**: Document your detection logic and patterns
5. **Testing**: Write comprehensive unit and integration tests
6. **False Positives**: Implement validation logic to reduce false positives
7. **Logging**: Use console sparingly; leverage evidence fields
8. **Type Safety**: Use TypeScript strict mode
9. **Evidence**: Collect comprehensive evidence (request, response, description)
10. **Remediation**: Provide actionable remediation guidance

## Attack Surface Filtering

Filter attack surfaces efficiently:

```typescript
// By type
const forms = attackSurfaces.filter(s => s.type === 'form-input');

// By context
const sqlTargets = attackSurfaces.filter(s => 
  s.context === InjectionContext.SQL
);

// By name pattern
const idParams = attackSurfaces.filter(s => 
  s.name.toLowerCase().includes('id')
);

// Multiple criteria
const apiInputs = attackSurfaces.filter(s => 
  (s.type === 'api-param' || s.type === 'json-body') &&
  s.name.toLowerCase().includes('search')
);
```

## Payload Injection Examples

```typescript
import { PayloadInjector, PayloadEncoding } from '../src/scanners/active/PayloadInjector';

const injector = new PayloadInjector();

// Single payload
const result = await injector.inject(page, surface, "' OR 1=1--", {
  encoding: PayloadEncoding.NONE,
  submit: true,
  baseUrl: 'https://example.com',
});

// Multiple payloads
const payloads = ["payload1", "payload2", "payload3"];
const results = await injector.injectMultiple(page, surface, payloads, {
  encoding: PayloadEncoding.URL,
  submit: false,
  baseUrl: 'https://example.com',
});

// With encoding
const encoded = await injector.inject(page, surface, "<script>alert(1)</script>", {
  encoding: PayloadEncoding.HTML_ENTITY,
  submit: true,
  baseUrl: 'https://example.com',
});
```

## Common Patterns

### Pattern: Baseline Comparison

```typescript
// Measure baseline response
const baseline = await injector.inject(page, surface, surface.value || '', options);
const baselineLength = baseline.response?.body?.length || 0;

// Test payloads
const payload1 = await injector.inject(page, surface, "' OR '1'='1", options);
const payload1Length = payload1.response?.body?.length || 0;

// Compare
if (Math.abs(payload1Length - baselineLength) > 100) {
  // Significant difference detected
}
```

### Pattern: Time-Based Detection

```typescript
// Baseline timing
let baselineTime = 0;
for (let i = 0; i < 2; i++) {
  const start = Date.now();
  await injector.inject(page, surface, '', options);
  baselineTime += Date.now() - start;
}
baselineTime = baselineTime / 2;

// Test sleep payload
const start = Date.now();
const result = await injector.inject(page, surface, "' AND SLEEP(2)--", options);
const duration = Date.now() - start;

if (duration > baselineTime * 2 && duration > 2000) {
  // Time-based vulnerability detected
}
```

### Pattern: JSON Response Analysis

```typescript
const result = await injector.inject(page, surface, payload, options);

if (result.response?.body) {
  try {
    const json = JSON.parse(result.response.body);
    
    // Check for arrays
    if (Array.isArray(json.data)) {
      console.log(`Array length: ${json.data.length}`);
    }
    
    // Check for status fields
    if (json.status === 'error' || json.error) {
      // Error detected
    }
  } catch {
    // Not JSON
  }
}
```

## Package Structure (for NPM publishing)

```
my-custom-detector/
├── package.json
├── tsconfig.json
├── README.md
├── LICENSE
├── src/
│   ├── index.ts
│   └── MyCustomDetector.ts
├── tests/
│   └── MyCustomDetector.test.ts
└── examples/
    └── usage-example.ts
```

### package.json

```json
{
  "name": "@yourorg/playwright-security-custom-detector",
  "version": "1.0.0",
  "description": "Custom detector for Playwright Security",
  "main": "dist/index.js",
  "types": "dist/index.d.ts",
  "peerDependencies": {
    "@tzigger/playwright-security": "^0.1.0",
    "playwright": "^1.40.0"
  },
  "scripts": {
    "build": "tsc",
    "test": "jest"
  }
}
```

## Support and Resources

- **Documentation**: [Main Docs](./README.md)
- **Examples**: See `tests/` directory for working examples
- **Issues**: [GitHub Issues](https://github.com/Tzigger/playwright-security/issues)
- **Discussions**: [GitHub Discussions](https://github.com/Tzigger/playwright-security/discussions)

---

**Last Updated**: November 27, 2025  
**Framework Version**: 0.1.0-beta.1
