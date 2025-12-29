# Kinetic Plugin Development Guide

> Guide for extending Kinetic with custom detectors and reporters.

## Overview

Kinetic is designed to be extensible. You can add:
1.  **Active Detectors**: Logic that interacts with the page (clicks, injections).
2.  **Passive Detectors**: Logic that analyzes network traffic (headers, bodies).
3.  **Reporters**: Custom output formats.

## 📦 Setup

If you are developing a plugin in a separate project:

```bash
npm install @tzigger/kinetic playwright --save-dev
```

---

## 1. Creating a Custom Active Detector

Active detectors implement the `IActiveDetector` interface. They receive a list of **Attack Surfaces** (inputs, forms, URLs) found by the crawler or Element Scanner.

### Code Example

```typescript
import { 
  IActiveDetector, 
  ActiveDetectorContext, 
  Vulnerability, 
  VulnerabilitySeverity, 
  VulnerabilityCategory 
} from '@tzigger/kinetic';
import { PayloadInjector, PayloadEncoding } from '@tzigger/kinetic/scanners/active/PayloadInjector';

export class MyCustomDetector implements IActiveDetector {
  readonly id = 'my-custom-check';
  readonly name = 'My Custom Logic Detector';
  readonly description = 'Checks for specific business logic flaws';
  readonly version = '1.0.0';
  
  // Injector handles safe mode filtering automatically
  private injector = new PayloadInjector();

  async detect(context: ActiveDetectorContext): Promise<Vulnerability[]> {
    const { page, attackSurfaces, baseUrl } = context;
    const vulnerabilities: Vulnerability[] = [];

    // 1. Filter surfaces you care about
    const targets = attackSurfaces.filter(s => s.name.includes('price'));

    for (const surface of targets) {
      // 2. Inject Payload
      const result = await this.injector.inject(page, surface, '-99', {
        encoding: PayloadEncoding.NONE
      });

      // 3. Analyze Result
      if (result.response?.body?.includes('Order Confirmed')) {
        vulnerabilities.push({
          id: `biz-logic-${Date.now()}`,
          category: VulnerabilityCategory.BUSINESS_LOGIC,
          severity: VulnerabilitySeverity.CRITICAL,
          title: 'Negative Price Accepted',
          description: 'The application accepted a negative price.',
          remediation: 'Validate input ranges on the server.',
          evidence: {
            request: { body: result.payload },
            response: { snippet: 'Order Confirmed' }
          },
          // Important: VerificationEngine uses confidence to filter results
          confidence: 1.0, 
          url: page.url(),
          timestamp: new Date(),
          references: []
        });
      }
    }

    return vulnerabilities;
  }
}
```

### Registration

Register your detector before the scan starts using the `DetectorRegistry`.

```typescript
import { DetectorRegistry } from '@tzigger/kinetic';
import { MyCustomDetector } from './MyCustomDetector';

DetectorRegistry.getInstance().registerActiveDetector(new MyCustomDetector(), {
  id: 'my-custom-check',
  name: 'My Custom Logic Detector',
  category: 'business-logic',
  description: 'Checks for negative prices',
  type: 'active',
  enabledByDefault: true
});
```

---

## 2. Creating a Custom Passive Detector

Passive detectors implement `IPassiveDetector`. They receive a list of intercepted Network Requests/Responses.

### Code Example

```typescript
import { IPassiveDetector, PassiveDetectorContext, Vulnerability } from '@tzigger/kinetic';

export class LegacyHeaderDetector implements IPassiveDetector {
  readonly name = 'Legacy Header Check';
  
  async detect(context: PassiveDetectorContext): Promise<Vulnerability[]> {
    const vulns: Vulnerability[] = [];
    
    for (const response of context.responses) {
      const headers = response.headers;
      
      // Check for X-Powered-By
      if (headers['x-powered-by']) {
        vulns.push({
          id: `info-leak-${Date.now()}`,
          title: 'Server Information Leak',
          // ... standard vulnerability fields ...
        });
      }
    }
    
    return vulns;
  }
}
```

### Registration

```typescript
DetectorRegistry.getInstance().registerPassiveDetector(new LegacyHeaderDetector(), {
  id: 'legacy-headers',
  name: 'Legacy Header Check',
  category: 'headers',
  description: 'Checks for legacy server headers',
  type: 'passive',
  enabledByDefault: true
});
```

---

## 3. Creating a Custom Reporter

Reporters implement `IReporter` and output scan results to a file or service.

### Code Example

```typescript
import { IReporter, ScanResult, ReportFormat } from '@tzigger/kinetic';
import * as fs from 'fs/promises';

export class SlackReporter implements IReporter {
  readonly id = 'slack';
  readonly format = ReportFormat.JSON; 

  async generate(result: ScanResult): Promise<void> {
    const criticalCount = result.summary.critical;
    
    if (criticalCount > 0) {
      const message = {
        text: `🚨 *Security Scan Failed*\nFound ${criticalCount} critical issues on ${result.targetUrl}`
      };
      
      // Send to Slack Webhook (mock)
      console.log('Sending to Slack:', JSON.stringify(message));
    }
  }
}
```

### Registration

```typescript
const engine = new ScanEngine();
engine.registerReporter(new SlackReporter());
```

---

## Best Practices

1.  **Use PayloadInjector**: Do not use `page.fill` directly in active detectors. The `PayloadInjector` handles:
    *   **Safe Mode**: Automatically blocks `DROP TABLE`, etc.
    *   **SPA Waiting**: Ensures the UI is ready.
    *   **Encoding**: Handles URL/HTML/Base64 encoding.

2.  **Set Confidence**: 
    *   `1.0`: You saw proof (e.g., reflected payload + execution).
    *   `0.8`: Strong indicators (e.g., SQL error message).
    *   `<0.6`: Suspicious behavior but not confirmed.
    *   *Note: The Verification Engine verifies findings with confidence > 0.6.*

3.  **Handle ElementScanner**: 
    *   Your active detector might run in `ElementScanner` mode where `attackSurfaces` contains only specific elements.
    *   Don't assume `attackSurfaces` contains *all* page inputs.

4.  **Performance**:
    *   Avoid navigating (`page.goto`) inside a detector if possible.
    *   Use `context.baseUrl` for relative link resolution.

## Testing Your Plugin

We provide helpers to unit test your detectors.

```typescript
import { describe, it, expect } from '@jest/globals';
import { MyCustomDetector } from './MyCustomDetector';

describe('MyCustomDetector', () => {
  it('detects vulnerabilities', async () => {
    const detector = new MyCustomDetector();
    
    // Mock Context
    const mockContext = {
      page: {} as any,
      attackSurfaces: [{ name: 'price', type: 'form-input' }],
      // ...
    };

    const results = await detector.detect(mockContext as any);
    expect(results).toHaveLength(1);
  });
});
```
