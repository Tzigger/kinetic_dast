# SSRF Detector

## Overview

The SSRF (Server-Side Request Forgery) Detector is a comprehensive security testing tool that identifies SSRF vulnerabilities in web applications. It uses three detection strategies:

1. **Reflected/Error-Based Detection**: Detects when internal content is reflected in the response
2. **Timing-Based Blind Detection**: Detects blind SSRF via response timing analysis
3. **OOB-Based Blind Detection**: Detects blind SSRF via out-of-band interactions

The detector supports advanced payload categories including WAF bypass techniques, cloud metadata extraction, and protocol smuggling.

## Detection Strategies

### Reflected/Error-Based Detection

This strategy injects various payloads and analyzes the response for signs of internal service access:

- **Localhost Bypass**: Tests multiple representations of localhost (IPv6, Decimal, Hex, Octal, DNS rebinding)
- **Cloud Metadata**: Attempts to access cloud provider metadata endpoints (AWS, GCP, Azure, etc.)
- **Protocol Smuggling**: Tests dangerous protocols (file://, gopher://, dict://, ftp://, ldap://)
- **Service Signatures**: Detects known service banners and responses (Redis, SSH, Apache, etc.)

**Example**:
```typescript
const detector = new SsrfDetector({
  enableReflected: true,
  enableWafBypass: true,
  enableCloudMetadata: true,
  enableProtocolSmuggling: true,
});
```

### Timing-Based Blind Detection

This strategy detects blind SSRF by measuring response time differences:

- Injects a non-routable IP address (e.g., `10.255.255.1`)
- Measures how long the server takes to respond
- Compares against baseline timing
- If the response takes significantly longer, the server likely attempted to connect

**Example**:
```typescript
const detector = new SsrfDetector({
  enableTiming: true,
  timingThresholdMs: 5000,
  timingMultiplier: 5,
});
```

### OOB-Based Blind Detection

This strategy uses out-of-band interactions to detect blind SSRF:

- Generates a unique callback URL using an OOB service (Interactsh, Burp Collaborator, or custom)
- Injects the callback URL into the target application
- Waits for the target server to make a request to the callback URL
- Checks for interactions (DNS, HTTP, SMTP, etc.)
- If interactions are found, SSRF is confirmed

**Example**:
```typescript
import { createOOBClient } from '@tzigger/kinetic';

const oobClient = createOOBClient('interactsh', {
  server: 'oast.pro',
  pollInterval: 5000,
  maxPolls: 10,
});

const detector = new SsrfDetector({
  enableOOB: true,
  oobClient,
  oobWaitMs: 5000,
});
```

## Payload Categories

### WAF Bypass Payloads

The detector includes advanced WAF bypass techniques:

| Type | Example | Description |
|------|---------|-------------|
| IPv6 | `http://[::1]` | IPv6 localhost |
| Decimal | `http://2130706433` | Decimal IP encoding |
| Hex | `http://0x7f000001` | Hexadecimal IP encoding |
| Octal | `http://0177.0000.0000.0001` | Octal IP encoding |
| Short | `http://127.1` | Short IP notation |
| DNS Rebinding | `http://localtest.me` | Public DNS pointing to 127.0.0.1 |
| URL Authority | `http://evil.com@127.0.0.1` | URL authority bypass |

### Cloud Metadata Payloads

Tests for cloud metadata access vulnerabilities:

| Provider | Endpoint | Signatures |
|----------|----------|------------|
| AWS | `http://169.254.169.254/latest/meta-data/` | `ami-id`, `instance-id` |
| AWS IAM | `http://169.254.169.254/latest/meta-data/iam/security-credentials/` | `AccessKeyId`, `SecretAccessKey` |
| GCP | `http://metadata.google.internal/computeMetadata/v1/` | `computeMetadata` |
| Azure | `http://169.254.169.254/metadata/instance?api-version=2021-02-01` | `compute`, `vmId` |
| DigitalOcean | `http://169.254.169.254/metadata/v1/` | `droplet_id` |
| Oracle Cloud | `http://169.254.169.254/opc/v1/instance/` | `availabilityDomain` |
| Alibaba Cloud | `http://100.100.100.200/latest/meta-data/` | `instance-id` |
| Kubernetes | `https://kubernetes.default.svc/api/v1/namespaces/default/secrets` | `items`, `kind` |

### Protocol Smuggling Payloads

Tests for dangerous protocol support:

| Protocol | Example | Risk |
|----------|---------|------|
| file:// | `file:///etc/passwd` | Local file read |
| gopher:// | `gopher://127.0.0.1:6379/_INFO` | Redis exploitation |
| dict:// | `dict://127.0.0.1:6379/INFO` | Redis info disclosure |
| ftp:// | `ftp://127.0.0.1:21/` | Internal FTP access |
| ldap:// | `ldap://127.0.0.1:389/` | Internal LDAP access |

## Configuration

### Basic Configuration

```typescript
import { SsrfDetector } from '@tzigger/kinetic';

const detector = new SsrfDetector({
  // Detection strategies
  enableReflected: true,
  enableTiming: true,
  enableOOB: false,
  
  // Payload categories
  enableWafBypass: true,
  enableCloudMetadata: true,
  enableProtocolSmuggling: true,
  
  // OOB configuration
  oobWaitMs: 3000,
  
  // Timing configuration
  timingThresholdMs: 5000,
  timingMultiplier: 5,
  
  // Admin panel paths
  adminPaths: ['/admin', '/administrator', '/manage'],
});
```

### OOB Configuration

```typescript
import { SsrfDetector, createOOBClient } from '@tzigger/kinetic';

// Using Interactsh
const oobClient = createOOBClient('interactsh', {
  server: 'oast.pro',
  token: 'your-token', // For private server
  pollInterval: 5000,
  maxPolls: 10,
  timeout: 30000,
});

const detector = new SsrfDetector({
  enableOOB: true,
  oobClient,
  oobWaitMs: 5000,
});

// Using MockOOBClient (for testing)
const mockClient = createOOBClient('mock', {
  callbackPort: 9999,
  baseUrl: 'http://localhost:9999',
});

const testDetector = new SsrfDetector({
  enableOOB: true,
  oobClient: mockClient,
});
```

### Configuration via Config File

```json
{
  "target": {
    "url": "https://example.com"
  },
  "detectors": {
    "enabled": ["ssrf"],
    "ssrf": {
      "enableReflected": true,
      "enableTiming": true,
      "enableOOB": true,
      "enableWafBypass": true,
      "enableCloudMetadata": true,
      "enableProtocolSmuggling": true,
      "oobClientType": "interactsh",
      "oobClientOptions": {
        "server": "oast.pro",
        "pollInterval": 5000,
        "maxPolls": 10
      },
      "oobWaitMs": 5000,
      "timingThresholdMs": 5000,
      "timingMultiplier": 5
    }
  }
}
```

## Usage Examples

### CLI Usage

```bash
# Basic SSRF scan
kinetic https://example.com --detectors ssrf

# With OOB detection
kinetic https://example.com --detectors ssrf --ssrf-oob

# With custom OOB server
kinetic https://example.com --detectors ssrf --ssrf-oob-server custom.server

# Disable WAF bypass
kinetic https://example.com --detectors ssrf --ssrf-no-waf-bypass
```

### Playwright Test Integration

```typescript
import { test, expect } from '@playwright/test';
import { SsrfDetector, createOOBClient } from '@tzigger/kinetic';

test('SSRF detection with OOB', async ({ page }) => {
  await page.goto('https://example.com');
  
  // Create OOB client
  const oobClient = createOOBClient('interactsh', {
    server: 'oast.pro',
  });
  
  // Create detector with OOB enabled
  const detector = new SsrfDetector({
    enableReflected: true,
    enableTiming: true,
    enableOOB: true,
    oobClient,
    oobWaitMs: 5000,
  });
  
  // Create attack surface
  const attackSurface = {
    id: 'test-surface',
    name: 'url',
    type: 'url-parameter' as const,
    value: 'http://example.com',
    context: 'url' as const,
    metadata: {},
  };
  
  // Run detection
  const vulnerabilities = await detector.detect({
    page,
    attackSurfaces: [attackSurface],
    baseUrl: 'https://example.com',
  });
  
  // Check results
  expect(vulnerabilities.length).toBeGreaterThan(0);
  
  // Cleanup
  await oobClient.cleanup();
});
```

### Programmatic Usage

```typescript
import { SsrfDetector, createOOBClient } from '@tzigger/kinetic';
import { Page } from 'playwright';

async function scanForSSRF(page: Page, url: string) {
  // Create OOB client
  const oobClient = createOOBClient('interactsh', {
    server: 'oast.pro',
  });
  
  // Create detector
  const detector = new SsrfDetector({
    enableReflected: true,
    enableTiming: true,
    enableOOB: true,
    oobClient,
    oobWaitMs: 5000,
    enableWafBypass: true,
    enableCloudMetadata: true,
    enableProtocolSmuggling: true,
  });
  
  // Create attack surface
  const attackSurface = {
    id: 'test-surface',
    name: 'url',
    type: 'url-parameter' as const,
    value: url,
    context: 'url' as const,
    metadata: {},
  };
  
  // Run detection
  const vulnerabilities = await detector.detect({
    page,
    attackSurfaces: [attackSurface],
    baseUrl: url,
  });
  
  // Cleanup
  await oobClient.cleanup();
  
  return vulnerabilities;
}
```

### Element Scanner Integration

```typescript
import { ElementScanner } from '@tzigger/kinetic';
import { SsrfDetector, createOOBClient } from '@tzigger/kinetic';

const scanner = new ElementScanner({
  baseUrl: 'https://example.com',
  elements: [{
    name: 'Stock API',
    locator: '#stockApi',
    type: 'form-input' as const,
    context: 'url' as const,
    testCategories: ['ssrf'],
  }],
});

// Register SSRF detector with OOB
const oobClient = createOOBClient('interactsh', {
  server: 'oast.pro',
});

scanner.registerDetectors([
  new SsrfDetector({
    enableReflected: true,
    enableTiming: true,
    enableOOB: true,
    oobClient,
    oobWaitMs: 5000,
  }),
]);

// Run scan
const result = await scanner.execute({ page });
```

## Best Practices

### 1. Use OOB Detection for Production Scans

OOB detection is the most reliable method for detecting blind SSRF:

```typescript
const detector = new SsrfDetector({
  enableOOB: true,
  oobClient: createOOBClient('interactsh'),
});
```

### 2. Enable All Payload Categories

For comprehensive testing, enable all payload categories:

```typescript
const detector = new SsrfDetector({
  enableWafBypass: true,
  enableCloudMetadata: true,
  enableProtocolSmuggling: true,
});
```

### 3. Adjust Timing Thresholds

Different applications have different response times. Adjust thresholds accordingly:

```typescript
const detector = new SsrfDetector({
  timingThresholdMs: 10000,  // Increase for slow applications
  timingMultiplier: 3,       // Lower multiplier for faster detection
});
```

### 4. Use Private OOB Server for Sensitive Scans

For sensitive applications, use a private OOB server:

```typescript
const oobClient = createOOBClient('interactsh', {
  server: 'your-private-server.com',
  token: 'your-auth-token',
});
```

### 5. Cleanup OOB Client

Always cleanup the OOB client after scanning:

```typescript
await oobClient.cleanup();
```

## Limitations

### 1. OOB Service Dependency

OOB detection requires an external OOB service. If the service is down, OOB detection will fail gracefully.

### 2. Network Latency

Timing-based detection can be affected by network latency. Use appropriate thresholds.

### 3. SPA Complexity

Deep logic in SPAs may not be discovered by the crawler. Use ElementScanner for specific components.

### 4. False Positives

Timing-based detection may produce false positives. Use OOB detection for confirmation.

### 5. Rate Limiting

Some applications may rate limit requests. Use the global rate limiter:

```typescript
import { getGlobalRateLimiter } from '@tzigger/kinetic';

const limiter = getGlobalRateLimiter();
limiter.setRateLimit(5); // 5 requests per second
```

## Troubleshooting

### OOB Detection Not Working

1. Check if OOB service is reachable:
   ```typescript
   const isReady = await oobClient.isReady();
   console.log('OOB client ready:', isReady);
   ```

2. Increase wait time:
   ```typescript
   const detector = new SsrfDetector({
     oobWaitMs: 10000, // Increase to 10 seconds
   });
   ```

3. Check OOB client logs for errors.

### Timing Detection Producing False Positives

1. Increase timing threshold:
   ```typescript
   const detector = new SsrfDetector({
     timingThresholdMs: 10000,
     timingMultiplier: 10,
   });
   ```

2. Disable timing detection and rely on OOB:
   ```typescript
   const detector = new SsrfDetector({
     enableTiming: false,
     enableOOB: true,
   });
   ```

### No Vulnerabilities Found

1. Enable all payload categories:
   ```typescript
   const detector = new SsrfDetector({
     enableWafBypass: true,
     enableCloudMetadata: true,
     enableProtocolSmuggling: true,
   });
   ```

2. Check if attack surfaces are being detected:
   ```typescript
   const surfaces = detector['filterUrlSurfaces'](attackSurfaces);
   console.log('Filtered surfaces:', surfaces);
   ```

3. Use ElementScanner for specific components:
   ```typescript
   const scanner = new ElementScanner({
     baseUrl: 'https://example.com',
     elements: [{
       name: 'URL Input',
       locator: '#url-input',
       type: 'form-input' as const,
       context: 'url' as const,
       testCategories: ['ssrf'],
     }],
   });
   ```

## References

- [OWASP SSRF](https://owasp.org/www-community/attacks/Server_Side_Request_Forgery)
- [PortSwigger SSRF](https://portswigger.net/web-security/ssrf)
- [ProjectDiscovery Interactsh](https://github.com/projectdiscovery/interactsh)
- [Burp Collaborator](https://portswigger.net/burp/documentation/collaborator)
- [CWE-918: Server-Side Request Forgery (SSRF)](https://cwe.mitre.org/data/definitions/918.html)
