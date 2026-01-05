# Kinetic API Quick Reference

> Cheat sheet for Kinetic v0.2.0 classes, interfaces, and configurations.

## 🧪 Playwright Test Helpers

Import path: `@tzigger/kinetic/testing`

### `runActiveSecurityScan(target, options)`
Performs crawling and payload injection.

```typescript
const vulns = await runActiveSecurityScan(page, {
  detectors: 'sql',           // 'all' | 'sql' | 'xss' | 'errors'
  aggressiveness: 'medium',   // 'low' | 'medium' | 'high'
  maxPages: 3,
  submitForms: true
});
```

### `runPassiveSecurityScan(target, options)`
Analyzes network traffic without modification.

```typescript
const vulns = await runPassiveSecurityScan('https://example.com', {
  detectors: 'headers',       // 'all' | 'headers' | 'data' | 'cookies'
  maxPages: 1
});
```

### `assertNoVulnerabilities(vulns, maxSeverity?)`
Assertion helper for tests.

```typescript
// Fails if HIGH or CRITICAL issues found
assertNoVulnerabilities(vulns, VulnerabilitySeverity.HIGH);
```

---

## 🏗️ Core Classes

Import path: `@tzigger/kinetic`

### `ScanEngine`
The main orchestrator.

```typescript
const engine = new ScanEngine();
engine.registerScanner(new ActiveScanner());
await engine.loadConfiguration(config);
const result = await engine.scan();
await engine.cleanup();
```

### `ActiveScanner`
Crawls and injects payloads.

```typescript
const scanner = new ActiveScanner({
  maxDepth: 3,
  aggressiveness: 'medium',
  safeMode: true
});
```

### `ElementScanner` (v0.2)
Targeted scanning of specific DOM elements via locators.

```typescript
const scanner = new ElementScanner({
  baseUrl: 'http://localhost:3000',
  elements: [
    { 
      locator: '#search-input', 
      name: 'Search Bar', 
      type: AttackSurfaceType.FORM_INPUT 
    }
  ]
});
```

---

## ⚙️ Configuration Interfaces

### `ScanConfiguration`
Used by `ScanEngine` and `kinetic.config.json`.

```typescript
interface ScanConfiguration {
  target: {
    url: string;
    authentication?: {
      type: 'form' | 'basic' | 'bearer';
      credentials?: { username?: string; password?: string; token?: string };
      loginPage?: { url: string };
    };
  };
  scanners: {
    active: { 
      enabled: boolean; 
      safeMode?: boolean; 
      parallelism?: number;
    };
    passive: { enabled: boolean };
  };
  detectors: {
    enabled: string[]; // e.g. ['sql-injection', 'xss', 'sensitive-data']
    disabled: string[];
    tuning?: Record<string, any>;
  };
  reporting: {
    formats: ('json' | 'html' | 'sarif' | 'console')[];
    outputDir: string;
  };
}
```

### `ElementScanConfig`
Used specifically by `ElementScanner`.

```typescript
interface ElementScanConfig {
  baseUrl: string;
  elements: ElementTarget[];
  pageUrl?: string;        // Optional: Navigate here before scanning
  pageTimeout?: number;
  authentication?: PageAuthConfig;
}

interface ElementTarget {
  locator: string;         // Playwright selector
  name: string;
  type: AttackSurfaceType; // FORM_INPUT, URL_PARAMETER, API_PARAM, JSON_BODY
  context?: InjectionContext; // SQL, HTML, JAVASCRIPT
  testCategories?: string[]; // Limit to ['xss', 'sql']
}
```

---

## 💻 CLI Reference

Command: `kinetic`

| Flag | Description | Example |
|------|-------------|---------|
| `[url]` | Target URL | `kinetic http://target.com` |
| `-c, --config <file>` | Load JSON config | `kinetic -c kinetic.config.json` |
| `--scan-type <type>` | `active`, `passive`, or `both` | `kinetic --scan-type passive` |
| `--auth <creds>` | Basic/Form auth | `kinetic --auth user:pass` |
| `--safemode-disable`| **Dangerous**: Allow destructive payloads | `kinetic --safemode-disable` |
| `--parallel <n>` | Parallel workers | `kinetic --parallel 4` |
| `--rate-limit <n>` | Requests per second | `kinetic --rate-limit 5` |
| `-f, --formats` | Output formats | `kinetic -f json,html` |
| `--headless` | Run hidden browser | `kinetic --headless` |

---

## 🔑 Enums

Import path: `@tzigger/kinetic/types`

### `VulnerabilitySeverity`
`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`

### `VulnerabilityCategory`
`INJECTION`, `XSS`, `DATA_EXPOSURE`, `SECURITY_MISCONFIGURATION`, `BROKEN_AUTHENTICATION`, ...

### `AttackSurfaceType`
`FORM_INPUT`, `URL_PARAMETER`, `JSON_BODY`, `API_PARAM`, `COOKIE`, `HEADER`

---

## 🚦 Rate Limiter

Import path: `@tzigger/kinetic`

### `getGlobalRateLimiter()`
Returns the singleton RateLimiter instance.

```typescript
import { getGlobalRateLimiter } from '@tzigger/kinetic';

const limiter = getGlobalRateLimiter();
limiter.setRateLimit(10);          // 10 requests per second
await limiter.waitForToken();       // Wait for available token
limiter.handleResponse(statusCode); // Handle 429 backoff
```

### RateLimiter Methods

| Method | Description |
|--------|-------------|
| `setRateLimit(rps)` | Set requests per second limit |
| `waitForToken()` | Wait until a token is available |
| `handleResponse(status)` | Process response status for 429 backoff |
| `getStats()` | Get current limiter statistics |
