# DAST Engine Architecture

## System Overview

The DAST (Dynamic Application Security Testing) Engine is built on a modular, layered architecture that enables extensibility, maintainability, and scalability. It leverages Playwright for browser automation and implements multiple detection techniques for OWASP Top 10 vulnerabilities.

## Architectural Layers

### 1. Testing Layer
- **Helper Functions**: `runActiveSecurityScan()`, `runPassiveSecurityScan()`, `combinedSecurityScan()`
- **Playwright Integration**: Seamless integration with Playwright Test framework
- **SPA Support**: Existing page reuse for Single Page Applications

### 2. Core Layer
- **ScanEngine**: Main orchestrator coordinating scanners and detectors
- **BrowserManager**: Playwright lifecycle management and context handling
- **ConfigurationManager**: Configuration validation, loading, and merging
- **Interfaces**: IScanner, IDetector, IReporter for extensibility

### 3. Scanner Layer
- **ActiveScanner**: DOM manipulation, payload injection, and fuzzing
- **DomExplorer**: Attack surface discovery and SPA framework detection
- **PayloadInjector**: Intelligent payload injection with encoding
- **PassiveScanner**: Network traffic interception (planned)

### 4. Detector Layer
- **SqlInjectionDetector**: Error-based, boolean-based, time-based, union-based, authentication bypass
- **XssDetector**: Reflected, stored, DOM-based, JSON XSS, Angular template injection
- **ErrorBasedDetector**: Stack trace disclosure, database errors, framework errors
- Base classes for extensibility

### 5. Reporter Layer
- **JSONReporter**: Structured JSON output
- **HTMLReporter**: Human-readable HTML reports
- **SARIFReporter**: SARIF format for CI/CD integration
- **ConsoleReporter**: Terminal output with formatting

## Current Implementation Status

### ✅ Implemented
- Core scanning engine with SPA support
- Active scanner with DOM exploration
- SQL injection detection (5 techniques)
- XSS detection (5 types)
- Error disclosure detection
- Multiple report formats (JSON, HTML, SARIF)
- Playwright test integration
- Configuration management

### 🚧 Partial Implementation
- Passive scanner (architecture ready, detectors partial)
- Plugin system (interfaces defined, registry partial)

### 📋 Planned
- Machine learning false positive reduction
- Distributed scanning support
- WebSocket security testing
- API fuzzing capabilities

## Design Patterns

### 1. Strategy Pattern
Used in detectors to allow different detection algorithms to be swapped at runtime.

```typescript
interface IActiveDetector {
  detect(context: ActiveDetectorContext): Promise<Vulnerability[]>;
}

class ActiveScanner {
  private detectors: IActiveDetector[] = [];
  
  registerDetectors(detectors: IActiveDetector[]): void {
    this.detectors.push(...detectors);
  }
}
```

### 2. Factory Pattern
Helper functions act as factories for creating configured scan engines.

```typescript
async function runActiveSecurityScan(
  target: string | Page,
  options?: ActiveScanOptions
): Promise<Vulnerability[]> {
  const engine = new ScanEngine();
  const scanner = new ActiveScanner();
  scanner.registerDetectors([
    new SqlInjectionDetector(),
    new XssDetector(),
    new ErrorBasedDetector()
  ]);
  engine.registerScanner(scanner);
  return (await engine.scan()).vulnerabilities;
}
```

### 3. Builder Pattern
Configuration building with fluent API.

```typescript
const config: ScanConfiguration = {
  target: {
    url: 'https://example.com',
    scope: {
      maxDepth: 2,
      maxPages: 5
    }
  },
  scanners: {
    active: {
      enabled: true,
      aggressiveness: AggressivenessLevel.MEDIUM
    }
  }
};
```

### 4. Singleton Pattern
Browser instance management to reuse contexts.

```typescript
class BrowserManager {
  private browsers: Map<string, Browser> = new Map();
  
  async createBrowser(scanId: string): Promise<Browser> {
    if (!this.browsers.has(scanId)) {
      this.browsers.set(scanId, await chromium.launch());
    }
    return this.browsers.get(scanId)!;
  }
}
```

### 5. Adapter Pattern
SPA mode adapts existing Playwright Page objects to the scanning engine.

```typescript
// Helper adapts Page object to scanning engine
if (typeof target !== 'string') {
  engine.setExistingPage(target); // Adapter
}
```

## Data Flow

### Standard Flow (URL String)
1. **Initialization**
   - Helper function receives URL string
   - Create ScanEngine and scanners
   - Load configuration

2. **Browser Launch**
   - BrowserManager initializes Playwright
   - Create browser context and page
   - Navigate to target URL

3. **Active Scanning**
   - DomExplorer discovers attack surfaces (forms, inputs, APIs)
   - Categorize surfaces by injection context
   - For each surface:
     - PayloadInjector sends payloads
     - Detectors analyze responses
     - Collect vulnerabilities

4. **Reporting**
   - Aggregate results from all detectors
   - Generate reports in specified formats
   - Return vulnerability array

### SPA Flow (Existing Page Object)
1. **Initialization**
   - Helper function receives Page object
   - Create ScanEngine and scanners
   - Call `engine.setExistingPage(page)`

2. **Browser Reuse**
   - Skip browser creation
   - Reuse existing page and context
   - Use `page.url()` as starting point

3. **Active Scanning**
   - Check if already on target URL (skip navigation)
   - Detect SPA framework (Angular/React/Vue)
   - Extract hash routes (`/#/login`, `/#/search`)
   - Discover attack surfaces on current page
   - For each surface:
     - Inject payloads
     - Wait for XHR/network requests
     - Analyze JSON responses
     - Collect vulnerabilities

4. **Cleanup**
   - Skip browser closure (test owns the page)
   - Return results to test

## Attack Surface Discovery

### Types of Attack Surfaces

1. **Form Inputs**
   - `<input type="text">`
   - `<textarea>`
   - `<select>`

2. **URL Parameters**
   - Query strings
   - Hash parameters (SPA routes)

3. **API Endpoints**
   - Intercepted XHR/Fetch requests
   - REST API calls
   - JSON request bodies

4. **Cookies**
   - Session cookies
   - Tracking cookies
   - Custom cookies

5. **JSON Bodies**
   - API request payloads
   - GraphQL queries

### Prioritization

Attack surfaces are prioritized based on:
- **Type**: API endpoints > Forms > URL params
- **Context**: Known vulnerable patterns (id, search, query)
- **Visibility**: User-facing inputs prioritized
- **Framework**: API routes (`/rest/`, `/api/`) scored higher

## Component Interactions

```
┌──────────────────┐
│ Test File        │
│ (Playwright)     │
└────────┬─────────┘
         │ calls runActiveSecurityScan(page)
         ▼
┌──────────────────────────┐
│ Helper Function          │
│ (testing/helpers.ts)     │
└────────┬─────────────────┘
         │ creates
         ▼
┌──────────────────────────┐
│ ScanEngine               │◄──── setExistingPage(page)
└────────┬─────────────────┘
         │ registers
         ▼
┌──────────────────────────┐
│ ActiveScanner            │
└────────┬─────────────────┘
         │ uses
         ├──────────────┬──────────────┐
         ▼              ▼              ▼
┌─────────────┐  ┌─────────────┐  ┌──────────────┐
│DomExplorer  │  │PayloadInj.. │  │BrowserManager│
└──────┬──────┘  └──────┬──────┘  └──────────────┘
       │                │
       │ discovers      │ injects
       ▼                ▼
┌──────────────────────────────┐
│ Attack Surfaces              │
│ - Forms                      │
│ - URL params                 │
│ - API endpoints              │
│ - Cookies                    │
└────────┬─────────────────────┘
         │ tests
         ▼
┌──────────────────────────────┐
│ Detectors                    │
│ - SqlInjectionDetector       │
│ - XssDetector                │
│ - ErrorBasedDetector         │
└────────┬─────────────────────┘
         │ returns
         ▼
┌──────────────────────────────┐
│ Vulnerabilities[]            │
└────────┬─────────────────────┘
         │ optionally formats
         ▼
┌──────────────────────────────┐
│ Reporters                    │
│ - JSON, HTML, SARIF          │
└──────────────────────────────┘
```

## Extension Points

1. **Custom Detectors**: Implement `IActiveDetector` or `IPassiveDetector`
2. **Custom Reporters**: Implement `IReporter` interface
3. **Custom Patterns**: Add to payload files in `config/payloads/`
4. **Custom Aggressiveness**: Define custom `AggressivenessLevel` mappings
5. **Helper Functions**: Create domain-specific wrappers

### Example: Custom Detector

```typescript
import { IActiveDetector, ActiveDetectorContext } from '../core/interfaces/IActiveDetector';
import { Vulnerability } from '../types/vulnerability';

export class CustomDetector implements IActiveDetector {
  readonly name = 'Custom Detector';
  readonly description = 'Detects custom vulnerabilities';
  readonly version = '1.0.0';

  async detect(context: ActiveDetectorContext): Promise<Vulnerability[]> {
    const { page, attackSurfaces, baseUrl } = context;
    // Your detection logic
    return [];
  }
}
```

### Example: Custom Helper

```typescript
export async function runSqlInjectionScan(
  page: Page
): Promise<Vulnerability[]> {
  return runActiveSecurityScan(page, {
    detectors: 'sql',
    aggressiveness: AggressivenessLevel.HIGH,
    maxPages: 5,
  });
}
```

## Security Considerations

- All network traffic is analyzed locally (no external data transmission)
- No data is sent to external servers
- Configurable scope to prevent unintended scanning
- Rate limiting to avoid DoS
- Authentication support for protected resources
- Payload encoding to minimize false positives
- Secure cookie handling (HttpOnly, Secure flags checked)
- SPA mode respects user authentication state

## Performance Optimizations

1. **Parallel Detection**: Multiple detectors run concurrently
2. **Smart Payload Selection**: Context-aware payloads (numeric vs string)
3. **Response Caching**: Baseline measurements reused
4. **Configurable Limits**: `maxPages`, `maxDepth` for scope control
5. **Timeout Management**: Per-page and per-test timeouts
6. **Incremental Reporting**: Vulnerabilities reported as discovered
7. **Browser Reuse**: SPA mode reuses existing browser contexts
8. **Reduced Sleep Times**: Time-based SQLi uses 2s delays (down from 5s)

## Known Limitations

### SPA Testing
- **SQLi Detection**: May miss SQLi in complex Angular/React apps
- **API Discovery**: Passive API interception not yet implemented
- **Framework-Specific**: Angular zone stability not yet handled
- **Workaround**: Use hybrid testing (framework + direct API tests)

See [SPA Testing Limitations](./SPA-TESTING-LIMITATIONS.md) for details.

### Performance
- Default scans can take 4-5 minutes for comprehensive coverage
- Recommended timeout: 5-10 minutes for full scans
- Use `maxPages` and `maxDepth` to control scope

### Detection Accuracy
- Time-based SQLi may have false positives on slow networks
- XSS in cookies may include false positives for analytics
- Error disclosure may include non-security errors

## Implementation Details

### SQL Injection Detection

**Techniques**:
1. **Error-based**: Database error pattern matching (Sequelize, SQLite, MySQL, etc.)
2. **Boolean-based**: True vs false condition comparison with JSON-aware diffing
3. **Time-based**: Response delay detection with baseline averaging
4. **Union-based**: Query stacking detection
5. **Authentication Bypass**: Login SQLi with token/redirect/UI detection

**Payloads**: Context-aware (numeric vs string), database-specific

### XSS Detection

**Types**:
1. **Reflected**: Immediate payload reflection in response
2. **Stored**: Persistent XSS (requires re-navigation)
3. **DOM-based**: JavaScript-executed XSS
4. **JSON XSS**: Unescaped payloads in JSON responses
5. **Angular Template Injection**: `{{7*7}}` detection

**Payloads**: Script tags, event handlers, template injection

### Error Disclosure Detection

**Patterns**:
- Stack traces (at file.js:line:col)
- Database errors (SQL, Sequelize, TypeORM, Prisma)
- Framework errors (Express, Next.js, Angular)
- Path disclosure
- Version information

## Future Enhancements

### Planned for v0.2.0
- [ ] Full passive scanner implementation
- [ ] Network request interception for API discovery
- [ ] Angular zone stability awareness
- [ ] Reduced scan times (payload optimization)
- [ ] Parallel attack surface testing

### Long-term Roadmap
- [ ] Machine learning-based false positive reduction
- [ ] Distributed scanning support
- [ ] GraphQL API scanning
- [ ] WebSocket security testing
- [ ] Enhanced API fuzzing capabilities
- [ ] Real-time vulnerability notifications
- [ ] Historical trend analysis
- [ ] OWASP ZAP integration
- [ ] Burp Suite import/export

## References

- [OWASP Top 10 2025](https://owasp.org/www-project-top-ten/)
- [Playwright Documentation](https://playwright.dev/)
- [CWE Database](https://cwe.mitre.org/)
- [SARIF Specification](https://sarifweb.azurewebsites.net/)

---

**Last Updated**: November 27, 2025  
**Framework Version**: 0.1.0-beta.1
