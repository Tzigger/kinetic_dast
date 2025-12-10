# Kinetic Security Scanner

> High-performance Dynamic Application Security Testing (DAST) Engine powered by Playwright

![Version](https://img.shields.io/badge/version-0.1.0-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![TypeScript](https://img.shields.io/badge/TypeScript-5.3-blue.svg)
![Playwright](https://img.shields.io/badge/Playwright-1.56-orange.svg)

## 🎯 Overview

**Kinetic** is a powerful, modular, and extensible security testing framework that combines **passive network analysis** with **active vulnerability scanning** to detect security issues in web applications.

### Key Features

- 🔍 **Dual Scanning Modes**
  - **Passive Scanner**: Network traffic interception and analysis
  - **Active Scanner**: Input fuzzing and form manipulation

- 🛡️ **Comprehensive Detection**
  - SQL Injection
  - Cross-Site Scripting (XSS)
  - Command Injection
  - Sensitive Data Exposure
  - Insecure Transmission
  - Security Headers
  - And more...

- 🔌 **Plugin Architecture**
  - Custom scanners
  - Custom detectors
  - Extensible patterns

- 📊 **Multiple Report Formats**
  - JSON (machine-readable)
  - HTML (human-friendly)
  - SARIF (CI/CD integration)
  - Console (real-time)
  - Markdown

- ⚙️ **Highly Configurable**
  - Configuration profiles
  - Custom payloads
  - Scope management
  - Authentication support

## 🚀 Quick Start

### For Framework Users

Install Kinetic in your project:

```bash
npm install https://github.com/Tzigger/kinetic_dast.git
```

Use in your Playwright tests:

```typescript
import { test, expect } from '@playwright/test';
import { 
  runActiveSecurityScan, 
  runPassiveSecurityScan,
  assertNoVulnerabilities,
  VulnerabilitySeverity 
} from '@tzigger/kinetic';

// Example 1: Quick passive scan for security headers
test('should have security headers', async () => {
  const vulnerabilities = await runPassiveSecurityScan('https://myapp.com', {
    detectors: 'headers'
  });
  
  // Assert no high/critical issues
  assertNoVulnerabilities(vulnerabilities, VulnerabilitySeverity.HIGH);
});

// Example 2: Active scan for SQL injection
test('login should not have SQL injection', async () => {
  const vulnerabilities = await runActiveSecurityScan('https://myapp.com/login', {
    detectors: 'sql',
    maxPages: 1
  });
  
  expect(vulnerabilities).toHaveLength(0);
});

// Example 3: Comprehensive security check
test('full security scan', async () => {
  // Fast passive scan first
  const passiveVulns = await runPassiveSecurityScan('https://myapp.com');
  
  // Then deeper active scan
  const activeVulns = await runActiveSecurityScan('https://myapp.com', {
    aggressiveness: 'medium',
    maxPages: 3
  });
  
  const allVulns = [...passiveVulns, ...activeVulns];
  expect(allVulns.filter(v => v.severity === 'critical')).toHaveLength(0);
});
```

📖 **See [Developer Guide](./docs/DEVELOPER-GUIDE.md) for complete usage documentation**

---

### Using the Kinetic CLI

To use the `kinetic` command globally:

```bash
# Clone and setup
git clone https://github.com/tzigger/kinetic.git
cd kinetic
npm install

# Build the project
npm run build

# Link the CLI globally (may require sudo on macOS/Linux)
npm link
# or
sudo npm link

# Now you can use kinetic anywhere
kinetic --help
```

Run scans with the CLI:

```bash
# Passive scan (fast, non-intrusive)
kinetic https://example.com --scan-type passive

# Active scan (comprehensive)
kinetic https://example.com --scan-type active

# Both passive and active
kinetic https://example.com --scan-type both

# With custom output and formats
kinetic https://example.com --output ./my-reports --formats html,json,sarif

# Use a configuration file
kinetic --config ./config/default.config.json

# Use a profile
kinetic https://example.com --config ./config/profiles/aggressive.json
```

---

### For Framework Development

Run development commands:

```bash
# Run tests
npm test

# Run a development scan (without installing globally)
npm run dev -- https://example.com --scan-type passive

# Use npm start for the built CLI
npm start -- https://example.com --scan-type active
```

### Programmatic Usage

```typescript
import { ScanEngine } from './src/core/engine/ScanEngine';
import { ConfigurationBuilder } from './src/core/config/ConfigurationBuilder';

// Build configuration
const config = new ConfigurationBuilder()
  .setTarget('https://example.com')
  .enablePassiveScanner()
  .enableActiveScanner('medium')
  .setReportFormats(['json', 'html'])
  .build();

// Run scan
const engine = new ScanEngine(config);
const results = await engine.run();

console.log(`Found ${results.vulnerabilities.length} vulnerabilities`);
```

## 📋 Architecture

### High-Level Design

```
┌─────────────────────────────────────────────────┐
│              CLI Interface Layer                 │
└─────────────────────────────────────────────────┘
                        │
┌─────────────────────────────────────────────────┐
│           Core Engine Layer                      │
│  ScanEngine │ BrowserManager │ ConfigManager    │
└─────────────────────────────────────────────────┘
                        │
        ┌───────────────┴───────────────┐
        ▼                               ▼
┌──────────────────┐          ┌──────────────────┐
│ Passive Scanner  │          │  Active Scanner  │
└──────────────────┘          └──────────────────┘
        │                               │
        ▼                               ▼
┌──────────────────────────────────────────────────┐
│            Detector Layer (Strategy)             │
└──────────────────────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────┐
│           Reporting Layer                        │
└─────────────────────────────────────────────────┘
```

### Project Structure

```
src/
├── core/              # Core engine and interfaces
├── scanners/          # Passive and active scanners
├── detectors/         # Vulnerability detectors
├── reporters/         # Report generators
├── utils/             # Utilities and helpers
├── types/             # TypeScript type definitions
├── plugins/           # Plugin system
└── cli/               # CLI interface

config/                # Configuration files
├── default.config.json
├── profiles/          # Scan profiles
└── payloads/          # Attack payloads

docs/                  # Documentation
examples/              # Example usage
tests/                 # Test suites
```

## 🔧 Configuration

### Configuration File

Create a `config.json`:

```json
{
  "target": {
    "url": "https://example.com",
    "crawlDepth": 2,
    "maxPages": 50
  },
  "scanners": {
    "passive": {
      "enabled": true,
      "interceptTypes": ["xhr", "fetch", "document"]
    },
    "active": {
      "enabled": true,
      "aggressiveness": "medium",
      "payloadSets": ["sql-injection", "xss"]
    }
  },
  "reporting": {
    "formats": ["json", "html"],
    "outputDir": "./reports"
  }
}
```

### Profiles

Use pre-configured profiles:

- `passive-only` - Non-intrusive scanning
- `aggressive` - Comprehensive testing
- `quick-scan` - Fast vulnerability check

## 🔌 Plugin Development

Create custom detectors:

```typescript
import { BaseDetector } from './src/core/interfaces/IDetector';
import { Vulnerability, VulnerabilityCategory } from './src/types';

export class CustomDetector extends BaseDetector {
  readonly id = 'custom-detector';
  readonly name = 'Custom Vulnerability Detector';
  readonly version = '1.0.0';
  readonly category = VulnerabilityCategory.CUSTOM;
  readonly description = 'Detects custom vulnerabilities';

  async detect(data: unknown): Promise<Vulnerability[]> {
    // Your detection logic here
    return [];
  }

  getPatterns(): RegExp[] {
    return [/your-pattern/gi];
  }
}
```

## 📊 Reports

### Sample Output

```
┌─────────────────────────────────────────────────┐
│          Kinetic Security Scan Report           │
├─────────────────────────────────────────────────┤
│ Target: https://example.com                      │
│ Duration: 2m 34s                                 │
│ Pages Scanned: 15                                │
├─────────────────────────────────────────────────┤
│ Vulnerabilities Found: 8                         │
│   Critical: 2                                    │
│   High: 3                                        │
│   Medium: 2                                      │
│   Low: 1                                         │
└─────────────────────────────────────────────────┘
```

## 🧪 Testing

### Helper Functions

The framework provides two focused helper functions for easy integration into your Playwright tests:

#### `runActiveSecurityScan(url, options?)`
Tests for **injection vulnerabilities** (SQL injection, XSS, command injection, etc.)

```typescript
const vulnerabilities = await runActiveSecurityScan('https://myapp.com/search', {
  detectors: 'sql',           // 'all', 'sql', 'xss', or 'errors'
  aggressiveness: 'low',      // 'low', 'medium', or 'high'
  maxPages: 2,                // Number of pages to scan
  headless: true              // Run browser in headless mode
});
```

**Use when:** Testing forms, search boxes, login pages, or any user input

**Performance:** 30-120s depending on aggressiveness and pages

#### `runPassiveSecurityScan(url, options?)`
Analyzes **traffic patterns** (headers, data exposure, cookies, transmission security)

```typescript
const vulnerabilities = await runPassiveSecurityScan('https://myapp.com', {
  detectors: 'headers',       // 'all', 'headers', 'transmission', 'data', or 'cookies'
  headless: true              // Run browser in headless mode
});
```

**Use when:** Checking security headers, HTTPS usage, sensitive data leaks, cookie security

**Performance:** 3-5s (very fast)

#### `assertNoVulnerabilities(vulnerabilities, maxSeverity?)`
Assertion helper to fail tests if vulnerabilities are found

```typescript
// Fail if ANY vulnerabilities found
assertNoVulnerabilities(vulnerabilities);

// Fail only if HIGH or CRITICAL vulnerabilities found
assertNoVulnerabilities(vulnerabilities, VulnerabilitySeverity.HIGH);
```

### Running Tests

```bash
# Run all tests
npm test

# Run specific test suites
npm run test:unit
npm run test:integration
npm run test:e2e

# Coverage report
npm run test:coverage
```

## 🛠️ Development

```bash
# Build the project
npm run build

# Watch mode
npm run build:watch

# Lint code
npm run lint
npm run lint:fix

# Format code
npm run format
npm run format:check
```

## 📚 Documentation

### For Users
- [Developer Guide](./docs/DEVELOPER-GUIDE.md) - **Complete guide for using the framework in your projects**
- [API Quick Reference](./docs/API-QUICK-REFERENCE.md) - Quick reference for all APIs and methods

### For Contributors
- [Architecture](./docs/architecture.md) - System design and patterns
- [Plugin Development](./docs/plugin-development.md) - Creating custom plugins

## 🤝 Contributing

Contributions are welcome! Please read our contributing guidelines before submitting PRs.

## 📄 License

MIT License - see LICENSE file for details

## ⚠️ Disclaimer

This tool is for authorized security testing only. Always obtain proper authorization before scanning any application you don't own.

## 🔗 Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Playwright Documentation](https://playwright.dev/)
- [CWE Database](https://cwe.mitre.org/)

## 📧 Support

For issues and questions, please use the GitHub issue tracker.

---


