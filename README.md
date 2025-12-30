# Kinetic Security Scanner

> High-performance Dynamic Application Security Testing (DAST) Engine powered by Playwright.

![Version](https://img.shields.io/badge/version-0.2.0-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![TypeScript](https://img.shields.io/badge/TypeScript-5.x-blue.svg)
![Playwright](https://img.shields.io/badge/Playwright-1.56-orange.svg)

## 🎯 Overview

**Kinetic** is a modular, extensible security testing framework designed for modern Single Page Applications (SPAs). Unlike traditional scanners that struggle with client-side rendering, Kinetic leverages Playwright to fully render applications before analyzing them.

It combines **passive network analysis** with **active vulnerability scanning** and uses a sophisticated **Verification Engine** to rigorously test findings and reduce false positives.

### Key Features (v0.2.0)

- 🧠 **Smart SPA Scanning**: Framework-aware waiting (Angular/React/Vue) ensures the page is stable before testing.
- 🔍 **Triple-Mode Scanning**:
  - **Active**: Crawling, form discovery, and payload injection.
  - **Passive**: Real-time network traffic analysis (PII, Headers, Auth).
  - **Element**: Targeted scanning of specific DOM elements via locators.
- ✅ **Active Verification**: Uses statistical timing analysis and response diffing to verify blind injections (SQLi, Command Injection).
- 🛡️ **Production Guardrails**: "Safe Mode" automatically filters destructive payloads (e.g., `DROP TABLE`) on non-local targets.
- 🔌 **Plugin Architecture**: Easily extendable with custom Detectors and Reporters.

## 🚀 Quick Start

### 1. CLI Usage

Install globally to use the `kinetic` command:

```bash
npm install -g @tzigger/kinetic
```

Run scans immediately:

```bash
# Basic Active Scan (Crawls and tests inputs)
kinetic https://example.com

# Passive Scan (Fast - Checks headers, cookies, PII leaks)
kinetic https://example.com --scan-type passive

# Active Scan with Authentication
kinetic https://example.com --auth "admin:password123"

# Targeted Element Scan (Requires config)
kinetic -c kinetic.config.json
```

### 2. Playwright Test Integration

Install as a dev dependency to use within your existing E2E tests:

```bash
npm install --save-dev @tzigger/kinetic
```

```typescript
import { test, expect } from '@playwright/test';
import { runActiveSecurityScan, assertNoVulnerabilities } from '@tzigger/kinetic/testing';

test('login form security', async ({ page }) => {
  await page.goto('https://myapp.com/login');
  
  // Scans inputs found on the current page state
  const vulns = await runActiveSecurityScan(page, {
    detectors: 'sql',           // Limit to SQL Injection
    aggressiveness: 'medium'
  });
  
  // Fail test if vulnerabilities are found
  assertNoVulnerabilities(vulns);
});
```

## 📋 Architecture

Kinetic uses a layered architecture to separate orchestration, execution, and strategy.

```
┌─────────────────────────────────────────────────┐
│              CLI / Testing Helper                │
└─────────────────────────────────────────────────┘
                        │
┌─────────────────────────────────────────────────┐
│           Core Engine Layer                      │
│  ScanEngine │ BrowserManager │ ConfigManager    │
└─────────────────────────────────────────────────┘
                        │
        ┌───────────────┼───────────────┐
        ▼               ▼               ▼
┌──────────────┐ ┌──────────────┐ ┌──────────────┐
│ Active       │ │ Element      │ │ Passive      │
│ Scanner      │ │ Scanner      │ │ Scanner      │
└───────┬──────┘ └──────┬───────┘ └──────┬───────┘
        │               │                │
        ▼               ▼                ▼
┌──────────────────────────────────────────────────┐
│            Detector Layer (Strategy)             │
│   (SQLi, XSS, SSRF, Headers, Sensitive Data)     │
└──────────────────────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────┐
│           Verification Engine                    │
│   (Time-based Checks, Response Diffing)          │
└─────────────────────────────────────────────────┘
```

## 🛡️ Safety Features & Production Guardrails

Kinetic is designed to be safe by default.

### Safe Mode
Enabled automatically when scanning non-local targets (e.g., not `localhost` or `127.0.0.1`).
- **Blocks**: `DROP`, `DELETE`, `TRUNCATE`, `GRANT`, System Commands.
- **Allows**: `OR 1=1`, `SLEEP()`, `<script>alert(1)</script>`.

### Environment Detection
The `TargetValidator` analyzes your URL before scanning starts.
- **Production**: Checks for HTTPS, standard ports, and forces Safe Mode.
- **Local**: Allows full aggressive testing.

*Read more in the [Safe Mode Guide](./docs/SAFE-MODE.md).*

## 🔧 Configuration

Create a `kinetic.config.json` for advanced control:

```json
{
  "target": {
    "url": "https://example.com",
    "crawlDepth": 2,
    "maxPages": 10
  },
  "scanners": {
    "active": {
      "enabled": true,
      "safeMode": true,
      "parallelism": 3
    }
  },
  "detectors": {
    "enabled": ["sql-injection", "xss", "sensitive-data"],
    "disabled": ["cookie-security"]
  },
  "reporting": {
    "formats": ["json", "html", "sarif"],
    "outputDir": "./reports"
  }
}
```

## 📚 Documentation

| Document | Description |
|----------|-------------|
| **[Developer Guide](./docs/DEVELOPER-GUIDE.md)** | **Start here.** Complete guide to API, architecture, and usage. |
| **[Element Scanner](./docs/ELEMENT-SCANNER.md)** | Guide for targeted testing of specific DOM elements. |
| **[API Reference](./docs/API-QUICK-REFERENCE.md)** | Quick lookups for classes, interfaces, and methods. |
| **[Safe Mode](./docs/SAFE-MODE.md)** | Details on production guardrails and payload filtering. |
| **[Migration Guide](./docs/MIGRATION-GUIDE.md)** | Upgrading from v0.1.x to v0.2.0. |

## 📦 Supported Vulnerabilities

| Category | Detectors |
|----------|-----------|
| **Injection** | SQLi (Boolean/Error/Time), Command Injection, SSTI, XML |
| **XSS** | Reflected, Stored, DOM-based, JSON-based, Angular Template |
| **Access Control** | Path Traversal, SSRF (Cloud Metadata/Local) |
| **Config** | Security Headers, Cookie Flags, CORS, Error Disclosure |
| **Data** | PII Exposure (Emails, Keys, Tokens, Credentials) |

## 🤝 Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](./CONTRIBUTING.md).

## 📄 License

MIT License
