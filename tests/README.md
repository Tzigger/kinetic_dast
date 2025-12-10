# Kinetic DAST - Test Suite

This folder contains the test suite for validating Kinetic's security scanning capabilities.

## 📁 Test Structure

```
tests/
├── integration/       # Integration tests against real vulnerable apps
│   └── bwapp-element-scanner.spec.ts
├── unit/             # Unit tests for individual modules
│   ├── dom-explorer.test.ts
│   ├── logger.test.ts
│   └── verification-timeout.test.ts
├── e2e/              # End-to-end CLI tests
│   └── cli.test.ts
└── setup.ts          # Test setup utilities
```

## 🚀 Running Tests

### Prerequisites

For integration tests against bWAPP:
```bash
# Start bWAPP Docker container
docker run -d -p 8080:80 raesene/bwapp

# Initialize database (first time only)
# Visit http://localhost:8080/install.php and click "Install"
```

### Run All Tests

```bash
# Run all tests
npm test

# Run with specific browser
npx playwright test --project=chromium
```

### Run Specific Test Suites

```bash
# Integration tests (requires bWAPP)
npx playwright test tests/integration/ --project=chromium

# Unit tests
npm run test:unit

# CLI tests
npm run test:e2e
```

### Run a Single Test File

```bash
npx playwright test tests/integration/bwapp-element-scanner.spec.ts --project=chromium
```

## 📋 Test Categories

### Integration Tests (`tests/integration/`)

These tests validate that Kinetic correctly detects vulnerabilities on real vulnerable applications.

**`bwapp-element-scanner.spec.ts`** - Core validation tests:
- ✅ SQL Injection detection on form inputs
- ✅ XSS detection on vulnerable fields
- ✅ Command Injection detection
- ✅ Detector filtering by test categories

Requirements: bWAPP running on `http://localhost:8080`

### Unit Tests (`tests/unit/`)

Test individual modules in isolation:

| Test File | What It Tests |
|-----------|--------------|
| `dom-explorer.test.ts` | Attack surface discovery from DOM and network requests |
| `logger.test.ts` | Logging utility functionality |
| `verification-timeout.test.ts` | Timeout management and verification engine |

### E2E Tests (`tests/e2e/`)

Test the CLI tool end-to-end:

| Test File | What It Tests |
|-----------|--------------|
| `cli.test.ts` | CLI argument parsing, help output, error handling |

## 🔧 Test Configuration

### Playwright Configuration (`playwright.config.ts`)

Key settings:
- Projects: chromium, firefox, webkit
- Timeouts: 120 seconds for integration tests
- Parallel execution: Controlled per test file

### Environment Variables

```bash
# bWAPP connection
BWAPP_URL=http://localhost:8080
BWAPP_USER=bee
BWAPP_PASSWORD=bug
BWAPP_SECURITY_LEVEL=0
```

## 📊 Writing New Tests

### Integration Test Template

```typescript
import { test, expect } from '@playwright/test';
import { ElementScanner } from '../../src/scanners/active/ElementScanner';
import { SqlInjectionDetector } from '../../src/detectors/active/SqlInjectionDetector';
import { AttackSurfaceType, InjectionContext } from '../../src/scanners/active/DomExplorer';

test.use({ storageState: 'storage-states/bwapp-auth.json' });

test('detects SQL injection on vulnerable input', async ({ page, context }) => {
  test.setTimeout(120000);
  
  const scanner = new ElementScanner({
    baseUrl: 'http://localhost:8080',
    pageUrl: '/sqli_1.php',
    elements: [{
      locator: 'input[name="title"]',
      name: 'Movie Search',
      type: AttackSurfaceType.FORM_INPUT,
      context: InjectionContext.SQL,
      testCategories: ['sqli'],
    }],
  });

  scanner.registerDetectors([new SqlInjectionDetector()]);
  
  // Run scan and assert
  await scanner.initialize({ page, browserContext: context, ... });
  const result = await scanner.execute();
  
  expect(result.vulnerabilities.filter(v => v.cwe === 'CWE-89')).toHaveLength(1);
});
```

### Unit Test Template (Jest)

```typescript
import { MyModule } from '../../src/module';

describe('MyModule', () => {
  let module: MyModule;

  beforeEach(() => {
    module = new MyModule();
  });

  it('should do something', () => {
    const result = module.doSomething();
    expect(result).toBe(expected);
  });
});
```

## 🐛 Debugging Tests

### Show Browser During Tests

```bash
npx playwright test --headed
```

### Run Single Test with Debug

```bash
npx playwright test -g "detects SQL injection" --debug
```

### View Test Report

```bash
npx playwright show-report
```

## ✅ Test Coverage

Current test coverage goals:
- Integration tests: Validate detection of OWASP Top 10 vulnerabilities
- Unit tests: 80%+ coverage on core modules
- E2E tests: CLI commands and error handling
