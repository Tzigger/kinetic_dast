# Practical Examples

> Real-world examples for using Playwright Security Framework

## Table of Contents

- [Quick Start with Helper Functions](#quick-start-with-helper-functions)
- [Playwright Test Integration](#playwright-test-integration)
- [CI/CD Integration](#cicd-integration)
- [Custom Detectors](#custom-detectors)
- [Authentication Scenarios](#authentication-scenarios)
- [Advanced Configurations](#advanced-configurations)

---

## Quick Start with Helper Functions

### Example 1: Passive Security Headers Check

```typescript
import { test, expect } from '@playwright/test';
import { runPassiveSecurityScan, VulnerabilitySeverity } from '../src/testing/helpers';

test('should have proper security headers', async () => {
  const vulnerabilities = await runPassiveSecurityScan('https://myapp.com', {
    detectors: 'headers',
    headless: true
  });
  
  // Check for missing HSTS header
  const hstsIssues = vulnerabilities.filter(v => 
    v.title.includes('Strict-Transport-Security')
  );
  expect(hstsIssues).toHaveLength(0);
});
```

### Example 2: SQL Injection Test

```typescript
import { test } from '@playwright/test';
import { runActiveSecurityScan, assertNoVulnerabilities } from '../src/testing/helpers';

test('login form should not have SQL injection', async () => {
  const vulnerabilities = await runActiveSecurityScan('https://myapp.com/login', {
    detectors: 'sql',
    aggressiveness: 'medium',
    maxPages: 1
  });
  
  // Fail test if any vulnerabilities found
  assertNoVulnerabilities(vulnerabilities);
});
```

### Example 3: Combined Active + Passive Scan

```typescript
import { test, expect } from '@playwright/test';
import { 
  runActiveSecurityScan, 
  runPassiveSecurityScan,
  VulnerabilitySeverity 
} from '../src/testing/helpers';

test('comprehensive security check', async () => {
  // Fast passive scan first (3-5s)
  const passiveVulns = await runPassiveSecurityScan('https://myapp.com');
  console.log(`Passive: ${passiveVulns.length} issues`);
  
  // Then active scan for injections (30-120s)
  const activeVulns = await runActiveSecurityScan('https://myapp.com', {
    aggressiveness: 'low',
    maxPages: 3
  });
  console.log(`Active: ${activeVulns.length} issues`);
  
  // Combine and check severity
  const allVulns = [...passiveVulns, ...activeVulns];
  const critical = allVulns.filter(v => v.severity === VulnerabilitySeverity.CRITICAL);
  expect(critical).toHaveLength(0);
});
```

### Example 4: SPA Security Testing

```typescript
import { test, expect } from '@playwright/test';
import { runPassiveSecurityScan } from '../src/testing/helpers';

test('SPA should not leak sensitive data', async () => {
  const vulnerabilities = await runPassiveSecurityScan(
    'https://myapp.com/#/dashboard',
    {
      detectors: 'data', // Focus on data exposure
      headless: true
    }
  );
  
  // Check for exposed phone numbers, emails, etc.
  const dataLeaks = vulnerabilities.filter(v => 
    v.category === 'sensitive-data-exposure'
  );
  expect(dataLeaks).toHaveLength(0);
});
```

---

## Playwright Test Integration

### Example 5: Basic Security Test Suite

```typescript
// tests/security.spec.ts
import { test, expect } from '@playwright/test';
import { 
  runActiveSecurityScan,
  runPassiveSecurityScan,
  assertNoVulnerabilities, 
  VulnerabilitySeverity 
} from '../src/testing/helpers';

test.describe('Application Security Tests', () => {
  
  test('home page should have no critical vulnerabilities', async () => {
    const vulnerabilities = await runPassiveSecurityScan('https://myapp.com', {
      detectors: 'all',
      headless: true
    });
    
    // No critical or high severity allowed
    assertNoVulnerabilities(vulnerabilities, VulnerabilitySeverity.MEDIUM);
  });
  
  test('login form should be protected against SQL injection', async () => {
    const vulnerabilities = await runActiveSecurityScan('https://myapp.com/login', {
      detectors: 'sql',
      maxPages: 1
    });
    
    const sqlVulns = vulnerabilities.filter(v => v.category === 'injection');
    expect(sqlVulns).toHaveLength(0);
    expect(sqlVulns, 'No SQL injection vulnerabilities allowed').toHaveLength(0);
  });
  
  test('search functionality should be protected against XSS', async ({ page }) => {
    await page.goto('https://myapp.com/search');
    
    const vulnerabilities = await runSecurityScan(page.url(), {
      detectors: 'xss',
      maxPages: 1
    });
    
    const xssVulns = vulnerabilities.filter(v => v.category === 'xss');
    expect(xssVulns, 'No XSS vulnerabilities allowed').toHaveLength(0);
  });
  
  test('should not expose sensitive error messages', async ({ page }) => {
    await page.goto('https://myapp.com');
    
    const vulnerabilities = await runSecurityScan(page.url(), {
      detectors: 'errors',
      maxPages: 3
    });
    
    const errorVulns = vulnerabilities.filter(v => 
      v.category === 'information-disclosure'
    );
    
    expect(errorVulns, 'No error disclosure allowed').toHaveLength(0);
  });
});
```

### Example 2: Multi-Page Security Test

```typescript
// tests/multi-page-security.spec.ts
import { test, expect } from '@playwright/test';
import { runSecurityScan, VulnerabilitySeverity } from '@tzigger/playwright-security/testing';

test.describe('Multi-Page Security Scan', () => {
  const pages = [
    { name: 'Home', url: '/' },
    { name: 'Login', url: '/login' },
    { name: 'Signup', url: '/signup' },
    { name: 'Products', url: '/products' },
    { name: 'Checkout', url: '/checkout' },
  ];
  
  for (const pageInfo of pages) {
    test(`${pageInfo.name} page security`, async ({ page }) => {
      const fullUrl = `https://myapp.com${pageInfo.url}`;
      await page.goto(fullUrl);
      
      const vulnerabilities = await runSecurityScan(page.url(), {
        detectors: 'all',
        maxPages: 1,
        headless: true
      });
      
      // Generate detailed report
      const report = {
        page: pageInfo.name,
        url: fullUrl,
        total: vulnerabilities.length,
        critical: vulnerabilities.filter(v => v.severity === VulnerabilitySeverity.CRITICAL).length,
        high: vulnerabilities.filter(v => v.severity === VulnerabilitySeverity.HIGH).length,
        medium: vulnerabilities.filter(v => v.severity === VulnerabilitySeverity.MEDIUM).length,
        low: vulnerabilities.filter(v => v.severity === VulnerabilitySeverity.LOW).length,
      };
      
      console.log(`Security Report for ${pageInfo.name}:`, report);
      
      // Fail on critical or high
      expect(report.critical, `Critical vulnerabilities on ${pageInfo.name}`).toBe(0);
      expect(report.high, `High severity vulnerabilities on ${pageInfo.name}`).toBe(0);
    });
  }
});
```

### Example 3: API Endpoint Security

```typescript
// tests/api-security.spec.ts
import { test, expect } from '@playwright/test';
import { runSecurityScan } from '@tzigger/playwright-security/testing';

test.describe('API Security Tests', () => {
  const apiBase = 'https://api.myapp.com/v1';
  
  const endpoints = [
    '/users',
    '/users/1',
    '/products',
    '/products/search',
    '/orders',
    '/orders/123'
  ];
  
  test('all API endpoints should be secure', async () => {
    const results = [];
    
    for (const endpoint of endpoints) {
      const vulns = await runSecurityScan(`${apiBase}${endpoint}`, {
        detectors: 'sql',
        maxPages: 1,
        headless: true
      });
      
      results.push({
        endpoint,
        vulnerabilities: vulns.length,
        critical: vulns.filter(v => v.severity === 'critical').length
      });
    }
    
    // Print summary
    console.table(results);
    
    // Assert no critical vulnerabilities in any endpoint
    const criticalTotal = results.reduce((sum, r) => sum + r.critical, 0);
    expect(criticalTotal, 'API endpoints should have no critical vulnerabilities').toBe(0);
  });
});
```

---

## CI/CD Integration

### Example 4: GitHub Actions Workflow

```yaml
# .github/workflows/security-scan.yml
name: Security Scan

on:
  pull_request:
    branches: [main, develop]
  push:
    branches: [main]
  schedule:
    # Run daily at 2 AM
    - cron: '0 2 * * *'

jobs:
  security-scan:
    runs-on: ubuntu-latest
    
    steps:
      - name: Checkout code
        uses: actions/checkout@v3
      
      - name: Setup Node.js
        uses: actions/setup-node@v3
        with:
          node-version: '18'
          cache: 'npm'
      
      - name: Install dependencies
        run: npm ci
      
      - name: Install Playwright browsers
        run: npx playwright install --with-deps chromium
      
      - name: Run security tests
        run: npx playwright test tests/security.spec.ts
        env:
          BASE_URL: ${{ secrets.STAGING_URL }}
          TEST_USERNAME: ${{ secrets.TEST_USERNAME }}
          TEST_PASSWORD: ${{ secrets.TEST_PASSWORD }}
      
      - name: Upload test results
        if: always()
        uses: actions/upload-artifact@v3
        with:
          name: playwright-results
          path: test-results/
          retention-days: 30
      
      - name: Upload security reports
        if: always()
        uses: actions/upload-artifact@v3
        with:
          name: security-reports
          path: security-reports/
          retention-days: 90
      
      - name: Upload SARIF to GitHub Security
        if: always()
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: security-reports/scan.sarif
          category: dast-scan
      
      - name: Comment PR with results
        if: github.event_name == 'pull_request'
        uses: actions/github-script@v6
        with:
          script: |
            const fs = require('fs');
            const report = JSON.parse(fs.readFileSync('security-reports/scan.json', 'utf8'));
            const comment = `## 🔒 Security Scan Results
            
            - **Total Vulnerabilities**: ${report.vulnerabilities.length}
            - **Critical**: ${report.vulnerabilities.filter(v => v.severity === 'critical').length}
            - **High**: ${report.vulnerabilities.filter(v => v.severity === 'high').length}
            - **Medium**: ${report.vulnerabilities.filter(v => v.severity === 'medium').length}
            - **Low**: ${report.vulnerabilities.filter(v => v.severity === 'low').length}
            
            View full report in the artifacts.`;
            
            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: comment
            });
```

### Example 5: GitLab CI Pipeline

```yaml
# .gitlab-ci.yml
stages:
  - test
  - security

security-scan:
  stage: security
  image: mcr.microsoft.com/playwright:v1.40.0-jammy
  before_script:
    - npm ci
  script:
    - npx playwright test tests/security.spec.ts
  artifacts:
    when: always
    paths:
      - security-reports/
    reports:
      junit: test-results/junit.xml
    expire_in: 30 days
  rules:
    - if: '$CI_PIPELINE_SOURCE == "merge_request_event"'
    - if: '$CI_COMMIT_BRANCH == "main"'
```

### Example 6: Jenkins Pipeline

```groovy
// Jenkinsfile
pipeline {
    agent any
    
    environment {
        BASE_URL = credentials('staging-url')
        TEST_CREDENTIALS = credentials('test-credentials')
    }
    
    stages {
        stage('Install') {
            steps {
                sh 'npm ci'
                sh 'npx playwright install --with-deps chromium'
            }
        }
        
        stage('Security Scan') {
            steps {
                sh 'npx playwright test tests/security.spec.ts'
            }
        }
    }
    
    post {
        always {
            archiveArtifacts artifacts: 'security-reports/**/*', fingerprint: true
            publishHTML([
                allowMissing: false,
                alwaysLinkToLastBuild: true,
                keepAll: true,
                reportDir: 'security-reports',
                reportFiles: 'scan.html',
                reportName: 'Security Scan Report'
            ])
        }
    }
}
```

---

## Custom Detectors

### Example 7: API Key Leakage Detector

```typescript
// detectors/ApiKeyDetector.ts
import { 
  BaseDetector, 
  Vulnerability, 
  VulnerabilityCategory, 
  VulnerabilitySeverity 
} from '@tzigger/playwright-security';

export class ApiKeyDetector extends BaseDetector {
  readonly id = 'api-key-leakage';
  readonly name = 'API Key Leakage Detector';
  readonly version = '1.0.0';
  readonly category = VulnerabilityCategory.SENSITIVE_DATA_EXPOSURE;
  readonly description = 'Detects exposed API keys and secrets in responses';
  
  async detect(data: unknown): Promise<Vulnerability[]> {
    const vulnerabilities: Vulnerability[] = [];
    
    if (!this.isResponseData(data)) {
      return vulnerabilities;
    }
    
    const { body, url } = data;
    const patterns = this.getPatterns();
    
    for (const pattern of patterns) {
      const matches = body.matchAll(pattern);
      
      for (const match of matches) {
        const keyType = this.identifyKeyType(match[0]);
        
        vulnerabilities.push(
          this.createVulnerability({
            title: `${keyType} API Key Exposed`,
            description: `An ${keyType} API key was found in the response body at ${url}. This could allow unauthorized access to your services.`,
            severity: VulnerabilitySeverity.CRITICAL,
            evidence: {
              url,
              keyType,
              pattern: pattern.source,
              matchedValue: this.maskKey(match[0]),
              location: 'response-body'
            },
            remediation: `
              1. Immediately revoke the exposed API key
              2. Never include API keys in client-side code
              3. Use environment variables for secrets
              4. Implement server-side proxies for API calls
              5. Use short-lived tokens when possible
            `,
            confidence: 0.95,
            cwe: 'CWE-798',
            owasp: 'A02:2021 – Cryptographic Failures',
            references: [
              'https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password',
              'https://cwe.mitre.org/data/definitions/798.html'
            ]
          })
        );
      }
    }
    
    return vulnerabilities;
  }
  
  getPatterns(): RegExp[] {
    return [
      // Generic API keys
      /(?:api[_-]?key|apikey|api_key)['"]?\s*[:=]\s*['"]([a-zA-Z0-9_\-]{20,})['"]/gi,
      
      // AWS Access Keys
      /AKIA[0-9A-Z]{16}/g,
      
      // Google API Keys
      /AIza[0-9A-Za-z\-_]{35}/g,
      
      // GitHub Tokens
      /ghp_[0-9a-zA-Z]{36}/g,
      /gho_[0-9a-zA-Z]{36}/g,
      
      // Stripe Keys
      /sk_live_[0-9a-zA-Z]{24,}/g,
      /pk_live_[0-9a-zA-Z]{24,}/g,
      
      // Slack Tokens
      /xox[baprs]-[0-9a-zA-Z\-]{10,}/g,
      
      // JWT Tokens
      /eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}/g,
    ];
  }
  
  getCWEReferences(): string[] {
    return ['CWE-798', 'CWE-259', 'CWE-321'];
  }
  
  getOWASPReferences(): string[] {
    return ['A02:2021'];
  }
  
  private isResponseData(data: unknown): data is { body: string; url: string } {
    return (
      typeof data === 'object' &&
      data !== null &&
      'body' in data &&
      'url' in data &&
      typeof (data as any).body === 'string' &&
      typeof (data as any).url === 'string'
    );
  }
  
  private identifyKeyType(key: string): string {
    if (key.startsWith('AKIA')) return 'AWS';
    if (key.startsWith('AIza')) return 'Google';
    if (key.startsWith('ghp_') || key.startsWith('gho_')) return 'GitHub';
    if (key.startsWith('sk_live_') || key.startsWith('pk_live_')) return 'Stripe';
    if (key.startsWith('xox')) return 'Slack';
    if (key.startsWith('eyJ')) return 'JWT';
    return 'Generic';
  }
  
  private maskKey(key: string): string {
    if (key.length <= 8) return '***';
    return key.substring(0, 4) + '...' + key.substring(key.length - 4);
  }
}
```

**Usage**:

```typescript
import { ActiveScanner } from '@tzigger/playwright-security';
import { ApiKeyDetector } from './detectors/ApiKeyDetector';

const scanner = new ActiveScanner();
scanner.registerDetectors([
  new ApiKeyDetector(),
  // ... other detectors
]);
```

### Example 8: CORS Misconfiguration Detector

```typescript
// detectors/CorsDetector.ts
import { 
  BaseDetector, 
  Vulnerability, 
  VulnerabilityCategory, 
  VulnerabilitySeverity 
} from '@tzigger/playwright-security';

export class CorsDetector extends BaseDetector {
  readonly id = 'cors-misconfiguration';
  readonly name = 'CORS Misconfiguration Detector';
  readonly version = '1.0.0';
  readonly category = VulnerabilityCategory.SECURITY_MISCONFIGURATION;
  readonly description = 'Detects insecure CORS configurations';
  
  async detect(data: unknown): Promise<Vulnerability[]> {
    const vulnerabilities: Vulnerability[] = [];
    
    if (!this.isResponseData(data)) {
      return vulnerabilities;
    }
    
    const { headers, url } = data;
    const corsHeader = headers['access-control-allow-origin'];
    const credentialsHeader = headers['access-control-allow-credentials'];
    
    // Check for wildcard with credentials
    if (corsHeader === '*' && credentialsHeader === 'true') {
      vulnerabilities.push(
        this.createVulnerability({
          title: 'Insecure CORS: Wildcard with Credentials',
          description: 'The server allows any origin (*) while also allowing credentials. This is a severe security risk.',
          severity: VulnerabilitySeverity.HIGH,
          evidence: {
            url,
            'Access-Control-Allow-Origin': corsHeader,
            'Access-Control-Allow-Credentials': credentialsHeader
          },
          remediation: 'Either specify exact origins or disable credentials. Never use both wildcard and credentials together.',
          confidence: 1.0,
          cwe: 'CWE-346',
          owasp: 'A05:2021 – Security Misconfiguration'
        })
      );
    }
    
    // Check for overly permissive wildcard
    if (corsHeader === '*') {
      vulnerabilities.push(
        this.createVulnerability({
          title: 'Permissive CORS Policy',
          description: 'The server allows requests from any origin using wildcard (*)',
          severity: VulnerabilitySeverity.MEDIUM,
          evidence: {
            url,
            'Access-Control-Allow-Origin': corsHeader
          },
          remediation: 'Specify exact allowed origins instead of using wildcard.',
          confidence: 0.8,
          cwe: 'CWE-346'
        })
      );
    }
    
    return vulnerabilities;
  }
  
  getPatterns(): RegExp[] {
    return [];
  }
  
  getCWEReferences(): string[] {
    return ['CWE-346'];
  }
  
  private isResponseData(data: unknown): data is { 
    headers: Record<string, string>; 
    url: string 
  } {
    return (
      typeof data === 'object' &&
      data !== null &&
      'headers' in data &&
      'url' in data
    );
  }
}
```

---

## Authentication Scenarios

### Example 9: Form-Based Authentication

```typescript
// tests/authenticated-security.spec.ts
import { test } from '@playwright/test';
import { ScanEngine, ActiveScanner, SqlInjectionDetector } from '@tzigger/playwright-security';
import { ScanConfiguration, AuthType } from '@tzigger/playwright-security/types';

test('authenticated pages security scan', async ({ page }) => {
  const engine = new ScanEngine();
  const scanner = new ActiveScanner();
  scanner.registerDetector(new SqlInjectionDetector());
  engine.registerScanner(scanner);
  
  const config: ScanConfiguration = {
    target: {
      url: 'https://myapp.com/dashboard',
      authentication: {
        type: AuthType.FORM,
        loginUrl: 'https://myapp.com/login',
        credentials: {
          username: process.env.TEST_USERNAME!,
          password: process.env.TEST_PASSWORD!
        },
        formSelectors: {
          usernameField: '#username',
          passwordField: '#password',
          submitButton: 'button[type="submit"]'
        },
        successIndicator: 'text=Dashboard'
      },
      crawlDepth: 2,
      maxPages: 10
    },
    scanners: {
      active: { enabled: true, aggressiveness: 'medium' },
      passive: { enabled: false }
    }
  };
  
  await engine.loadConfiguration(config);
  const results = await engine.scan();
  await engine.cleanup();
  
  console.log(`Found ${results.vulnerabilities.length} vulnerabilities in authenticated section`);
});
```

### Example 10: Token-Based Authentication

```typescript
import { ScanConfiguration, AuthType } from '@tzigger/playwright-security/types';

const config: ScanConfiguration = {
  target: {
    url: 'https://api.myapp.com/v1/users',
    authentication: {
      type: AuthType.BEARER,
      credentials: {
        token: process.env.API_TOKEN!
      }
    },
    customHeaders: {
      'Authorization': `Bearer ${process.env.API_TOKEN}`,
      'Content-Type': 'application/json'
    }
  },
  // ... rest of config
};
```

---

## Advanced Configurations

### Example 11: Multi-Environment Configuration

```typescript
// config/security-config.ts
import { ScanConfiguration, AggressivenessLevel } from '@tzigger/playwright-security/types';

export function getSecurityConfig(environment: 'dev' | 'staging' | 'prod'): ScanConfiguration {
  const baseConfig: ScanConfiguration = {
    target: {
      url: process.env[`${environment.toUpperCase()}_URL`]!,
      crawlDepth: 2,
      maxPages: 20,
      scope: {
        excludePatterns: [
          '**/logout',
          '**/delete-account',
          '**/*.pdf',
          '**/*.zip'
        ]
      }
    },
    scanners: {
      passive: { enabled: true },
      active: { 
        enabled: true,
        aggressiveness: environment === 'prod' 
          ? AggressivenessLevel.LOW 
          : AggressivenessLevel.MEDIUM
      }
    },
    reporting: {
      formats: ['json', 'html', 'sarif'],
      outputDir: `./security-reports/${environment}`
    }
  };
  
  return baseConfig;
}

// Usage
const config = getSecurityConfig(process.env.NODE_ENV as any);
```

### Example 12: Comprehensive Test with All Features

```typescript
// tests/comprehensive-security.spec.ts
import { test, expect } from '@playwright/test';
import { 
  ScanEngine, 
  ActiveScanner,
  SqlInjectionDetector,
  XssDetector,
  ErrorBasedDetector,
  JsonReporter,
  HtmlReporter,
  SarifReporter
} from '@tzigger/playwright-security';
import * as fs from 'fs/promises';

test('comprehensive security scan with all features', async () => {
  const engine = new ScanEngine();
  
  // Setup scanner with all detectors
  const scanner = new ActiveScanner();
  scanner.registerDetectors([
    new SqlInjectionDetector(),
    new XssDetector(),
    new ErrorBasedDetector()
  ]);
  engine.registerScanner(scanner);
  
  // Setup all reporters
  engine.registerReporters([
    new JsonReporter(),
    new HtmlReporter(),
    new SarifReporter()
  ]);
  
  // Event monitoring
  const foundVulnerabilities: any[] = [];
  
  engine.on('scan:start', () => {
    console.log('🔍 Starting comprehensive security scan...');
  });
  
  engine.on('vulnerability:found', (vuln) => {
    foundVulnerabilities.push(vuln);
    console.log(`⚠️  [${vuln.severity.toUpperCase()}] ${vuln.title}`);
  });
  
  engine.on('scan:complete', (results) => {
    console.log(`✅ Scan complete! Found ${results.vulnerabilities.length} vulnerabilities`);
  });
  
  // Load configuration
  const config = {
    target: {
      url: process.env.BASE_URL || 'https://myapp.com',
      crawlDepth: 3,
      maxPages: 50,
      scope: {
        includePatterns: [
          `${process.env.BASE_URL || 'https://myapp.com'}/**`
        ],
        excludePatterns: [
          '**/logout',
          '**/signout',
          '**/delete'
        ]
      }
    },
    scanners: {
      passive: { enabled: true },
      active: { 
        enabled: true, 
        aggressiveness: 'medium',
        submitForms: true,
        followRedirects: true
      }
    },
    reporting: {
      formats: ['json', 'html', 'sarif'],
      outputDir: './security-reports',
      verbosity: 'detailed'
    }
  };
  
  await engine.loadConfiguration(config);
  const results = await engine.scan();
  await engine.cleanup();
  
  // Analyze results
  const byCategory = results.vulnerabilities.reduce((acc, vuln) => {
    acc[vuln.category] = (acc[vuln.category] || 0) + 1;
    return acc;
  }, {} as Record<string, number>);
  
  const bySeverity = results.vulnerabilities.reduce((acc, vuln) => {
    acc[vuln.severity] = (acc[vuln.severity] || 0) + 1;
    return acc;
  }, {} as Record<string, number>);
  
  // Print summary
  console.log('\n📊 Summary by Category:');
  console.table(byCategory);
  
  console.log('\n📊 Summary by Severity:');
  console.table(bySeverity);
  
  // Save custom summary
  await fs.writeFile(
    './security-reports/summary.json',
    JSON.stringify({
      timestamp: new Date().toISOString(),
      total: results.vulnerabilities.length,
      byCategory,
      bySeverity,
      criticalIssues: results.vulnerabilities.filter(v => v.severity === 'critical')
    }, null, 2)
  );
  
  // Assertions
  expect(bySeverity.critical || 0, 'No critical vulnerabilities allowed').toBe(0);
  expect(bySeverity.high || 0, 'No high severity vulnerabilities allowed').toBe(0);
});
```

---

## More Examples

For additional examples, see:
- [examples/](../examples/) directory in the repository
- [Developer Guide](./DEVELOPER-GUIDE.md) for detailed API documentation
- [API Quick Reference](./API-QUICK-REFERENCE.md) for quick lookups

---

## Contributing Examples

Have a useful example? Please contribute! See [CONTRIBUTING.md](../CONTRIBUTING.md) for guidelines.
