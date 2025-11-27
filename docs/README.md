# Documentation Index

Welcome to the Playwright Security Framework documentation!

## 📖 Getting Started

New to the framework? Start here:

1. **[Testing Guide](./TESTING-GUIDE.md)** ⭐ **Start Here!**
   - How to write security tests easily
   - Helper function reference (`runActiveSecurityScan`, etc.)
   - Configuration options and examples
   - Attack surface types explained
   - Best practices and patterns
   - **~35 KB** | **Essential for Test Writers**

2. **[Developer Guide](./DEVELOPER-GUIDE.md)**
   - Complete guide for using the framework in your projects
   - Installation, configuration, and usage
   - API reference and examples
   - Best practices and troubleshooting
   - **~26 KB** | **Comprehensive**

3. **[API Quick Reference](./API-QUICK-REFERENCE.md)**
   - Quick lookup for all APIs and methods
   - Common patterns and imports
   - Configuration examples
   - **~11 KB** | **Quick Reference**

4. **[Examples](./EXAMPLES.md)**
   - Real-world usage examples
   - Playwright test integration
   - CI/CD integration (GitHub Actions, GitLab, Jenkins)
   - Custom detectors and reporters
   - **~23 KB** | **Practical Examples**

## ⚠️ Known Limitations

Important information about current limitations:

- **[SPA Testing Limitations](./SPA-TESTING-LIMITATIONS.md)**
  - Current status of SPA (Single Page Application) support
  - Known issues with Angular/React/Vue testing
  - Recommended workarounds and alternatives
  - Timeline for improvements
  - **~8 KB** | **Important for SPA Testing**

## 🔄 Upgrading

Upgrading to a new version?

- **[Migration Guide](./MIGRATION-GUIDE.md)**
  - Version-specific migration instructions
  - Breaking changes and how to fix them
  - Best practices for upgrading
  - **~6 KB** | **Version Migrations**

## 🏗️ Contributing

Want to contribute to the framework?

- **[Architecture](./architecture.md)**
  - System design and patterns
  - Component overview
  - Extension points
  - **~5.5 KB** | **Architecture Details**

- **[Plugin Development](./plugin-development.md)**
  - Creating custom plugins
  - Plugin API reference
  - Development guidelines
  - **~7.5 KB** | **Plugin Development**

## 📚 Documentation Overview

| Document | Purpose | Target Audience | Size |
|----------|---------|-----------------|------|
| [Testing Guide](./TESTING-GUIDE.md) | Write security tests | Test writers | 35 KB |
| [Developer Guide](./DEVELOPER-GUIDE.md) | Complete usage guide | Framework users | 26 KB |
| [API Quick Reference](./API-QUICK-REFERENCE.md) | Quick API lookup | All developers | 11 KB |
| [Examples](./EXAMPLES.md) | Real-world examples | Framework users | 23 KB |
| [SPA Testing Limitations](./SPA-TESTING-LIMITATIONS.md) | SPA testing issues | SPA testers | 8 KB |
| [Migration Guide](./MIGRATION-GUIDE.md) | Version upgrades | Existing users | 6 KB |
| [Architecture](./architecture.md) | System design | Contributors | 5.5 KB |
| [Plugin Development](./plugin-development.md) | Custom plugins | Advanced users | 7.5 KB |

## 🎯 Quick Links

### For Test Writers

Want to write security tests?

1. 📖 **Testing Guide**: See [Testing Guide](./TESTING-GUIDE.md) - **Start here!**
2. 🚀 **Quick Start**: See [Testing Guide - Quick Start](./TESTING-GUIDE.md#quick-start)
3. 🔧 **Helper Functions**: See [Testing Guide - Helper Functions](./TESTING-GUIDE.md#helper-functions)
4. ⚙️ **Configuration**: See [Testing Guide - Configuration Options](./TESTING-GUIDE.md#configuration-options)
5. 🎯 **Patterns**: See [Testing Guide - Advanced Patterns](./TESTING-GUIDE.md#advanced-patterns)

### For Framework Users

Want to use this framework programmatically?

1. 📦 **Installation**: See [Developer Guide - Installation](./DEVELOPER-GUIDE.md#installation)
2. 🚀 **Quick Start**: See [Developer Guide - Quick Start](./DEVELOPER-GUIDE.md#quick-start)
3. 🧪 **Playwright Tests**: See [Examples - Playwright Test Integration](./EXAMPLES.md#playwright-test-integration)
4. ⚙️ **Configuration**: See [API Quick Reference - Configuration](./API-QUICK-REFERENCE.md#configuration)
5. 🔌 **Custom Detectors**: See [Developer Guide - Custom Detectors](./DEVELOPER-GUIDE.md#custom-detectors)

### For CI/CD Integration

Setting up automated security scanning?

1. 🔄 **GitHub Actions**: See [Examples - GitHub Actions Workflow](./EXAMPLES.md#example-4-github-actions-workflow)
2. 🦊 **GitLab CI**: See [Examples - GitLab CI Pipeline](./EXAMPLES.md#example-5-gitlab-ci-pipeline)
3. 🏗️ **Jenkins**: See [Examples - Jenkins Pipeline](./EXAMPLES.md#example-6-jenkins-pipeline)

### For Contributors

Want to contribute to the framework?

1. 🏛️ **Architecture Overview**: See [Architecture](./architecture.md)
2. 🔌 **Plugin System**: See [Plugin Development](./plugin-development.md)
3. 🧩 **Creating Detectors**: See [Developer Guide - Custom Detectors](./DEVELOPER-GUIDE.md#custom-detectors)
4. 📝 **Creating Reporters**: See [Developer Guide - Custom Reporters](./DEVELOPER-GUIDE.md#custom-reporters)

## 🔍 Common Use Cases

### Use Case 1: Add Security Tests to Existing Project

```typescript
// tests/security.spec.ts
import { test, expect } from '@playwright/test';
import { runActiveSecurityScan } from '@tzigger/playwright-security';

test('app security', async ({ page }) => {
  await page.goto('https://myapp.com');
  const vulnerabilities = await runActiveSecurityScan(page);
  expect(vulnerabilities).toHaveLength(0);
});
```

**See**: [Testing Guide - Quick Start](./TESTING-GUIDE.md#quick-start)

### Use Case 2: Programmatic Security Scanning

```typescript
import { ScanEngine, ActiveScanner, SqlInjectionDetector } from '@tzigger/playwright-security';

const engine = new ScanEngine();
const scanner = new ActiveScanner();
scanner.registerDetector(new SqlInjectionDetector());
engine.registerScanner(scanner);

await engine.loadConfiguration(config);
const results = await engine.scan();
```

**See**: [API Quick Reference - Core Classes](./API-QUICK-REFERENCE.md#core-classes)

### Use Case 3: Custom Vulnerability Detection

```typescript
import { BaseDetector, VulnerabilityCategory } from '@tzigger/playwright-security';

class MyDetector extends BaseDetector {
  readonly id = 'my-detector';
  readonly category = VulnerabilityCategory.CUSTOM;
  // ... implementation
}
```

**See**: [Examples - Custom Detectors](./EXAMPLES.md#custom-detectors)

## 📝 Additional Resources

- **Main Repository**: https://github.com/Tzigger/playwright_security
- **Issues**: https://github.com/Tzigger/playwright_security/issues
- **Changelog**: [CHANGELOG.md](../CHANGELOG.md)
- **License**: [LICENSE](../LICENSE)

## 🆘 Getting Help

1. **Check the docs**: Most questions are answered in the [Developer Guide](./DEVELOPER-GUIDE.md)
2. **Search issues**: Someone might have had the same question
3. **Ask questions**: Open a [discussion](https://github.com/Tzigger/playwright_security/discussions)
4. **Report bugs**: Open an [issue](https://github.com/Tzigger/playwright_security/issues)

## 📊 Documentation Stats

- **Total Documents**: 9
- **Total Size**: ~128 KB
- **Last Updated**: November 27, 2025
- **Framework Version**: 0.1.0-beta.1

---

**Happy Secure Testing! 🔒**
