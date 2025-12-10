# Kinetic Migration Guide

> Guide for upgrading between versions of Kinetic Security Scanner

## Overview

This guide helps you migrate your code when upgrading to new versions of Kinetic.

---

## Migrating to v0.1.0-beta.1 (Current Version)

### From Scratch (New Installation)

If you're installing the framework for the first time:

**Option 1: Framework Integration (for testing)**
```bash
npm install @tzigger/kinetic --save-dev
```

**Option 2: CLI Tool (for standalone scanning)**
```bash
# Clone the repository
git clone https://github.com/tzigger/kinetic.git
cd kinetic

# Install dependencies
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

See [Developer Guide](./DEVELOPER-GUIDE.md) for complete setup instructions.

### Package Name Change

**⚠️ Breaking Change**: Package renamed from `kinetic` to `@tzigger/kinetic`

**Before**:
```bash
npm install kinetic
```

**After**:
```bash
npm install @tzigger/kinetic
```

**Update imports**:
```typescript
// ❌ Old (will not work)
import { ScanEngine } from 'kinetic';

// ✅ New (scoped package)
import { ScanEngine } from '@tzigger/kinetic';
```

### API Changes

#### 1. Testing Helpers Export Path

**Before** (v0.0.x):
```typescript
// Testing helpers were not available
```

**After** (v0.1.0-beta.1):
```typescript
import { 
  runActiveSecurityScan, 
  runPassiveSecurityScan,
  assertNoVulnerabilities,
  VulnerabilitySeverity 
} from '@tzigger/kinetic';
```

**Note**: The framework now provides separate helpers for active and passive scanning:
- `runActiveSecurityScan()` - Tests for injection vulnerabilities (SQLi, XSS, etc.)
- `runPassiveSecurityScan()` - Analyzes traffic patterns (headers, cookies, data exposure)

#### 2. Scanner Registration

**No changes** - Scanner registration remains the same:
```typescript
const scanner = new ActiveScanner();
scanner.registerDetectors([new SqlInjectionDetector()]);
engine.registerScanner(scanner);
```

#### 3. Configuration Structure

**No breaking changes** - Configuration structure is backward compatible.

Optional new fields added:
```typescript
const config = {
  target: {
    // New optional fields
    scope: {
      includePatterns: ['https://myapp.com/**'],
      excludePatterns: ['**/logout']
    },
    customHeaders: {
      'X-Custom-Header': 'value'
    }
  }
};
```

---

## Future Migrations

### Planned for v0.2.0

**Expected changes** (subject to change):
- ✅ Passive scanner (COMPLETED in v0.1.0-beta.1)
- SPA (Single Page Application) detection improvements
- Additional active detectors (CSRF, Path Traversal, Command Injection)
- Authentication support (OAuth, session-based)
- Multi-browser support (Firefox, WebKit)
- Performance improvements

**Migration difficulty**: Low to Medium

### Planned for v1.0.0 (Stable)

**Expected changes** (subject to change):
- API stabilization
- Potential breaking changes for consistency
- Enhanced plugin system
- Additional authentication methods

**Migration difficulty**: Medium

We will provide detailed migration guides for each major version.

---

## Best Practices for Future Upgrades

### 1. Pin Your Version

Use exact versions in `package.json` to avoid unexpected breaking changes:

```json
{
  "devDependencies": {
    "@tzigger/kinetic": "0.1.0-beta.1"
  }
}
```

### 2. Review CHANGELOG

Always review [CHANGELOG.md](../CHANGELOG.md) before upgrading:

```bash
# View changelog
cat node_modules/@tzigger/kinetic/CHANGELOG.md
```

### 3. Test Before Deploying

Test the upgrade in a development environment first:

```bash
# Install new version in dev
npm install @tzigger/kinetic@latest --save-dev

# Run your security tests
npm test

# If everything works, commit package.json
```

### 4. Gradual Migration

For major versions, migrate gradually:

1. Update package version
2. Fix type errors (if any)
3. Update imports
4. Test each module
5. Update configuration (if needed)
6. Deploy

---

## Deprecation Policy

We follow semantic versioning (SemVer):

- **Patch versions (0.1.x)**: Bug fixes, no breaking changes
- **Minor versions (0.x.0)**: New features, backward compatible
- **Major versions (x.0.0)**: Breaking changes allowed

### Deprecation Timeline

1. **Announcement**: Deprecated features announced in CHANGELOG
2. **Warning Period**: Minimum 2 minor versions before removal
3. **Removal**: Only in major version releases

---

## Getting Help

If you encounter issues during migration:

1. Check [CHANGELOG.md](../CHANGELOG.md) for breaking changes
2. Review [Developer Guide](./DEVELOPER-GUIDE.md) for updated examples
3. Search [GitHub Issues](https://github.com/tzigger/kinetic/issues)
4. Open a new issue if needed

---

## Version Compatibility

### Node.js Compatibility

| Framework Version | Node.js Version |
|------------------|-----------------|
| 0.1.0-beta.1     | >= 18.0.0      |
| Future versions  | >= 18.0.0      |

### Playwright Compatibility

| Framework Version | Playwright Version |
|------------------|-------------------|
| 0.1.0-beta.1     | >= 1.40.0        |
| Future versions  | >= 1.40.0        |

---

## Common Migration Issues

### Issue 1: Module Not Found

**Error**:
```
Cannot find module 'kinetic'
```

**Solution**:
Update package name to scoped version:
```bash
npm uninstall kinetic
npm install @tzigger/kinetic --save-dev
```

### Issue 2: Import Errors

**Error**:
```
Module '"@tzigger/kinetic"' has no exported member 'runSecurityScan'
```

**Solution**:
Use correct import path and function names for testing helpers:
```typescript
import { 
  runActiveSecurityScan,
  runPassiveSecurityScan,
  assertNoVulnerabilities 
} from '@tzigger/kinetic';
```

**Note**: `runSecurityScan()` was split into `runActiveSecurityScan()` and `runPassiveSecurityScan()` for better control.

### Issue 3: Type Errors

**Error**:
```
Type 'X' is not assignable to type 'Y'
```

**Solution**:
1. Check CHANGELOG for type changes
2. Update TypeScript definitions
3. Ensure you're using the latest `@types` if applicable

---

## Rollback Instructions

If you need to rollback to a previous version:

```bash
# Rollback to specific version
npm install @tzigger/kinetic@0.1.0 --save-dev

# Or use package-lock.json
git checkout HEAD -- package-lock.json
npm ci
```

---

## Staying Updated

### Subscribe to Releases

1. Go to https://github.com/tzigger/kinetic
2. Click "Watch" → "Custom" → "Releases"
3. You'll be notified of new versions

### Check for Updates

```bash
# Check for updates
npm outdated @tzigger/kinetic

# Update to latest version
npm update @tzigger/kinetic
```

---

## Contributing Migration Guides

If you encounter migration issues not covered here:

1. Document your solution
2. Submit a PR to update this guide
3. Help other users avoid the same issues

See [CONTRIBUTING.md](../CONTRIBUTING.md) for guidelines.

---

## CLI Tool Usage

### Using kinetic Command

After installation via `npm link`, you can use the `kinetic` command:

```bash
# Passive scan (fast, 3-5 seconds)
kinetic https://example.com --scan-type passive

# Active scan (comprehensive, 30-120 seconds)
kinetic https://example.com --scan-type active

# Both passive and active
kinetic https://example.com --scan-type both

# Custom output and formats
kinetic https://example.com --output ./reports --formats html,json,sarif

# Use a configuration file
kinetic --config ./config/default.config.json

# Use a profile
kinetic https://example.com --config ./config/profiles/aggressive.json
```

### CLI Flags Reference

| Flag | Description | Default |
|------|-------------|----------|
| `--scan-type <type>` | Scan type: `active`, `passive`, or `both` | `active` |
| `--passive` | Enable passive scanning | `false` |
| `--active` | Enable active scanning | `true` |
| `-o, --output <dir>` | Output directory for reports | `./reports` |
| `-f, --formats <list>` | Report formats (console,json,html,sarif) | `console,json,html` |
| `-c, --config <file>` | Load configuration from file | - |
| `--headless` | Run headless browser | `true` |
| `--parallel <n>` | Number of parallel scanners | `2` |

### Unlinking the CLI

If you need to uninstall the global `kinetic` command:

```bash
npm unlink -g @tzigger/kinetic
# or
sudo npm unlink -g @tzigger/kinetic
```

---

**Last Updated**: November 27, 2025 (v0.1.0-beta.1)
