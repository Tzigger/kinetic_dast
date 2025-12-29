# Kinetic Migration Guide

> Guide for upgrading between versions of Kinetic Security Scanner.

## Table of Contents
- [Migrating to v0.2.0](#migrating-to-v020)
- [Migrating to v0.1.0-beta.1](#migrating-to-v010-beta1)
- [Deprecation Policy](#deprecation-policy)

---

## Migrating to v0.2.0

v0.2.0 introduces the **Verification Engine** and **Element Scanner**. While the API remains largely compatible, there are behavioral changes you should be aware of.

### ⚠️ Behavioral Changes

#### 1. Slower but More Accurate Scans
The new **Verification Engine** is enabled by default. When a vulnerability is detected, Kinetic now performs additional checks (time-based statistical analysis, response structure diffing) to confirm it.
*   **Impact**: Scans may take 10-30% longer depending on the number of potential findings.
*   **Benefit**: Significant reduction in False Positives (especially for SQL Injection).
*   **Action**: If speed is critical and accuracy secondary, you can tune this in config:
    ```json
    "detectors": {
      "tuning": {
        "sqli": { "techniqueTimeouts": { "booleanBased": 5000 } }
      }
    }
    ```

#### 2. Deprecation of `runSecurityScan`
The generic `runSecurityScan` helper is now **deprecated**.
*   **Action**: Switch to the specific helpers for better type safety and clarity.

```typescript
// ❌ Deprecated
import { runSecurityScan } from '@tzigger/kinetic';
await runSecurityScan(page);

// ✅ Recommended
import { runActiveSecurityScan } from '@tzigger/kinetic/testing';
await runActiveSecurityScan(page);
```

### 🚀 New Features

#### Element Scanner
You can now scan specific elements without crawling.
```typescript
import { ElementScanner } from '@tzigger/kinetic/scanners/active/ElementScanner';
// See docs/ELEMENT-SCANNER.md for usage
```

---

## Migrating to v0.1.0-beta.1

### Package Name Change

**⚠️ Breaking Change**: Package renamed from `kinetic` to `@tzigger/kinetic`.

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
// ❌ Old
import { ScanEngine } from 'kinetic';

// ✅ New
import { ScanEngine } from '@tzigger/kinetic';
```

### API Changes

#### 1. Testing Helpers Location
Helpers have moved to the testing namespace.

**Action**: Update imports.
```typescript
import { 
  runActiveSecurityScan, 
  runPassiveSecurityScan 
} from '@tzigger/kinetic/testing';
```

#### 2. Safe Mode
Safe Mode is now **auto-enabled** for non-local targets.
*   **Impact**: Scanning staging/prod URLs will block destructive payloads automatically.
*   **Action**: If you intentionally want to run destructive tests on a remote server, you must explicitly disable it via config or CLI (`--safemode-disable`).

---

## Deprecation Policy

We follow semantic versioning (SemVer):

- **Patch versions (0.x.1)**: Bug fixes, no breaking changes.
- **Minor versions (0.1.0)**: New features, potential behavioral changes, deprecation warnings.
- **Major versions (1.0.0)**: Stable release, breaking changes allowed.

### Current Deprecations (v0.2.0)

| Feature | Replacement | Removal Target |
|---------|-------------|----------------|
| `runSecurityScan()` | `runActiveSecurityScan()` | v1.0.0 |
| `payload` (in Evidence) | `payloadUsed` | v1.0.0 |

---

## Getting Help

If you encounter issues during migration:

1. Check [CHANGELOG.md](../CHANGELOG.md) for detailed changes.
2. Review [Developer Guide](./DEVELOPER-GUIDE.md) for updated examples.
3. Open an issue on [GitHub](https://github.com/tzigger/kinetic/issues).
