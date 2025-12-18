# Detector Configuration Guide

## Overview

The Kinetic DAST framework uses a **Detector Registry** system that allows you to control which security detectors run via configuration files. This gives you fine-grained control over scan behavior without modifying code.

## Configuration

### ScanConfiguration.detectors

All detector configuration is done through the `detectors` section of your scan configuration:

```json
{
  "detectors": {
    "enabled": ["*"],           // Array of detector IDs or patterns to enable
    "disabled": [],             // Array of detector IDs to disable (overrides enabled)
    "sensitivity": "normal",    // Detector sensitivity level
    "tuning": {                 // Detector-specific tuning parameters
      "sqli": { ... },
      "xss": { ... }
    }
  }
}
```

## Built-in Detectors

### Active Detectors (require interaction)

| ID | Name | Category | Description |
|----|------|----------|-------------|
| `sql-injection` | SQL Injection Detector | sql | Detects SQL injection vulnerabilities (error-based, boolean-based, time-based) |
| `xss` | XSS Detector | xss | Detects cross-site scripting (reflected, stored, DOM-based, JSON-based) |
| `error-based` | Error-Based Detector | errors | Detects information disclosure through error messages |

### Passive Detectors (observe traffic only)

| ID | Name | Category | Description |
|----|------|----------|-------------|
| `sensitive-data` | Sensitive Data Detector | data | Detects PII exposure (emails, SSNs, credit cards) |
| `header-security` | Header Security Detector | headers | Detects missing/misconfigured security headers |
| `cookie-security` | Cookie Security Detector | cookies | Detects insecure cookie configurations |
| `insecure-transmission` | Insecure Transmission Detector | transmission | Detects unencrypted HTTP traffic |

## Pattern Matching

The `enabled` array supports powerful pattern matching:

### Wildcard: `*`
Matches all detectors:
```json
{
  "detectors": {
    "enabled": ["*"]
  }
}
```

### Exact ID Matching
Specify detector IDs exactly:
```json
{
  "detectors": {
    "enabled": ["sql-injection", "xss"]
  }
}
```

### Wildcard Patterns
Use `*` for prefix/suffix matching:
```json
{
  "detectors": {
    "enabled": ["sql-*"]  // Matches: sql-injection
  }
}
```

### Category Matching
Match all detectors in a category:
```json
{
  "detectors": {
    "enabled": ["*-security"]  // Matches: header-security, cookie-security
  }
}
```

## Disabled List (Override)

The `disabled` array **always overrides** the `enabled` array:

```json
{
  "detectors": {
    "enabled": ["*"],           // Enable all detectors
    "disabled": ["xss", "error-based"]  // Except these two
  }
}
```

**Result**: Only `sql-injection`, `sensitive-data`, `header-security`, `cookie-security`, `insecure-transmission` will run.

## Common Configurations

### 1. SQL Injection Only
```json
{
  "detectors": {
    "enabled": ["sql-injection"],
    "disabled": []
  }
}
```

### 2. All Passive Scanners
```json
{
  "detectors": {
    "enabled": [
      "sensitive-data",
      "header-security",
      "cookie-security",
      "insecure-transmission"
    ],
    "disabled": []
  }
}
```

### 3. Security Headers + Cookie Checks
```json
{
  "detectors": {
    "enabled": ["*-security"],  // Matches header-security and cookie-security
    "disabled": []
  }
}
```

### 4. Everything Except XSS
```json
{
  "detectors": {
    "enabled": ["*"],
    "disabled": ["xss"]
  }
}
```

### 5. Active Detectors Only
```json
{
  "detectors": {
    "enabled": ["sql-injection", "xss", "error-based"],
    "disabled": []
  },
  "scanners": {
    "passive": { "enabled": false },
    "active": { "enabled": true }
  }
}
```

## Testing Helpers Integration

The `runActiveSecurityScan()` and `runPassiveSecurityScan()` helpers automatically configure detector patterns:

### Active Scan
```typescript
import { runActiveSecurityScan } from '@tzigger/kinetic/testing';

// Test SQL injection only
const results = await runActiveSecurityScan('http://localhost:3000', {
  detectors: 'sql',  // Maps to enabled: ['sql-injection']
  maxPages: 1
});
```

**Detector Mapping (Active)**:
- `'sql'` → `['sql-injection']`
- `'xss'` → `['xss']`
- `'errors'` → `['error-based']`
- `'all'` → `['*']`

### Passive Scan
```typescript
import { runPassiveSecurityScan } from '@tzigger/kinetic/testing';

// Test headers only
const results = await runPassiveSecurityScan('http://localhost:3000', {
  detectors: 'headers',  // Maps to enabled: ['header-security']
});
```

**Detector Mapping (Passive)**:
- `'headers'` → `['header-security']`
- `'cookies'` → `['cookie-security']`
- `'transmission'` → `['insecure-transmission']`
- `'data'` → `['sensitive-data']`
- `'all'` → `['*']`

## CLI Usage

When using the CLI, the config file's `detectors.enabled` and `detectors.disabled` arrays control which detectors execute:

```bash
# Run with custom config
kinetic --config ./my-config.json

# Example config: only SQL injection and XSS
cat my-config.json
{
  "detectors": {
    "enabled": ["sql-injection", "xss"],
    "disabled": []
  }
}
```

## Custom Detector Registration

To add custom detectors to the registry:

```typescript
import { DetectorRegistry } from '@tzigger/kinetic';
import { MyCustomDetector } from './detectors/MyCustomDetector';

const registry = DetectorRegistry.getInstance();

registry.registerActiveDetector(new MyCustomDetector(), {
  id: 'my-custom-detector',
  name: 'My Custom Detector',
  type: 'active',
  category: 'custom',
  description: 'My custom security check',
  enabledByDefault: true,
});
```

Then reference it in config:
```json
{
  "detectors": {
    "enabled": ["my-custom-detector"]
  }
}
```

## Implementation Details

### Registry Pattern
- Singleton `DetectorRegistry` manages all detectors
- `registerBuiltInDetectors()` initializes 7 built-in detectors
- CLI and helpers call `getActiveDetectors(config.detectors)` / `getPassiveDetectors(config.detectors)`

### Filtering Logic
1. Start with all registered detectors
2. Filter by `enabled` patterns (wildcard matching)
3. Remove any detectors in `disabled` list
4. Return filtered detector instances

### Verification
Run the registry test to verify configuration:
```bash
node test-registry.js
```

Example output:
```
Test 2: enabled: ["sql-injection"]
  Active detectors: SQL Injection Detector
  Count: 1
```

## Best Practices

1. **Use wildcards for broad scans**: `enabled: ["*"]` for comprehensive coverage
2. **Be specific for focused testing**: `enabled: ["sql-injection"]` for targeted tests
3. **Use disabled list sparingly**: Only exclude problematic detectors
4. **Test config changes**: Use `test-registry.js` to verify detector filtering
5. **Document custom detectors**: Add clear ID/name/description metadata

## Troubleshooting

### No detectors running?
- Check `enabled` array is not empty
- Verify detector IDs match exactly (case-sensitive)
- Ensure `disabled` list is not blocking all detectors

### Wrong detectors running?
- Review pattern matching (wildcards may match unexpectedly)
- Check `disabled` list overrides
- Use exact IDs instead of patterns for precise control

### Custom detector not found?
- Ensure `registerBuiltInDetectors()` or custom registration is called **before** scanner creation
- Verify detector ID in config matches registered ID exactly
