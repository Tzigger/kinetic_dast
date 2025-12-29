# Detector Configuration Guide

## Overview

Kinetic uses a **Detector Registry** system that allows you to control which security checks run via configuration files. This gives you fine-grained control over scan behavior without modifying code.

## Configuration Structure

All detector configuration is done through the `detectors` section of your scan configuration (`kinetic.config.json` or inline config objects):

```json
{
  "detectors": {
    "enabled": ["*"],           // Array of detector IDs or patterns to enable
    "disabled": [],             // Array of detector IDs to disable (overrides enabled)
    "sensitivity": "normal",    // Global sensitivity level (normal/high/low)
    "tuning": {                 // Detector-specific settings
      "sqli": {
        "booleanBased": {
          "minRowCountDiff": 1,
          "baselineSamples": 3
        }
      },
      "sensitiveData": {
        "emailAllowlist": ["example.com"]
      }
    }
  }
}
```

## Built-in Detectors Reference

### Active Detectors (Payload Injection)

These detectors actively interact with the application (clicks, inputs, API calls).

| ID | Name | Category | Description |
|----|------|----------|-------------|
| `sql-injection` | SQL Injection Detector | sql | Error-based, Boolean-based, and Time-based SQLi detection. |
| `sqlmap` | SqlMap API Detector | sql | Bridge to run external `sqlmap` on discovered API endpoints. |
| `xss` | XSS Detector | xss | Reflected, Stored, DOM-based, JSON-based, Angular Template injection. |
| `command-injection` | Command Injection | cmdi | OS Command Injection, SSTI (Template Injection), and XXE. |
| `path-traversal` | Path Traversal | traversal | Local File Inclusion (LFI) and Path Traversal patterns. |
| `ssrf` | SSRF Detector | ssrf | Server-Side Request Forgery via URL manipulation. |
| `error-based` | Error-Based Detector | errors | Triggers and identifies stack traces and database errors. |

### Passive Detectors (Traffic Analysis)

These detectors analyze HTTP/S traffic without modifying requests.

| ID | Name | Category | Description |
|----|------|----------|-------------|
| `sensitive-data` | Sensitive Data | data | Detects PII (SSN, Emails, Phones) and Secrets (Keys, Tokens). |
| `header-security` | Security Headers | headers | Checks for HSTS, CSP, X-Frame-Options, etc. |
| `cookie-security` | Cookie Security | cookies | Validates `Secure`, `HttpOnly`, and `SameSite` attributes. |
| `insecure-transmission`| Insecure Transmission | transmission | Detects HTTP usage and Mixed Content issues. |

## Pattern Matching

The `enabled` array supports wildcard matching:

*   **`"*"`**: Enable ALL registered detectors.
*   **`"sql-*"`**: Matches `sql-injection` (but not `sqlmap`).
*   **`"*-security"`**: Matches `header-security` and `cookie-security`.
*   **Exact ID**: `["xss", "ssrf"]` matches those specific detectors.

### Disabled Overrides
The `disabled` array takes precedence. Useful for enabling "everything except X":

```json
{
  "detectors": {
    "enabled": ["*"],
    "disabled": ["sqlmap", "ssrf"] // Skip slow/intrusive detectors
  }
}
```

## Advanced Tuning

You can fine-tune specific detectors to reduce false positives or increase depth.

### SQL Injection Tuning
```json
"tuning": {
  "sqli": {
    "booleanBased": {
      "minRowCountDiff": 2,    // Require >2 char difference in response length
      "baselineSamples": 5     // Take 5 samples to establish baseline stability
    },
    "techniqueTimeouts": {
      "timeBased": 20000       // Increase timeout for slow networks
    }
  }
}
```

### Sensitive Data Tuning
```json
"tuning": {
  "sensitiveData": {
    "emailAllowlist": ["@mycompany.com", "support@example.com"], // Ignore these emails
    "skipPaths": ["/assets/", ".js.map"] // Don't scan these file types
  }
}
```

## Helper Function Mappings

When using `runActiveSecurityScan` or `runPassiveSecurityScan` in tests, simple string aliases map to detector patterns:

### Active Mapping
| Helper Option | Maps to Pattern |
|---------------|-----------------|
| `detectors: 'all'` | `['*']` |
| `detectors: 'sql'` | `['sql-injection']` |
| `detectors: 'xss'` | `['xss']` |
| `detectors: 'errors'`| `['error-based']` |

### Passive Mapping
| Helper Option | Maps to Pattern |
|---------------|-----------------|
| `detectors: 'headers'` | `['header-security']` |
| `detectors: 'cookies'` | `['cookie-security']` |
| `detectors: 'data'` | `['sensitive-data']` |
| `detectors: 'transmission'` | `['insecure-transmission']` |

## Custom Detector Registration

To add your own detector to the engine:

1.  Implement `IActiveDetector` or `IPassiveDetector`.
2.  Register it with the `DetectorRegistry` singleton **before** creating the scanner.

```typescript
import { DetectorRegistry, IActiveDetector } from '@tzigger/kinetic';

class MyCustomDetector implements IActiveDetector {
  // Implementation...
}

// Register
DetectorRegistry.getInstance().registerActiveDetector(new MyCustomDetector(), {
  id: 'my-custom-check',
  name: 'My Custom Check',
  category: 'custom',
  description: 'Checks for specific business logic flaws',
  enabledByDefault: true,
  type: 'active'
});

// Now you can enable it in config:
// { "detectors": { "enabled": ["my-custom-check"] } }
```

## Troubleshooting

### Why isn't my detector running?
1.  **Check `enabled`**: Is the ID or a matching wildcard present?
2.  **Check `disabled`**: Is it accidentally listed here?
3.  **Exact Match**: IDs are case-sensitive. Use `sql-injection`, not `SqlInjection`.
4.  **Registration**: If it's a custom detector, ensure it was registered before `engine.scan()` was called.

### Why is the scan taking too long?
1.  **Disable Time-Based Checks**: `disabled: ["sql-injection", "command-injection"]` (these rely on sleeps).
2.  **Disable External Tools**: `disabled: ["sqlmap"]`.
3.  **Tune SQLi**: Reduce `baselineSamples` in `tuning.sqli`.
