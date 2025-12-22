# Safe Mode API Reference

Quick reference for using safe mode and production guardrails in Kinetic.

## PayloadFilter

Utility for detecting and filtering destructive payloads.

### Constructor

```typescript
import { PayloadFilter } from '@tzigger/kinetic';

const filter = new PayloadFilter(LogLevel.INFO);
```

### Methods

#### `isSafe(payload: string): boolean`

Check if a payload is safe to inject.

```typescript
filter.isSafe("' OR '1'='1");              // true
filter.isSafe("'; DROP TABLE users--");    // false
filter.isSafe("' UNION SELECT NULL--");    // true
```

#### `filterPayloads(payloads: string[]): string[]`

Filter out destructive payloads from a list.

```typescript
const allPayloads = [
  "' OR '1'='1",
  "'; DROP TABLE users--",
  "' UNION SELECT 1--",
];

const safePayloads = filter.filterPayloads(allPayloads);
// Result: ["' OR '1'='1", "' UNION SELECT 1--"]
// Output: "Filtered out 1 destructive payload(s) in safe mode. (2/3 payloads remain safe)"
```

#### `getSafetyLevel(payload: string): 'safe' | 'warning' | 'dangerous'`

Categorize payload safety level.

```typescript
filter.getSafetyLevel("' OR '1'='1");       // 'safe'
filter.getSafetyLevel("'; DROP TABLE--");   // 'dangerous'
filter.getSafetyLevel("'; EXEC xp_cmd");    // 'dangerous'
```

#### `getFilterStats(originalPayloads: string[]): FilterStats`

Get filtering statistics for a payload list.

```typescript
const stats = filter.getFilterStats(payloads);
// {
//   total: 25,
//   safe: 20,
//   dangerous: 4,
//   warning: 1
// }
```

#### `containsDestructiveKeywords(payload: string): boolean`

Check if payload contains dangerous keywords.

```typescript
filter.containsDestructiveKeywords("'; DROP TABLE users--");  // true
filter.containsDestructiveKeywords("' OR 1=1--");              // false
```

---

## TargetValidator

Utility for validating target URLs and enforcing production guardrails.

### Constructor

```typescript
import { TargetValidator } from '@tzigger/kinetic';

const validator = new TargetValidator(LogLevel.INFO);
```

### Methods

#### `validateUrl(url: string): ValidationResult`

Validate a target URL and detect environment type.

```typescript
interface ValidationResult {
  isValid: boolean;
  environment: 'local' | 'staging' | 'production' | 'unknown';
  isProduction: boolean;
  isLocal: boolean;
  warnings: string[];
  recommendations: string[];
}

// Local target
const local = validator.validateUrl('http://localhost:3000');
// {
//   isValid: true,
//   environment: 'local',
//   isProduction: false,
//   isLocal: true,
//   warnings: [],
//   recommendations: []
// }

// Production target
const prod = validator.validateUrl('https://production.example.com');
// {
//   isValid: true,
//   environment: 'production',
//   isProduction: true,
//   isLocal: false,
//   warnings: ['Target is production (not local)'],
//   recommendations: [
//     'Active scanning on non-local targets requires explicit confirmation',
//     'Consider using safe mode (safeMode: true) for non-local targets'
//   ]
// }

// Invalid URL
const invalid = validator.validateUrl('not-a-url');
// {
//   isValid: false,
//   environment: 'unknown',
//   warnings: ['Invalid URL format'],
//   ...
// }
```

#### `shouldBlockActiveScan(url: string, options?: Options): BlockResult`

Determine if active scanning should be blocked for a target.

```typescript
interface BlockResult {
  shouldBlock: boolean;
  reason: string;
}

// Production without confirmation
validator.shouldBlockActiveScan('https://production.example.com', {
  safeMode: true,
  confirmProduction: false
});
// { shouldBlock: true, reason: 'Active scanning blocked on production target...' }

// Production with confirmation
validator.shouldBlockActiveScan('https://production.example.com', {
  confirmProduction: true
});
// { shouldBlock: false, reason: 'Target is safe for active scanning' }

// Local target
validator.shouldBlockActiveScan('http://localhost:3000');
// { shouldBlock: false, reason: 'Target is safe for active scanning' }
```

#### `getSummary(url: string): string`

Get a formatted validation summary.

```typescript
const summary = validator.getSummary('https://production.example.com');
console.log(summary);
// Output:
// === Target Validation Summary ===
// URL: https://production.example.com
// Environment: production
// Local Target: No
// Production Target: Yes
// 
// Warnings:
//   1. Target is production (not local)
// 
// Recommendations:
//   1. Active scanning on non-local targets requires explicit confirmation
//   2. Consider using safe mode (safeMode: true) for non-local targets
// 
// ================================
```

---

## PayloadInjector with Safe Mode

### Constructor with Safe Mode

```typescript
import { PayloadInjector, LogLevel } from '@tzigger/kinetic';

// Safe mode disabled (default)
const injector1 = new PayloadInjector(LogLevel.INFO);

// Safe mode enabled
const injector2 = new PayloadInjector(LogLevel.INFO, true);
```

### Setting Safe Mode Dynamically

```typescript
injector.setSafeMode(true);
injector.setSafeMode(false);

// Output when enabling:
// [PayloadInjector] SafeMode ENABLED: Destructive payloads will be filtered

// Output when disabling:
// [PayloadInjector] SafeMode DISABLED: All payloads will be used
```

### Injection with Safe Mode

When safe mode is enabled, destructive payloads are blocked:

```typescript
// Safe payload - will be injected
const result = await injector.inject(page, surface, "' OR '1'='1");
// Success: payload injected

// Destructive payload - will be blocked
const result = await injector.inject(page, surface, "'; DROP TABLE users--");
// Result: {
//   payload: "'; DROP TABLE users--",
//   error: 'Payload blocked by safe mode - contains destructive operations'
// }
// Console: [PayloadInjector] BLOCKED (Safe Mode): Destructive payload attempt - ...
```

---

## Active Scanning with Safe Mode

Safe mode applies to **active payload injection** (via `PayloadInjector`) and is controlled by `scanners.active.safeMode`.

- For non-local targets, `ScanEngine` will auto-enable safe mode if `safeMode` is not explicitly set.
- When safe mode is enabled, destructive payloads (e.g. `DROP TABLE`, `DELETE FROM`) are blocked at injection time.

---

## ScanEngine with Production Guardrails

### Automatic Safe Mode Enablement

```typescript
import { ScanEngine } from '@tzigger/kinetic';

const engine = new ScanEngine();

const config = {
  target: {
    url: 'https://production.example.com'
  },
  scanners: {
    active: {
      enabled: true,
      safeMode: false  // This will be overridden!
    }
  }
};

await engine.loadConfiguration(config);
const result = await engine.scan();

// Console output:
// [ScanEngine] Validating target...
// [TargetValidator] Validated target: production.example.com (production) - 
//                   isLocal: false, isProduction: true
// [ScanEngine] Target is non-local (non-localhost). Automatically enabling safe mode to prevent destructive payloads.
// [ScanEngine] SECURITY WARNING: Active scanning is enabled on production target. 
//              Ensure you have explicit permission...
```

### Pre-scan Validation

The ScanEngine performs validation before scanning:

1. Validates URL format
2. Detects environment type
3. Checks HTTPS on production
4. Warns about non-standard ports
5. Auto-enables safe mode for non-local targets

---

## Configuration Examples

### Local Development (No Safe Mode)

```json
{
  "target": {
    "url": "http://localhost:3000"
  },
  "scanners": {
    "active": {
      "enabled": true,
      "safeMode": false,
      "aggressiveness": "aggressive"
    }
  }
}
```

### Staging (Safe Mode Enabled)

```json
{
  "target": {
    "url": "https://staging.myapp.com"
  },
  "scanners": {
    "active": {
      "enabled": true,
      "safeMode": true,
      "aggressiveness": "medium"
    }
  }
}
```

### Production (Passive Only)

```json
{
  "target": {
    "url": "https://production.myapp.com"
  },
  "scanners": {
    "passive": {
      "enabled": true
    },
    "active": {
      "enabled": false
    }
  }
}
```

### Production with Safe Active Scanning

```json
{
  "target": {
    "url": "https://production.myapp.com"
  },
  "scanners": {
    "passive": {
      "enabled": true
    },
    "active": {
      "enabled": true,
      "safeMode": true,
      "aggressiveness": "low",
      "delayBetweenRequests": 500,
      "maxInputsPerPage": 5
    }
  }
}
```

---

## Error Handling

### Handling Blocked Payloads

```typescript
const injector = new PayloadInjector(LogLevel.INFO, true);

const result = await injector.inject(page, surface, destructivePayload);

if (result.error) {
  console.log('Payload was blocked:', result.error);
  // 'Payload blocked by safe mode - contains destructive operations'
}
```

### Checking Validation Results

```typescript
const validator = new TargetValidator();
const result = validator.validateUrl(url);

if (!result.isValid) {
  throw new Error(`Invalid target URL: ${url}`);
}

if (result.isProduction && !hasApproval) {
  throw new Error('Production scanning requires explicit approval');
}
```

---

## Logging & Audit Trail

### Enabling Detailed Logging

```typescript
import { LogLevel } from '@tzigger/kinetic';

// Enable INFO or DEBUG level to see safety operations
const filter = new PayloadFilter(LogLevel.DEBUG);
const validator = new TargetValidator(LogLevel.DEBUG);
const injector = new PayloadInjector(LogLevel.DEBUG, true);
const scanner = new ApiScanner({}, LogLevel.DEBUG, true);
```

### Example Log Output

```
[PayloadFilter] Filtered out 5 destructive payload(s) in safe mode. (18/23 payloads remain safe)
[PayloadInjector] BLOCKED (Safe Mode): Destructive payload attempt - '; DROP TABLE users--...
[TargetValidator] Validated target: production.example.com (production) - isLocal: false, isProduction: true
[ScanEngine] === Target Validation Summary ===
[ScanEngine] URL: https://production.example.com
[ScanEngine] Environment: production
[ScanEngine] Production Target: Yes
```

---

## Best Practices

### 1. Always Validate Before Scanning

```typescript
const validator = new TargetValidator();
const validation = validator.validateUrl(config.target.url);
console.log(validator.getSummary(config.target.url));
```

### 2. Use Safe Mode on Non-Local Targets

```typescript
if (!validation.isLocal) {
  config.scanners.active.safeMode = true;
}
```

### 3. Log All Filtering Operations

```typescript
const filter = new PayloadFilter(LogLevel.INFO);
const stats = filter.getFilterStats(payloads);
console.log(`Payloads: ${stats.safe} safe, ${stats.warning} warning, ${stats.dangerous} dangerous`);
```

### 4. Explicitly Confirm Production Scanning

```typescript
if (validation.isProduction && !approvedBySecurityTeam) {
  throw new Error('Production scanning requires security team approval');
}
```

---

## See Also

- [Safe Mode & Production Guardrails Documentation](./SAFE-MODE.md)
- [Configuration Reference](./README.md)
