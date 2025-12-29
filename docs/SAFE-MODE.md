# Safe Mode & Production Guardrails

Kinetic includes a robust safety system designed to prevent accidental damage to production environments during active security scanning.

## 🛡️ How It Works

Safe Mode operates on two layers:

1.  **Environment Detection (`TargetValidator`)**:
    *   Before scanning starts, Kinetic analyzes the target URL.
    *   **Local Targets** (`localhost`, `127.0.0.1`, private IPs): Safe Mode is **OFF** by default.
    *   **Remote/Production Targets**: Safe Mode is **auto-enabled** to prevent accidents.

2.  **Payload Filtering (`PayloadFilter`)**:
    *   When Safe Mode is active, every payload is checked against a blocklist of destructive patterns before injection.
    *   **Blocked**: Data modification (`DROP`, `DELETE`, `UPDATE`), System commands (`rm`, `shutdown`, `xp_cmdshell`), Privilege changes (`GRANT`, `REVOKE`).
    *   **Allowed**: Discovery payloads (`' OR 1=1`, `SLEEP(5)`, `<script>alert(1)</script>`).

---

## ⚙️ Configuration

### Auto-Enablement behavior
If you run `kinetic https://my-production-app.com`, Kinetic will output:
> ⚠️ Target is non-local. Automatically enabling Safe Mode.

### Explicitly Enabling Safe Mode
You can force Safe Mode on local environments (e.g., for testing the filter itself):

```json
// kinetic.config.json
{
  "scanners": {
    "active": {
      "safeMode": true
    }
  }
}
```

### Disabling Safe Mode (Dangerous)
To run destructive tests against a remote target (e.g., a specific staging sandbox), you must explicitly disable the guardrails.

**Via CLI:**
```bash
kinetic https://staging.example.com --active --safemode-disable
```

**Via Config:**
```json
{
  "scanners": {
    "active": {
      "safeMode": false
    }
  }
}
```

---

## 💻 API Reference

If you are writing custom detectors or scripts, you can interact with the safety modules directly.

### `PayloadFilter`
Used to check if a string contains destructive SQL or System commands.

```typescript
import { PayloadFilter } from '@tzigger/kinetic/utils';

const filter = new PayloadFilter();

// Check specific payloads
console.log(filter.isSafe("' OR '1'='1"));          // true
console.log(filter.isSafe("'; DROP TABLE users--")); // false

// Filter a list
const safeList = filter.filterPayloads([
  "' OR 1=1", 
  "'; DELETE FROM users"
]); 
// Returns: ["' OR 1=1"]
```

### `TargetValidator`
Used to determine if a URL represents a production environment.

```typescript
import { TargetValidator } from '@tzigger/kinetic/utils';

const validator = new TargetValidator();
const result = validator.validateUrl('https://api.production.com');

if (result.isProduction) {
  console.warn('Production target detected! Enforcing guardrails.');
}
```

---

## 🏗️ Architecture

The safety check happens at the lowest level of the injection process to ensure no scanner or detector bypasses it accidentally.

1.  **ScanEngine** initializes.
2.  **TargetValidator** determines if the environment is Local or Remote.
3.  If Remote and `safemode-disable` is NOT present → **Force Safe Mode**.
4.  **ActiveScanner** passes the `safeMode` boolean state to the **PayloadInjector**.
5.  **PayloadInjector** runs every payload through `PayloadFilter.isSafe()` immediately before execution.
    *   If Unsafe: The injection is skipped, and a warning is logged.
    *   If Safe: The injection proceeds.

---

## ❓ FAQ

**Q: Does Safe Mode block XSS testing?**
A: **No.** XSS payloads (like `<script>`) generally do not destroy server-side data, so they are allowed. Safe Mode focuses on SQL Injection and Command Injection payloads that delete data or compromise the host OS.

**Q: Can I customize the blocklist?**
A: Currently, the blocklist is hardcoded in `src/utils/PayloadFilter.ts` to ensure a baseline of safety. Custom blocklists are planned for v1.0.

**Q: I am getting "Payload blocked by safe mode" in my local logs.**
A: Check your config. You might have `safeMode: true` set globally, or your local URL might be parsing as a non-private IP.
