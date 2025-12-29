# bWAPP Validation Guide

This guide documents the validation strategy for **Kinetic** using the **bWAPP** (buggy Web Application) testbed. We use this to benchmark detection rates against known vulnerable endpoints using the targeted **Element Scanner**.

## 🧪 Benchmark Environment

*   **Target**: bWAPP (installed locally via Docker or XAMPP)
*   **Default URL**: `http://localhost:8080/`
*   **Auth**: `bee` / `bug` (Security Level 0)

## Authentication Setup

The integration tests rely on a pre-authenticated state to avoid logging in for every single test case.

*   **State File**: `storage-states/bwapp-auth.json`
*   **Setup**: The global setup script (or `global-setup.ts`) performs the login sequence and saves the cookies/local storage to this file.

## 🤖 Automated Validation Suites

We use **Playwright Integration Tests** to verify that specific detectors work against specific vulnerable fields.

### Element Scanner Tests
**File**: `tests/integration/bwapp-element-scanner.spec.ts`

This suite uses the `ElementScanner` to target specific DOM elements (inputs) known to be vulnerable. This isolates the detector logic from the crawler logic.

**Command:**
```bash
BWAPP_URL=http://localhost:8080 npx playwright test tests/integration/bwapp-element-scanner.spec.ts
```

**Coverage:**

| Test Case | Page | Element | Detector Used | Expected Result |
|-----------|------|---------|---------------|-----------------|
| **SQL Injection** | `/sqli_1.php` | `input[name="title"]` | `SqlInjectionDetector` | **CWE-89** found with confidence ≥ 0.8 |
| **Reflected XSS** | `/xss_get.php` | `input[name="firstname"]` | `XssDetector` | **CWE-79** found with confidence ≥ 0.8 |
| **Command Injection** | `/commandi.php` | `input[name="target"]` | `InjectionDetector` | **CWE-78** found with confidence ≥ 0.7 |

**Validation Criteria:**
1.  **Detection**: At least one vulnerability must be found for the target CWE.
2.  **Confidence**: The `VerificationEngine` must confirm the finding (Confidence > 0.7).
3.  **Evidence**: The result must include request/response evidence.

## 🛠️ Manual & Debugging Scenarios

For development and debugging, we provide a standalone script that runs the `ElementScanner` with verbose logging.

**File**: `examples/03-bwapp-scan.ts`

**Usage:**
```bash
# Ensure bWAPP is running
npm run build
npx ts-node examples/03-bwapp-scan.ts
```

**What it does:**
1.  Launches a headless browser.
2.  Logs into bWAPP automatically.
3.  Runs targeted scans against:
    *   Movie Search (SQLi)
    *   Firstname Input (XSS)
    *   DNS Lookup (Command Injection)
4.  Prints a summary of findings to the console.

## ⚠️ Known Limitations

1.  **CSRF**: Automated CSRF detection is currently manual-only.
2.  **Scope**: These tests validate the *detectors* and the *ElementScanner*. They do not validate the *ActiveScanner's* crawling/spidering capabilities.
