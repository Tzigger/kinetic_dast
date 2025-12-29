# OWASP Top 10 2025 - Implementation Roadmap

This document tracks Kinetic's coverage of the [OWASP Top 10 2025](https://owasp.org/www-project-top-ten/).

## 🏆 Current Status (v0.2.0)

**Overall Coverage: ~45%**

We have strong coverage for **Injection (A05)**, **Security Misconfiguration (A02)**, and **Cryptographic Failures (A04)**. The next major focus is Authentication and complex Access Control logic.

---

## Detailed Breakdown

### A01:2025 - Broken Access Control
**Status: 40% Implemented**

*   ✅ **Path Traversal** (`PathTraversalDetector`) - Detects LFI/RFI (`/etc/passwd`, `..\win.ini`).
*   ✅ **SSRF** (`SsrfDetector`) - Detects cloud metadata access (`169.254.169.254`).
*   ❌ **IDOR / BOLA** - Requires logic to replay requests with different IDs (Planned v0.3).
*   ❌ **Forced Browsing** - Discovery of unlinked admin pages.

### A02:2025 - Security Misconfiguration
**Status: 70% Implemented**

*   ✅ **Security Headers** (`HeaderSecurityDetector`) - HSTS, CSP, X-Frame-Options.
*   ✅ **Cookie Flags** (`CookieSecurityDetector`) - HttpOnly, Secure, SameSite.
*   ✅ **CORS Issues** (`HeaderSecurityDetector`) - Wildcard origins.
*   ✅ **Error Disclosure** (`ErrorBasedDetector`) - Stack traces, database errors.
*   ❌ **Unused Pages** - Detection of default install pages/files.

### A03:2025 - Software Supply Chain Failures
**Status: 20% Implemented**

*   ✅ **Vulnerable JS Libraries** (`PassiveScanner`) - Basic version regex matching (jQuery, Angular).
*   ❌ **Dependency Analysis** - Scanning `package.json` or analyzing build artifacts.
*   ❌ **CI/CD Integrity** - Out of scope for DAST.

### A04:2025 - Cryptographic Failures
**Status: 50% Implemented**

*   ✅ **Insecure Transmission** (`InsecureTransmissionDetector`) - HTTP vs HTTPS, Mixed Content.
*   ✅ **Sensitive Data Exposure** (`SensitiveDataDetector`) - Keys, Tokens, PII in transit.
*   ❌ **Weak Ciphers/TLS** - Requires lower-level network analysis (Node `tls` module hooks).

### A05:2025 - Injection
**Status: 90% Implemented**

*   ✅ **SQL Injection** (`SqlInjectionDetector`) - Error, Boolean, Time-based, Union.
*   ✅ **Cross-Site Scripting** (`XssDetector`) - Reflected, Stored, DOM, JSON.
*   ✅ **Command Injection** (`InjectionDetector`) - OS Command injection.
*   ✅ **SSTI** (`InjectionDetector`) - Server-Side Template Injection.
*   ✅ **XML Injection** (`InjectionDetector`) - Basic XXE patterns.

### A06:2025 - Insecure Design
**Status: 10% Implemented**

*   ⚠️ **Business Logic** - Hard to automate generically. Requires custom detectors.
*   ❌ **Rate Limiting** - Detection of missing throttling.

### A07:2025 - Authentication Failures
**Status: 30% Implemented**

*   ✅ **Session Management** (`SessionManager`) - Supports auth headers/cookies.
*   ❌ **Brute Force Detection** - Checking for lockout mechanisms.
*   ❌ **Weak Password Policy** - Profiling registration endpoints.
*   ❌ **Credential Stuffing** - Not implemented.

### A08:2025 - Software/Data Integrity Failures
**Status: 10% Implemented**

*   ✅ **Insecure Deserialization** (`InjectionDetector`) - Basic payload checks.
*   ❌ **Integrity Checks** - Verifying SRI hashes.

### A09:2025 - Logging & Alerting Failures
**Status: N/A**
*   Hard to test via DAST (requires internal view).

### A10:2025 - Mishandling Exceptional Conditions
**Status: 60% Implemented**

*   ✅ **Error Handling** (`ErrorBasedDetector`) - Detects unhandled exceptions and verbose errors.

---

## 📅 Roadmap to v1.0.0

### Phase 3: Authentication & Logic (Target: v0.3.0)
- [ ] **Auth Scanner**: Detect default credentials, weak password policies.
- [ ] **IDOR Detector**: Replay requests with modified User IDs.
- [ ] **CSRF Detector**: Verify anti-CSRF tokens on state-changing requests.

### Phase 4: API & Modern Web (Target: v0.4.0)
- [ ] **GraphQL Support**: Introspection analysis and specific injection depths.
- [ ] **WebSocket Scanning**: Intercept and fuzz WS messages.
- [ ] **OpenAPI/Swagger**: Fuller integration for deep API coverage.

### Phase 5: Enterprise Ready (Target: v1.0.0)
- [ ] **Report Web UI**: Interactive dashboard.
- [ ] **Distributed Scanning**: Multi-agent support.
- [ ] **Plugin Marketplace**: Dynamic loading of external npm plugins.
