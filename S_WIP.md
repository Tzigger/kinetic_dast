# Security WIP

**Goal:** To establish a common minimum standard of security checks for web applications and APIs.

| **Category** | **Test Objective** | **Verification Description** | **Risk Severity** | **Applicability (M/A)** |
| --- | --- | --- | --- | --- |
| **Authentication & Session Management** |  |  |  |  |
| Authentication Validation | Ensure only legitimate users access the system and that the login process is robust. | Verify endpoints reject requests with **missing, invalid, or expired tokens**. Test susceptibility to **brute-force attacks** and **session fixation risks**. Track **authentication failure rates** (< 5% threshold). | 🔴 High | Automated (A⚙️) |
| Session Handling & Tokens | Ensure proper management and security of sessions and tokens. | Validate proper **session handling**. Check for missing, invalid, or expired tokens (e.g., Bearer tokens). | 🔴 High | Automated (A⚙️) |
| Cookie Attributes | Prevent client-side risks related to cookies. | Verify critical security flags are present on cookies: **Secure**, **HttpOnly**, or **SameSite** flags. Check for overly broad cookie scope. | 🟠 Medium | Automated (A⚙️) |
| **Authorization (Access Control)** |  |  |  |  |
| Access Control (IDOR/BOLA) | Ensure users can access only their authorized resources. | Verify a user **cannot access, modify, or delete resources** (e.g., reports, customer data) belonging to another user (Insecure Direct Object References - IDOR). | 🔴 High | M✋/A⚙️ |
| Mass Assignment (API) | Prevent unauthorized field modification. | Attempt to inject unauthorized parameters in update requests (e.g., `"role": "admin"`, `"is_paid": true`) to overwrite protected fields. | 🔴 High | M✋ / A⚙️ |
| Privilege Escalation | Prevent users from performing actions above their defined permission level. | Check for **missing function-level access checks** and attempt **privilege escalation paths**. Ensure **tenant separation** (e.g., one user/PLP cannot see resources from another PLP). | 🔴 High | Manual (M✋) |
| **Input Validation & Injection Flaws** |  |  |  |  |
| SQL Injection (SQLi) | Prevent malicious data input from modifying database queries. | Test all user-controllable parameters (query strings, bodies, headers) using common injection payloads (e.g., `'`, `"`, `;`, `--`, `' OR '1'='1`, `admin'#`, encoded payloads). Expect input sanitization or rejection (e.g., 400 Bad Request). | 🔴 High | Automated (A⚙️) |
| Cross-Site Scripting (XSS) | Prevent execution of malicious client-side code. | Check for **Inline or reflected XSS vectors**. Test for general **Cross-Site Scripting (XSS)** vulnerabilities. | 🔴 High | Automated (A⚙️) |
| SSRF | Prevent server from making unauthorized calls. | If app fetches external URLs, test access to internal IPs (127.0.0.1) or Cloud Metadata services. | 🔴 High | A⚙️ / M✋ |
| Command/Code Injection | Prevent execution of system commands or arbitrary code on the server. | Test for **Command Injection** and **XML External Entity (XXE)** injection flaws. | 🔴 High | Automated (A⚙️) |
| Path Traversal | Prevent access to unauthorized system files. | Test input parameters for **path traversal attempts** using sequences such as `../`. | 🔴 High | Automated (A⚙️) |
| **Transport Security & Cryptography** |  |  |  |  |
| SSL/TLS Protocol Configuration | Ensure the application uses strong and current cryptographic protocols. | Audit supported **protocol versions** (e.g., SSL 2.0, 3.0, TLS 1.0, 1.1 are insecure/deprecated). Verify only secure protocols (TLS 1.2, TLS 1.3) are supported. | 🔴 High | Automated (A⚙️) |
| Cipher Suite Strength | Ensure the confidentiality and integrity of data in transit. | Analyze and audit for **weak cipher suites**. | 🟠 Medium | Automated (A⚙️) |
| Known Vulnerabilities | Ensure protection against known cryptographic attacks. | Check for known vulnerabilities (CVEs) such as **Heartbleed, BEAST, CRIME, and POODLE attacks**. Verify absence of certificate issues (e.g., expired, self-signed, weak signature). | 🔴 High | Automated (A⚙️) |
| **Security Configuration & Headers** |  |  |  |  |
| HTTP Security Headers | Enforce browser-side security policies and mitigate common attacks. | Verify presence and correct configuration of critical headers: **Strict-Transport-Security (HSTS)**, **Content-Security-Policy (CSP)**, **X-Frame-Options**, **X-Content-Type-Options**, and **Referrer-Policy**. | 🟠 Medium | Automated (A⚙️) |
| Request Forgery Prevention | Prevent unauthorized actions initiated by a third party. | Check for Cross-Site Request Forgery (**CSRF**) by scanning for missing tokens. Test for Server-Side Request Forgery (**SSRF**). | 🔴 High | Automated (A⚙️) |
| **Resilience and Rate Limiting** |  |  |  |  |
| DDoS / Rate Limiting | Ensure the system maintains availability and correctly handles high load. | Simulate high traffic patterns (Ramp-up, Spike, Stress Testing) to observe if requests are **rejected after load** is reached. Verify performance SLAs (e.g., HTTP Request Failure Rate < 10%). | 🔴 High | Automated (A⚙️) |
| Endurace/Soak Testing | Detect resource exhaustion issues over time. | Run system under constant, low-level load for an extended period (e.g., 12 hours) to reveal issues like **memory leaks** or long-term throttling problems. Track history of **latency** for key endpoints. | 🟠 Medium | Automated (A⚙️) |
| Race Conditions | Detect concurrency flaws | Send **simultaneous requests** (multi-threaded) to identify logic flaws (e.g., using a single-use coupon twice, double-spending). | 🔴 High | Automated (A⚙️) |
| Fail-Secure Testing | Ensure system fails safely. | Force critical failures (DB timeout, Payment down). Verify system fails "closed" and data remains consistent (transaction rollback). | 🔴 High | Manual (M✋) |
| **Information Leakage & Error Handling** |  |  |  |  |
| Error Message Disclosure | Prevent attackers from gaining insight into the server environment. | Validate that error messages are non-verbose and do not disclose sensitive details like **server software**, **technology stack details**, **directory listings**, or other verbose error messages. | 🟠 Medium | Automated (A⚙️) |
| Sensitive Data Logging | Ensure sensitive data is not accidentally recorded. | Verify that sensitive data, such as **passwords and tokens**, is **redacted in logs**. | 🟠 Medium | Automated (A⚙️) |
| Client-Side Risks | Ensure content is delivered securely and integrity is maintained. | Check for **mixed-content warnings** (HTTP content served over HTTPS), **insecure form submissions**, and improperly **cacheable HTTPS responses**. | 🟡 Low | Automated (A⚙️) |
| **Supply Chain & Integrity** |  |  |  |  |
| Dependency Vulnerabilities (SCA) | Prevent usage of components with known vulnerabilities. | Scan all third-party libraries (npm, nuget, maven) for known CVEs. Ensure no components with CVSS > 7.0 are present in the build. | 🔴 High | Automated (A⚙️) |
| Secret Scanning | Prevent leakage of credentials in code. | Scan codebase and commit history for hardcoded secrets, API keys, and tokens to prevent credential leaks. | 🔴 High | Automated (A⚙️) |
| Insecure Deserialization | Prevent remote code execution via objects. | Verify that the application does not accept untrusted serialized objects (Java/PHP/.NET) that could lead to RCE. | 🔴 High | A⚙️ / M✋ |
| Dependency Confusion | Prevent public package substitution. | Verify that internal private packages cannot be substituted by public packages with the same name. Check registry precedence settings. | 🔴 High | Automated (A⚙️) |
| **AI & LLM Safety** |  |  |  |  |
| Prompt Injection | Prevent manipulation of AI logic. | Attempt to override AI system instructions ("Ignore previous rules..."). | 🔴 High | Manual (M✋) |
| Insecure Output Handling | Prevent AI-generated attacks. | Verify AI-generated content is treated as untrusted (sanitized) before rendering to prevent XSS. | 🔴 High | Manual (M✋) |

---

**CI Jobs (Integrated Security Pipeline)**

The security pipeline integrates multiple scanners and performance tests, executed via GitHub Actions.

| **CI Job** | **Tool / Functionality** | **Policy / Goal** |
| --- | --- | --- |
| SAST | **SonarQube**. | Provides a text file summary of file name and error for developers to fix. |
| DAST-lite (Passive) | **OWASP ZAP** integrated with Playwright. | Contextualized scanning restricted to specified URL patterns; analyzes HTTP requests/responses for common security misconfigurations. |
| Headers/TLS Scan | **SecurityHeaders Scanner**, **SSL Labs Scanner**, **TestSSL.sh Scanner**. | Audits protocol support (SSL/TLS versions), cipher strengths, and known CVEs (Heartbleed, POODLE). Checks for missing HTTP security headers (CSP, HSTS, etc.). |
| Stress & Resilience Test | **K6 API Stress Test**. | Validates system performance under load; enforces strict performance thresholds (SLA targets). |
| DB/Access Control Test | **Security Integration Tests** (tagged `access-control` and `sql-injection`). | Ensures unauthorized requests receive **401/403 status codes** and SQL injection attempts are sanitized. |
| Fail-on-High Policy | **Threshold Enforcement / Delta Monitoring**. | Failures in K6 tests occur if SLAs are violated (e.g., failure rate > 10%). Results are monitored every sprint to identify any significant issues (deltas) requiring action. |
| SCA / Dependency Scan | **Snyk / OWASP Dependency-Check** | Scans `package.json` / `.csproj`. **Block build** on Critical/High CVEs. |
| Secret Scanning | **TruffleHog / Gitleaks** | Scans git history & commits. **Block build** immediately if secrets are found. |

---

**KPI Dashboard (Metrics Tracking)**

| **KPI Metric** | **Measurement Detail** | **Source** |
| --- | --- | --- |
| Open Vulns by Severity | Tracking the distribution of findings categorized as **High, Medium, Low, and Informational**. |  |
| Authentication Failures | Custom metric (`auth_failures`) tracked during stress testing. Threshold: **< 5%**. |  |
| Performance Trends | Custom metrics tracked: `custom_report_creation_time` and `report_query_time`. |  |
| Request Failure Rate | HTTP Request Failure Rate. Threshold: **< 10%**. |  |
| Latency History | **Tracking a history of latency** for all endpoints by running soak tests (12 hours) to correlate performance degradation with time/events. |  |

---

**References:**

[Introduction - OWASP Top 10:2025 RC1](https://owasp.org/Top10/2025/0x00_2025-Introduction/)