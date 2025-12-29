# Kinetic Architecture

> System design and component interaction for Kinetic v0.2.0.

## System Overview

Kinetic is built on a modular, layered architecture designed for extensibility and reliability. It orchestrates Playwright for browser automation while managing complex logic for crawling, payload injection, traffic interception, and result verification.

## Architectural Layers

### 1. Testing Layer (Entry Points)
- **Helpers**: `runActiveSecurityScan()`, `runPassiveSecurityScan()`.
- **CLI**: `kinetic` command-line interface.
- **Playwright Integration**: Adapters to reuse existing `Page` objects.

### 2. Core Layer (Orchestration)
- **ScanEngine**: The central controller. Manages lifecycle, config loading, and event event dispatching.
- **BrowserManager**: Handles Playwright browser contexts, pages, and lifecycle.
- **ConfigurationManager**: Validates and merges JSON/CLI configurations.
- **SessionManager**: Handles authentication state (Cookies/LocalStorage) and auto-login heuristics.

### 3. Scanner Layer (Execution)
- **ActiveScanner**: The main crawler. Discovers attack surfaces and injects payloads.
- **ElementScanner**: **(New v0.2)** Targeted scanner for specific DOM elements (via locators).
- **PassiveScanner**: Analyzes network traffic using `NetworkInterceptor`.
- **DomExplorer**: Analyzes DOM to find inputs, forms, and API endpoints.

### 4. Strategy Layer (Detection & Verification)
- **Detectors**: Logic for identifying potential vulnerabilities (SQLi, XSS, etc.).
- **PayloadInjector**: Context-aware injection with Safe Mode filtering.
- **VerificationEngine**: **(New v0.2)** Statistical analysis to confirm findings.
- **TimeoutManager**: **(New v0.2)** Adaptive timeout strategies for SPAs.

### 5. Reporting Layer
- **Reporters**: Console, JSON, HTML, SARIF output generators.

---

## Component Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                      ScanEngine                             │
│ ┌────────────────┐  ┌──────────────┐  ┌──────────────────┐  │
│ │ BrowserManager │  │ ConfigManager│  │ SessionManager   │  │
│ └───────┬────────┘  └──────────────┘  └────────┬─────────┘  │
└─────────┼──────────────────────────────────────┼────────────┘
          │                                      │
          ▼                                      ▼
┌────────────────────┐                 ┌────────────────────┐
│   ActiveScanner    │                 │   PassiveScanner   │
│ ┌────────────────┐ │                 │ ┌────────────────┐ │
│ │  DomExplorer   │ │                 │ │NetworkIntercept│ │
│ └───────┬────────┘ │                 │ └───────┬────────┘ │
│         ▼          │                 │         ▼          │
│ ┌────────────────┐ │                 │ ┌────────────────┐ │
│ │ PayloadInjector│ │                 │ │ResponseAnalyzer│ │
│ └───────┬────────┘ │                 │ └───────┬────────┘ │
└─────────┼──────────┘                 └─────────┼──────────┘
          │                                      │
          ▼                                      ▼
┌─────────────────────────────────────────────────────────────┐
│                     Detector Registry                       │
│  [SqlInjection] [XssDetector] [SensitiveData] [Headers] ... │
└─────────────────────────┬───────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│                  Verification Engine                        │
│  [TimeBasedVerifier] [ResponseDiffVerifier] [ReplayVerifier]│
└─────────────────────────┬───────────────────────────────────┘
                          │
                          ▼
                  ┌───────────────┐
                  │ ScanResult    │
                  └───────────────┘
```

---

## Core Flows

### 1. Active Scan Flow
1.  **Init**: `ScanEngine` initializes. `SessionManager` performs auto-login if configured.
2.  **Crawl**: `ActiveScanner` navigates to target. `DomExplorer` identifies inputs (Forms, URLs, APIs).
3.  **Inject**: `PayloadInjector` sends payloads (filtered by Safe Mode).
4.  **Detect**: Active Detectors (e.g., `SqlInjectionDetector`) analyze responses for errors/anomalies.
5.  **Verify**: If a vulnerability is found, `VerificationEngine` takes over:
    *   Runs **TimeBasedVerifier** (Z-score analysis) for blind injections.
    *   Runs **ResponseDiffVerifier** (Structural JSON diffing) for boolean logic.
6.  **Report**: Confirmed vulnerabilities are added to the final report.

### 2. Element Scan Flow (Targeted)
1.  **Config**: User provides specific locators (e.g., `#login-btn`, `input[name="q"]`).
2.  **Locate**: `ElementScanner` finds elements directly (skips crawling).
3.  **Context**: Converts element properties into an `AttackSurface`.
4.  **Inject/Detect/Verify**: Follows the standard active scan logic for just those elements.

### 3. Passive Scan Flow
1.  **Attach**: `NetworkInterceptor` attaches to the Playwright Page CDP session.
2.  **Monitor**: Captures all HTTP/S Requests and Responses.
3.  **Analyze**: `ResponseAnalyzer` checks for:
    *   PII (Emails, Keys)
    *   Security Headers
    *   Cookie Flags
    *   Unencrypted Transmission
4.  **Report**: Issues are reported immediately (no verification step needed for passive).

---

## Key Subsystems (v0.2 Updates)

### Verification Engine
To reduce false positives, Kinetic uses a multi-stage verification process.

*   **Statistical Analysis**: Uses Welch's t-test and standard deviation to determine if a time delay (e.g., `SLEEP(5)`) is statistically significant compared to baseline latency.
*   **Structural Diffing**: Compares the JSON structure or HTML DOM tree of responses to "True" vs "False" payloads, rather than just text matching.

### Timeout Manager & SPA Strategy
Handling modern SPAs requires more than hardcoded sleeps.

*   **SPAWaitStrategy**: Detects the framework (Angular, React, Vue). Uses framework-specific hooks (e.g., `ngZone.isStable`, `Vue.nextTick`) to ensure the page is idle.
*   **Adaptive Timeouts**: The `TimeoutManager` observes the application's response time. If the app is slow, it dynamically increases timeouts to prevent false negatives.

### Safe Mode Architecture
Safety is enforced at the lowest level of injection.

1.  **Configuration**: User sets `safeMode: true` (or auto-enabled for non-local).
2.  **PayloadFilter**: Loaded by `PayloadInjector`.
3.  **Check**: Before *any* payload is sent, it is regex-matched against destructive patterns (`DROP`, `TRUNCATE`, `GRANT`).
4.  **Action**: Destructive payloads are silently dropped; informational payloads (`OR 1=1`) are allowed.

---

## Extension Points

### Custom Detectors
Implement `IActiveDetector` or `IPassiveDetector`. Register via `DetectorRegistry`.

```typescript
class MyDetector implements IActiveDetector {
  async detect(context) { /* ... */ }
}
```

### Custom Reporters
Implement `IReporter`.

```typescript
class MyReporter implements IReporter {
  async generate(result) { /* ... */ }
}
```

### Plugins
(Future v1.0) The architecture allows for dynamic loading of external modules via `PluginManager` (currently stubbed).

---

## Design Patterns Used

*   **Strategy Pattern**: Detectors and Verifiers are interchangeable strategies.
*   **Singleton**: `DetectorRegistry`, `BrowserManager`, and `ConfigurationManager`.
*   **Observer**: `ScanEngine` emits events (`scan:start`, `vulnerability:found`) for Reporters/CLI to consume.
*   **Adapter**: `ElementScanner` adapts specific locators into the generic `AttackSurface` interface used by detectors.
*   **Chain of Responsibility**: `VerificationEngine` passes a candidate vulnerability through multiple verifiers.
