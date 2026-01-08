# Architecture Diagrams

## Before Refactoring (Problematic)

### ActiveScanner God Class
```
┌─────────────────────────────────────────────────────────────┐
│                      ActiveScanner                          │
│  (God Class - Multiple Responsibilities)                   │
├─────────────────────────────────────────────────────────────┤
│  - Queue management (urls, visited, depth)                 │
│  - Page navigation                                          │
│  - Surface discovery                                        │
│  - Detector orchestration                                   │
│  - Verification                                             │
│  - Worker coordination                                      │
│  - Result aggregation                                       │
│  - Reporting                                                │
│  - Session management                                       │
│  - Parallelism control                                      │
└─────────────────────────────────────────────────────────────┘
        ⬇️ (Tight coupling - too many responsibilities)
```

### NetworkInterceptor Tight Coupling
```
┌────────────────────────────────────────────────┐
│          NetworkInterceptor                    │
│  (Knows HOW to analyze - violation of DIP)    │
├────────────────────────────────────────────────┤
│  - Intercepts HTTP traffic                     │
│  - Stores requests/responses                   │
│  - Instantiates ResponseAnalyzer ❌            │
│  - Calls analyzer.analyze() ❌                 │
│  - Stores vulnerabilities ❌                   │
└────────────────────────────────────────────────┘
           │
           │ (Direct instantiation)
           ⬇️
┌────────────────────────────────────────────────┐
│          ResponseAnalyzer                      │
│  (Tightly coupled)                             │
├────────────────────────────────────────────────┤
│  - Analyzes responses                          │
│  - Detects SQL errors                          │
│  - Detects XSS reflections                     │
│  - Detects sensitive data                      │
└────────────────────────────────────────────────┘
```

---

## After Refactoring (SOLID Compliant)

### ActiveScanner with SRP
```
┌────────────────────────────────────────────────┐
│          ActiveScanner                         │
│  (Orchestrator - Single Responsibility)       │
├────────────────────────────────────────────────┤
│  - Session management                          │
│  - Worker coordination                         │
│  - Result aggregation                          │
│  - Progress tracking                           │
└────────────────────────────────────────────────┘
           │
           │ Uses
           ⬇️
┌────────────────────────────────────────────────┐
│          CrawlManager                          │
│  (Single Responsibility: Crawl State)         │
├────────────────────────────────────────────────┤
│  - Queue management                            │
│  - Visited tracking                            │
│  - Depth tracking                              │
│  - Limit checking                              │
└────────────────────────────────────────────────┘

           │
           │ Coordinates
           ⬇️
┌────────────────────────────────────────────────┐
│          ExecutionWorker                       │
│  (Single Responsibility: Process Page)        │
├────────────────────────────────────────────────┤
│  - Page navigation                             │
│  - Surface discovery                           │
│  - Detector execution                          │
│  - Verification                                │
│  - Link discovery                              │
└────────────────────────────────────────────────┘
   │
   │ Multiple workers run in parallel
   ⬇️
```

### NetworkInterceptor with DIP
```
┌────────────────────────────────────────────────┐
│          NetworkInterceptor                    │
│  (Pure Event Emitter - Follows DIP)           │
├────────────────────────────────────────────────┤
│  - Intercepts HTTP traffic ✅                  │
│  - Stores requests/responses ✅                │
│  - Emits 'response' events ✅                  │
│  - NO analysis knowledge ✅                    │
└────────────────────────────────────────────────┘
           │
           │ Emits events
           ⬇️
┌────────────────────────────────────────────────┐
│      PassiveScanOrchestrator                   │
│  (Wiring Layer - Follows DIP)                 │
├────────────────────────────────────────────────┤
│  - Subscribes to 'response' events            │
│  - Wires interceptor → analyzer               │
│  - Aggregates vulnerabilities                  │
│  - Provides analysis stats                     │
└────────────────────────────────────────────────┘
           │
           │ Uses (injected)
           ⬇️
┌────────────────────────────────────────────────┐
│          ResponseAnalyzer                      │
│  (Injected Dependency - Follows DIP)          │
├────────────────────────────────────────────────┤
│  - Analyzes responses                          │
│  - Detects SQL errors                          │
│  - Detects XSS reflections                     │
│  - Detects sensitive data                      │
└────────────────────────────────────────────────┘
```

---

## Component Interaction Flow

### Active Scanning
```
User
  │
  ⬇️ scan(targetUrl)
ActiveScanner (Orchestrator)
  │
  ├──⬇️ enqueue(url)
  │   CrawlManager
  │
  ├──⬇️ dequeue()
  │   CrawlManager
  │
  └──⬇️ processPage(url)
      ExecutionWorker
        │
        ├──⬇️ discoverSurfaces()
        │   DomExplorer
        │
        ├──⬇️ detect(surface)
        │   Detector[]
        │
        ├──⬇️ verify(result)
        │   VerificationEngine
        │
        └──⬆️ return { vulnerabilities, discoveredUrls }
      
      ⬆️ vulnerabilities
  ActiveScanner
  │
  ⬆️ ScanResult
User
```

### Passive Scanning
```
User
  │
  ⬇️ scan(targetUrl)
PassiveScanner
  │
  ├──⬇️ attach(page)
  │   NetworkInterceptor
  │
  ├──⬇️ new PassiveScanOrchestrator(interceptor, analyzer)
  │   PassiveScanOrchestrator
  │     │
  │     ├──⬇️ on('response', handler)
  │     │   NetworkInterceptor
  │     │
  │     └──⬇️ analyze(response)
  │         ResponseAnalyzer
  │
  ├──⬇️ navigate(url)
  │   Page
  │
  └──⬇️ getDetectedVulnerabilities()
      PassiveScanOrchestrator
      │
      ⬆️ vulnerabilities
  PassiveScanner
  │
  ⬆️ ScanResult
User
```

---

## Dependency Graph

### Before (Tight Coupling)
```
ActiveScanner ──depends on──┐
                            ├─→ DomExplorer
                            ├─→ Detectors[]
                            ├─→ VerificationEngine
                            ├─→ PayloadInjector
                            ├─→ TimeoutManager
                            └─→ SPAWaitStrategy

NetworkInterceptor ──depends on──┐
                                  └─→ ResponseAnalyzer ❌
                                      (Tight coupling - bad)
```

### After (Loose Coupling)
```
ActiveScanner ──depends on──┐
                            ├─→ CrawlManager
                            └─→ ExecutionWorker
                                  │
                                  └─→ DomExplorer
                                  └─→ Detectors[]
                                  └─→ VerificationEngine

NetworkInterceptor ──emits events──┐
                                    │
PassiveScanOrchestrator ──listens──┘
                        │
                        └──depends on──→ ResponseAnalyzer ✅
                                         (Injected - good)
```

---

## Metrics Comparison

### Before
| Metric | ActiveScanner | NetworkInterceptor |
|--------|--------------|-------------------|
| Lines of Code | ~800 | ~443 |
| Responsibilities | 10+ | 5+ |
| Dependencies | 8+ | 3+ |
| Testability | Low | Medium |
| Maintainability | Low | Low |

### After
| Component | Lines | Responsibilities | Dependencies | Testability |
|-----------|-------|-----------------|-------------|-------------|
| ActiveScanner | ~350 | 4 | 2 | High |
| CrawlManager | ~150 | 1 | 0 | Very High |
| ExecutionWorker | ~200 | 1 | 5 | High |
| NetworkInterceptor | ~368 | 1 | 0 | Very High |
| PassiveScanOrchestrator | ~180 | 1 | 2 | High |

**Total Reduction:** ~800 → ~1248 lines (distributed across focused modules)
**Complexity Reduction:** Easier to maintain despite more files

---

## SOLID Principles Applied

### ✅ Single Responsibility Principle (SRP)
- **CrawlManager:** Only manages crawl state
- **ExecutionWorker:** Only processes pages
- **ActiveScanner:** Only orchestrates workflow
- **NetworkInterceptor:** Only intercepts traffic
- **PassiveScanOrchestrator:** Only wires events

### ✅ Open/Closed Principle (OCP)
- Can extend with new analysis strategies without modifying interceptor
- Can add new worker types without changing orchestrator

### ✅ Liskov Substitution Principle (LSP)
- ResponseAnalyzer can be swapped with any analyzer implementing the interface
- Workers can be replaced with specialized workers

### ✅ Interface Segregation Principle (ISP)
- Components only expose methods they need
- No fat interfaces with unused methods

### ✅ Dependency Inversion Principle (DIP)
- NetworkInterceptor doesn't instantiate ResponseAnalyzer
- Dependencies are injected via constructor
- High-level modules don't depend on low-level modules
