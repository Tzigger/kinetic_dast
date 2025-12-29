# Element Scanner

**ElementScanner** is a targeted scanner introduced in Kinetic v0.2.0. Unlike the `ActiveScanner`, which relies on a crawler to discover inputs, the `ElementScanner` operates on a predefined list of Playwright locators.

This is ideal for:
*   **Integration Tests**: Verifying security of a specific component in isolation.
*   **Complex UIs**: Scanning elements that the crawler cannot reach (e.g., inside Shadow DOM, complex SPAs).
*   **Regression**: Re-testing a specific known vulnerability without re-scanning the whole application.

## 🚀 Basic Usage

```typescript
import { chromium } from 'playwright';
import { ElementScanner } from '@tzigger/kinetic/scanners/active/ElementScanner';
import { SqlInjectionDetector } from '@tzigger/kinetic/detectors/active/SqlInjectionDetector';
import { AttackSurfaceType, InjectionContext } from '@tzigger/kinetic/scanners/active/DomExplorer';

// 1. Define Configuration
const config = {
  baseUrl: 'http://localhost:3000',
  pageUrl: '/login', // Optional navigation
  elements: [
    {
      name: 'Username Field',
      locator: 'input[name="user"]',
      type: AttackSurfaceType.FORM_INPUT,
      context: InjectionContext.SQL,
      testCategories: ['sqli']
    }
  ]
};

// 2. Setup Browser
const browser = await chromium.launch();
const page = await browser.newPage();

// 3. Initialize & Run
const scanner = new ElementScanner(config);
scanner.registerDetector(new SqlInjectionDetector());

await scanner.initialize({ page, ...mockContext }); // Requires ScanContext
const result = await scanner.execute();

console.log(result.vulnerabilities);
```

## ⚙️ Configuration Interface

### `ElementScanConfig`

```typescript
interface ElementScanConfig {
  /** Base application URL */
  baseUrl: string;
  
  /** List of elements to test */
  elements: ElementTarget[];
  
  /** Optional: Navigate to this path before scanning */
  pageUrl?: string;
  
  /** Global timeout for operations (ms) */
  pageTimeout?: number;
  
  /** Delay between scanning elements (ms) */
  delayBetweenElements?: number;
  
  /** Authentication configuration (Auto-login) */
  authentication?: PageAuthConfig;
  
  /** Actions to perform before scanning (e.g., dismiss modal) */
  preActions?: PageAction[];
}
```

### `ElementTarget`

Defines exactly what to scan and how.

```typescript
interface ElementTarget {
  /** Playwright locator (CSS, XPath, id, etc.) */
  locator: string;
  
  /** Human-readable name for reports */
  name: string;
  
  /** Type of input */
  type: AttackSurfaceType; // FORM_INPUT, URL_PARAMETER, API_PARAM, JSON_BODY
  
  /** Injection Context (Helps detectors choose payloads) */
  context: InjectionContext; // SQL, HTML, JAVASCRIPT, JSON, URL, COMMAND
  
  /** Optional: Limit to specific detectors (matches detector names/categories) */
  testCategories?: string[]; // e.g. ['xss', 'sql']
  
  /** Optional: Default value */
  value?: string;
  
  /** Extra metadata for API targets (method, action, etc.) */
  metadata?: Record<string, any>;
}
```

## 🎯 Target Types & Contexts

### `AttackSurfaceType`
*   `FORM_INPUT`: Standard HTML `<input>`, `<textarea>`, `<select>`.
*   `URL_PARAMETER`: Query string parameters.
*   `JSON_BODY`: JSON keys in API payloads.
*   `API_PARAM`: API query parameters.

### `InjectionContext`
This hint tells the `PayloadInjector` which payloads are most effective.
*   `SQL`: Login forms, search bars, IDs.
*   `HTML`: Comments, bio fields, inputs reflected in DOM.
*   `JAVASCRIPT`: Inputs reflected inside `<script>` blocks.
*   `COMMAND`: Inputs passed to shell commands (e.g., DNS lookup tools).

## 💡 Examples

### 1. Testing a Login Form for SQL Injection

```typescript
const targets = [
  {
    name: 'Login Username',
    locator: '#username',
    type: AttackSurfaceType.FORM_INPUT,
    context: InjectionContext.SQL,
    testCategories: ['sqli']
  },
  {
    name: 'Login Password',
    locator: '#password',
    type: AttackSurfaceType.FORM_INPUT,
    context: InjectionContext.SQL,
    testCategories: ['sqli']
  }
];
```

### 2. Testing a Search Bar for XSS

```typescript
const targets = [
  {
    name: 'Search Input',
    locator: '[data-testid="search-bar"]',
    type: AttackSurfaceType.FORM_INPUT,
    context: InjectionContext.HTML,
    testCategories: ['xss']
  }
];
```

### 3. Testing with Authentication

```typescript
const config: ElementScanConfig = {
  baseUrl: 'http://localhost:3000',
  pageUrl: '/dashboard',
  authentication: {
    loginUrl: '/login',
    loginActions: [
      { type: 'fill', selector: '#user', value: 'admin' },
      { type: 'fill', selector: '#pass', value: 'secret' },
      { type: 'click', selector: '#submit' }
    ],
    successIndicator: { type: 'url', value: '/dashboard' }
  },
  elements: [ /* ... protected elements ... */ ]
};
```

## 📊 Results

The `execute()` method returns a standard `ScanResult`, but you can also access specific element statistics via `getElementResults()`:

```typescript
const detailedResults = scanner.getElementResults();

console.log(detailedResults.summary);
// [
//   { 
//     elementName: "Search Input", 
//     status: "success", 
//     vulnerabilities: 1 
//   }
// ]
```
