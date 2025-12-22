# ElementScanner

Targeted scanner that uses explicit Playwright locators to test known elements when automatic DOM discovery is unreliable. It complements the config-driven crawl performed by `ActiveScanner`, but operates on user-specified elements, allowing precise, expert-style testing on pages like bWAPP.

## When to Use
- You know the exact control to test (e.g., a login field, search box, API param) and want reliable injection.
- Auto-discovery misses elements in complex SPAs or heavily styled forms.
- You want to reproduce a pentester’s focused probe on a single control.

## How It Differs from ActiveScanner
- **ActiveScanner**: auto-discovers attack surfaces (DOM + captured XHR/fetch), crawls within configured limits, then runs detectors.
- **ElementScanner**: skips discovery; converts provided locators into `AttackSurface` objects and feeds them to existing detectors.

## Configuration (ElementScanConfig)
- `baseUrl` (string): application base URL.
- `pageUrl?` (string): page to navigate to before scanning elements.
- `elements` (ElementTarget[]): list of explicit targets.
- `pageTimeout?` (number): navigation/action timeout.
- `delayBetweenElements?` (number): ms delay between element scans.
- `continueOnError?` (boolean): keep scanning after errors.
- `authentication?` (PageAuthConfig): login flow (reused from page scans).
- `preActions?` (PageAction[]): actions before scanning (dismiss banners, etc.).

## ElementTarget
- `locator` (string): Playwright selector (CSS/XPath/role/data-test-id).
- `name` (string): human label for reports.
- `description?` (string): optional notes.
- `type` (AttackSurfaceType): e.g., `FORM_INPUT`, `URL_PARAMETER`, `API_PARAM`, `JSON_BODY`.
- `context` (InjectionContext): e.g., `SQL`, `HTML`, `JAVASCRIPT`, `JSON`, `URL`.
- `testCategories?` ((VulnerabilityCategory|string)[]): limit detectors (matched by detector name substring; falls back to all if none match).
- `value?` (string): default value to start from.
- `metadata?` (Record<string, any>): extra hints (formAction, method, API url, original body/key, etc.).
- `enabled?` (boolean): disable target without removing it.

## Results
- `ElementScanResult`: per-element status (found/success), vuln count, duration, error if any.
- `ElementVulnerabilityScanResult`: aggregated totals, success/fail counts, per-element summary.
- Output mirrors the standard scan result structure (vulnerabilities + severity summary).

## Locator Strategies
- Prefer stable selectors: `data-test-id`, `aria-label`, roles.
- Fallbacks: CSS, XPath for legacy pages, text/role selectors for accessibility-friendly apps.
- Keep locators narrow to avoid hitting multiple elements.

## Attack Surface Types
- `FORM_INPUT`: classic inputs/textarea/select; captures form action/method when available.
- `URL_PARAMETER`: query params to mutate.
- `API_PARAM`: XHR/fetch params; supply `metadata.url` and optional `method`.
- `JSON_BODY`: JSON key injection; supply `metadata.originalBody` and `originalKey`.

## Injection Contexts
- `SQL`, `HTML`, `JAVASCRIPT`, `JSON`, `URL`, `HTML_ATTRIBUTE`, `XML` — set the context that best matches the sink.

## Example (bWAPP SQLi search)
```ts
import { chromium } from 'playwright';
import { ElementScanner } from '../src/scanners/active/ElementScanner';
import { SqlInjectionDetector } from '../src/detectors/active/SqlInjectionDetector';
import { AttackSurfaceType, InjectionContext } from '../src/scanners/active/DomExplorer';
import { ElementScanConfig } from '../src/types/element-scan';

const config: ElementScanConfig = {
  baseUrl: 'http://localhost:8080',
  pageUrl: '/sqli_1.php',
  elements: [
    {
      locator: 'input[name="title"]',
      name: 'Movie Title Search',
      type: AttackSurfaceType.FORM_INPUT,
      context: InjectionContext.SQL,
      testCategories: ['sqli'],
      metadata: { formAction: '/sqli_1.php', formMethod: 'GET' },
    },
  ],
  authentication: {
    loginUrl: '/login.php',
    loginActions: [
      { type: 'fill', selector: 'input[name="login"]', value: 'bee' },
      { type: 'fill', selector: 'input[name="password"]', value: 'bug' },
      { type: 'select', selector: 'select[name="security_level"]', value: '0' },
      { type: 'click', selector: 'button[name="form"]' },
    ],
    successIndicator: { type: 'url', value: 'portal.php' },
  },
};

(async () => {
  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext();
  const page = await context.newPage();
  const scanner = new ElementScanner(config);
  scanner.registerDetector(new SqlInjectionDetector());
  await scanner.initialize({ page, browserContext: context, config: {} as any, logger: console as any });
  await scanner.execute();
  await scanner.cleanup();
  await browser.close();
})();
```

## Best Practices
- Use stable locators; avoid brittle nth-child selectors.
- Set the right `context` to guide payload choice in detectors.
- Provide `metadata.url/method` for API/JSON targets.
- Enable `continueOnError` when scanning many elements.
- Keep authentication and pre-actions minimal but reliable.

## Troubleshooting
- **Element not found**: confirm locator, ensure `pageUrl` navigation, add preActions/waits if needed.
- **No vulnerabilities detected**: verify the target actually sinks input; try different contexts/payloads or run a broader active scan on the same page as a baseline.
- **Stateful pages**: set `pageTimeout` and consider reloading between elements via preActions if state leaks.
