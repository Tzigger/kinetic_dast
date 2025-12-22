import { chromium } from '@playwright/test';
import fs from 'fs/promises';
import path from 'path';

import { ensureBwappAuthState } from '../global-setup';
import { ElementScanner } from '../src/scanners/active/ElementScanner';
import { SqlInjectionDetector } from '../src/detectors/active/SqlInjectionDetector';
import { XssDetector } from '../src/detectors/active/XssDetector';
import { InjectionDetector } from '../src/detectors/active/InjectionDetector';
import { LogLevel } from '../src/types/enums';
import { Logger } from '../src/utils/logger/Logger';
import { ElementScanConfig } from '../src/types/element-scan';
import { AttackSurfaceType, InjectionContext } from '../src/scanners/active/DomExplorer';
import { Vulnerability } from '../src/types/vulnerability';
import { IActiveDetector } from '../src/core/interfaces/IActiveDetector';

type Expectation = 'positive' | 'negative';

type MetricsCase = {
  id: string;
  detector: 'sqli' | 'xss' | 'cmdi';
  pageUrl: string;
  locator: string;
  injectionContext: InjectionContext;
  testCategories: string[];
  metadata: { formAction: string; formMethod: 'get' | 'post' };
  expectation: Expectation;
};

type CaseResult = {
  id: string;
  detector: MetricsCase['detector'];
  expectation: Expectation;
  pageUrl: string;
  locator: string;
  vulnerabilitiesFound: number;
  maxConfidence: number;
  evidenceCompleteCount: number;
  cwes: string[];
  findings?: Array<{
    title: string;
    cwe?: string;
    confidence?: number;
    url?: string;
    requestUrl?: string;
    requestMethod?: string;
    responseUrl?: string;
    responseStatus?: number;
    responseSnippet?: string;
    markerHit?: boolean;
  }>;
};

type MetricsSummary = {
  baseUrl: string;
  executedAt: string;
  totals: {
    cases: number;
    positives: number;
    negatives: number;
    tp: number;
    fp: number;
    fn: number;
    tn: number;
  };
  perDetector: Record<MetricsCase['detector'], {
    cases: number;
    tp: number;
    fp: number;
    fn: number;
    tn: number;
    precision: number | null;
    recall: number | null;
    avgConfidenceTP: number | null;
  }>;
  results: CaseResult[];
};

const DEFAULT_BWAPP_URL = 'http://localhost:8080';
const DEFAULT_STORAGE_STATE = path.join(process.cwd(), 'storage-states', 'bwapp-auth.json');
const OUTPUT_PATH = path.join(process.cwd(), 'test-security-reports', 'bwapp-metrics.json');

function makeLogger(): Logger {
  return new Logger(LogLevel.INFO, 'bwapp-metrics');
}

function mean(values: number[]): number | null {
  if (values.length === 0) return null;
  return values.reduce((sum, v) => sum + v, 0) / values.length;
}

function safeDiv(n: number, d: number): number | null {
  if (d === 0) return null;
  return n / d;
}

function detectorInstance(detector: MetricsCase['detector']): IActiveDetector {
  if (detector === 'sqli') return new SqlInjectionDetector();
  if (detector === 'xss') return new XssDetector();
  return new InjectionDetector(LogLevel.INFO, { permissiveMode: true });
}

function clampSnippet(value: string, maxLen: number): string {
  if (value.length <= maxLen) return value;
  return value.slice(0, maxLen) + '…';
}

function extractSnippet(body: string, needles: string[], windowSize: number = 220): string | undefined {
  for (const needle of needles) {
    const idx = body.indexOf(needle);
    if (idx === -1) continue;
    const start = Math.max(0, idx - windowSize);
    const end = Math.min(body.length, idx + needle.length + windowSize);
    return clampSnippet(body.slice(start, end), 700);
  }
  return undefined;
}

function inferXssMarkerFromUrl(url: string | undefined): string | undefined {
  if (!url) return undefined;
  try {
    const decoded = decodeURIComponent(url);
    const match = decoded.match(/xss-\d+-[0-9a-f]+/i);
    return match?.[0];
  } catch {
    const match = url.match(/xss-\d+-[0-9a-f]+/i);
    return match?.[0];
  }
}

async function runElementScan(args: {
  baseUrl: string;
  storageStatePath: string;
  metricsCase: MetricsCase;
}): Promise<CaseResult> {
  const { baseUrl, storageStatePath, metricsCase } = args;

  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({ storageState: storageStatePath });
  const page = await context.newPage();

  const elementConfig: ElementScanConfig = {
    baseUrl,
    pageUrl: metricsCase.pageUrl,
    elements: [
      {
        locator: metricsCase.locator,
        name: metricsCase.id,
        type: AttackSurfaceType.FORM_INPUT,
        context: metricsCase.injectionContext,
        testCategories: metricsCase.testCategories,
        metadata: metricsCase.metadata,
      },
    ],
    pageTimeout: 20000,
    continueOnError: false,
  };

  const scanner = new ElementScanner(elementConfig);
  scanner.registerDetectors([detectorInstance(metricsCase.detector)]);

  const emitted: Vulnerability[] = [];
  const scanContext = {
    page,
    browserContext: context,
    config: elementConfig,
    logger: makeLogger(),
    emitVulnerability: (v: unknown) => emitted.push(v as Vulnerability),
  } as any;

  await scanner.initialize(scanContext);
  const result = await scanner.execute();
  await scanner.cleanup();

  const combined = result.vulnerabilities.length ? result.vulnerabilities : emitted;

  const confidences = combined.map((v) => v.confidence ?? 0);
  const maxConfidence = confidences.length ? Math.max(...confidences) : 0;

  const evidenceCompleteCount = combined.filter(
    (v) => Boolean(v.evidence?.request) && Boolean(v.evidence?.response)
  ).length;

  const cwes = Array.from(new Set(combined.map((v) => v.cwe).filter((cwe): cwe is string => Boolean(cwe))));

  const findings = combined.slice(0, 3).map((v) => {
    const requestUrl = v.evidence?.request?.url;
    const requestMethod = v.evidence?.request?.method;
    const responseUrl = v.evidence?.url ?? requestUrl;
    const responseStatus = v.evidence?.response?.status;

    const responseBody =
      v.evidence?.response?.body ??
      v.evidence?.responseBody ??
      '';

    const responseTextForSnippets =
      responseBody ||
      v.evidence?.response?.snippet ||
      '';

    const inferredMarker = inferXssMarkerFromUrl(responseUrl);
    const needles = Array.from(
      new Set(
        [
          inferredMarker ? `window.__xss_mark__='${inferredMarker}'` : undefined,
          inferredMarker ? `window.__xss_mark__=\'${inferredMarker}\'` : undefined,
          inferredMarker,
          "window.__xss_mark__=",
          "alert('XSS-STORED')",
          'XSS-STORED',
          '&lt;script&gt;window.__xss_mark__',
        ].filter((v): v is string => Boolean(v))
      )
    );

    const responseSnippet = extractSnippet(responseTextForSnippets, needles);
    const markerHit = inferredMarker ? responseTextForSnippets.includes(inferredMarker) : undefined;

    return {
      title: v.title,
      cwe: v.cwe,
      confidence: v.confidence,
      url: v.url,
      requestUrl,
      requestMethod: requestMethod ? String(requestMethod) : undefined,
      responseUrl,
      responseStatus,
      responseSnippet,
      markerHit,
    };
  });

  await page.close();
  await context.close();
  await browser.close();

  return {
    id: metricsCase.id,
    detector: metricsCase.detector,
    expectation: metricsCase.expectation,
    pageUrl: metricsCase.pageUrl,
    locator: metricsCase.locator,
    vulnerabilitiesFound: combined.length,
    maxConfidence,
    evidenceCompleteCount,
    cwes,
    findings: findings.length ? findings : undefined,
  };
}

function computeSummary(baseUrl: string, results: CaseResult[]): MetricsSummary {
  const positives = results.filter((r) => r.expectation === 'positive');
  const negatives = results.filter((r) => r.expectation === 'negative');

  const tp = positives.filter((r) => r.vulnerabilitiesFound > 0).length;
  const fn = positives.filter((r) => r.vulnerabilitiesFound === 0).length;
  const fp = negatives.filter((r) => r.vulnerabilitiesFound > 0).length;
  const tn = negatives.filter((r) => r.vulnerabilitiesFound === 0).length;

  const detectors: MetricsCase['detector'][] = ['sqli', 'xss', 'cmdi'];
  const perDetector: MetricsSummary['perDetector'] = {
    sqli: {
      cases: 0,
      tp: 0,
      fp: 0,
      fn: 0,
      tn: 0,
      precision: null,
      recall: null,
      avgConfidenceTP: null,
    },
    xss: {
      cases: 0,
      tp: 0,
      fp: 0,
      fn: 0,
      tn: 0,
      precision: null,
      recall: null,
      avgConfidenceTP: null,
    },
    cmdi: {
      cases: 0,
      tp: 0,
      fp: 0,
      fn: 0,
      tn: 0,
      precision: null,
      recall: null,
      avgConfidenceTP: null,
    },
  };

  for (const det of detectors) {
    const detResults = results.filter((r) => r.detector === det);
    const detPos = detResults.filter((r) => r.expectation === 'positive');
    const detNeg = detResults.filter((r) => r.expectation === 'negative');

    const detTP = detPos.filter((r) => r.vulnerabilitiesFound > 0).length;
    const detFN = detPos.filter((r) => r.vulnerabilitiesFound === 0).length;
    const detFP = detNeg.filter((r) => r.vulnerabilitiesFound > 0).length;
    const detTN = detNeg.filter((r) => r.vulnerabilitiesFound === 0).length;

    const tpConfidences = detPos
      .filter((r) => r.vulnerabilitiesFound > 0)
      .map((r) => r.maxConfidence);

    perDetector[det] = {
      cases: detResults.length,
      tp: detTP,
      fp: detFP,
      fn: detFN,
      tn: detTN,
      precision: safeDiv(detTP, detTP + detFP),
      recall: safeDiv(detTP, detTP + detFN),
      avgConfidenceTP: mean(tpConfidences),
    };
  }

  return {
    baseUrl,
    executedAt: new Date().toISOString(),
    totals: {
      cases: results.length,
      positives: positives.length,
      negatives: negatives.length,
      tp,
      fp,
      fn,
      tn,
    },
    perDetector,
    results,
  };
}

async function main(): Promise<void> {
  const baseUrl = process.env['BWAPP_URL'] ?? DEFAULT_BWAPP_URL;
  const storageStatePath = process.env['BWAPP_STORAGE_STATE'] ?? DEFAULT_STORAGE_STATE;

  await ensureBwappAuthState(baseUrl, storageStatePath);

  const cases: MetricsCase[] = [
    // Positive cases (known vulnerable surfaces)
    {
      id: 'POS_sqli_movie_search',
      detector: 'sqli',
      pageUrl: '/sqli_1.php',
      locator: 'input[name="title"]',
      injectionContext: InjectionContext.SQL,
      testCategories: ['sqli'],
      metadata: { formAction: '/sqli_1.php', formMethod: 'get' },
      expectation: 'positive',
    },
    {
      id: 'POS_xss_firstname_reflected',
      detector: 'xss',
      pageUrl: '/xss_get.php',
      locator: 'input[name="firstname"]',
      injectionContext: InjectionContext.HTML,
      testCategories: ['xss'],
      metadata: { formAction: '/xss_get.php', formMethod: 'get' },
      expectation: 'positive',
    },
    {
      id: 'POS_cmdi_target',
      detector: 'cmdi',
      pageUrl: '/commandi.php',
      locator: 'input[name="target"]',
      injectionContext: InjectionContext.COMMAND,
      testCategories: ['injection', 'cmd'],
      metadata: { formAction: '/commandi.php', formMethod: 'post' },
      expectation: 'positive',
    },

    // Negative cases (cross-detector false-positive checks)
    {
      id: 'NEG_sqli_on_xss_surface',
      detector: 'sqli',
      pageUrl: '/xss_get.php',
      locator: 'input[name="firstname"]',
      injectionContext: InjectionContext.SQL,
      testCategories: ['sqli'],
      metadata: { formAction: '/xss_get.php', formMethod: 'get' },
      expectation: 'negative',
    },
    {
      id: 'NEG_xss_on_sqli_surface',
      detector: 'xss',
      pageUrl: '/sqli_1.php',
      locator: 'input[name="title"]',
      injectionContext: InjectionContext.HTML,
      testCategories: ['xss'],
      metadata: { formAction: '/sqli_1.php', formMethod: 'get' },
      expectation: 'negative',
    },
    {
      id: 'NEG_cmdi_on_sqli_surface',
      detector: 'cmdi',
      pageUrl: '/sqli_1.php',
      locator: 'input[name="title"]',
      injectionContext: InjectionContext.COMMAND,
      testCategories: ['injection', 'cmd'],
      metadata: { formAction: '/sqli_1.php', formMethod: 'get' },
      expectation: 'negative',
    },
  ];

  const results: CaseResult[] = [];
  for (const metricsCase of cases) {
    // eslint-disable-next-line no-console
    console.log(`[bwapp-metrics] Running ${metricsCase.id} (${metricsCase.detector}, ${metricsCase.expectation})`);
    results.push(await runElementScan({ baseUrl, storageStatePath, metricsCase }));
  }

  const summary = computeSummary(baseUrl, results);

  await fs.mkdir(path.dirname(OUTPUT_PATH), { recursive: true });
  await fs.writeFile(OUTPUT_PATH, JSON.stringify(summary, null, 2), 'utf-8');

  // eslint-disable-next-line no-console
  console.log(`\n[bwapp-metrics] Wrote report: ${OUTPUT_PATH}`);
  // eslint-disable-next-line no-console
  console.log(`[bwapp-metrics] Totals: TP=${summary.totals.tp}, FP=${summary.totals.fp}, FN=${summary.totals.fn}, TN=${summary.totals.tn}`);
  // eslint-disable-next-line no-console
  console.log(`[bwapp-metrics] Precision=${summary.totals.tp + summary.totals.fp ? (summary.totals.tp / (summary.totals.tp + summary.totals.fp)).toFixed(3) : 'N/A'} | Recall=${summary.totals.tp + summary.totals.fn ? (summary.totals.tp / (summary.totals.tp + summary.totals.fn)).toFixed(3) : 'N/A'}`);
}

main().catch((err: unknown) => {
  // eslint-disable-next-line no-console
  console.error('[bwapp-metrics] Failed:', err);
  process.exitCode = 1;
});
