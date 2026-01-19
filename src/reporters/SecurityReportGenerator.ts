/**
 * Security Report Generator
 *
 * Generates comprehensive security reports with OWASP 2025 mapping,
 * test context, and rich evidence from vulnerability findings.
 */

import * as fs from 'fs';
import * as path from 'path';

import { v4 as uuidv4 } from 'uuid';

import {
  SecurityReport,
  SecurityFinding,
  ReportSummary,
  OWASPInfo,
  TestContext,
  FindingEvidence,
} from '../types/SecurityReport';
import { VulnerabilitySeverity } from '../types/enums';
import { Vulnerability } from '../types/vulnerability';
import {
  getOWASP2025Category,
  OWASP2025Category,
  OWASP2025Stats,
} from '../utils/cwe/owasp-2025-mapping';

/**
 * OWASP 2025 category names for display
 */
const OWASP_CATEGORY_NAMES: Record<OWASP2025Category, string> = {
  [OWASP2025Category.A01_BROKEN_ACCESS_CONTROL]: 'Broken Access Control',
  [OWASP2025Category.A02_SECURITY_MISCONFIGURATION]: 'Security Misconfiguration',
  [OWASP2025Category.A03_SOFTWARE_SUPPLY_CHAIN]: 'Software Supply Chain',
  [OWASP2025Category.A04_CRYPTOGRAPHIC_FAILURES]: 'Cryptographic Failures',
  [OWASP2025Category.A05_INJECTION]: 'Injection',
  [OWASP2025Category.A06_INSECURE_DESIGN]: 'Insecure Design',
  [OWASP2025Category.A07_AUTHENTICATION_FAILURES]: 'Authentication Failures',
  [OWASP2025Category.A08_SOFTWARE_DATA_INTEGRITY]: 'Software and Data Integrity Failures',
  [OWASP2025Category.A09_LOGGING_ALERTING_FAILURES]: 'Logging & Alerting Failures',
  [OWASP2025Category.A10_MISHANDLING_EXCEPTIONAL_CONDITIONS]:
    'Mishandling of Exceptional Conditions',
};

/**
 * Options for the SecurityReportGenerator
 */
export interface SecurityReportGeneratorOptions {
  /** Report title */
  title?: string;
  /** Target description */
  target?: string;
  /** Framework version */
  version?: string;
  /** Include full response bodies (may be large) */
  includeFullResponses?: boolean;
  /** Max response snippet length */
  maxSnippetLength?: number;
}

/**
 * Generates security reports with OWASP 2025 mapping and rich evidence
 */
export class SecurityReportGenerator {
  private findings: SecurityFinding[] = [];
  private startTime: Date;
  private options: Required<SecurityReportGeneratorOptions>;
  private testFiles: Set<string> = new Set();
  private scanners: Set<string> = new Set();

  constructor(options: SecurityReportGeneratorOptions = {}) {
    this.startTime = new Date();
    this.options = {
      title: options.title || 'Security Scan Report',
      target: options.target || 'Unknown Target',
      version: options.version || '0.2.0',
      includeFullResponses: options.includeFullResponses ?? false,
      maxSnippetLength: options.maxSnippetLength ?? 500,
    };
  }

  /**
   * Add a vulnerability finding with test context
   */
  addFinding(
    vulnerability: Vulnerability,
    testContext: Partial<TestContext> = {}
  ): SecurityFinding {
    const finding = this.convertToSecurityFinding(vulnerability, testContext);
    this.findings.push(finding);

    // Track metadata
    if (testContext.testFile) {
      this.testFiles.add(testContext.testFile);
    }
    if (testContext.scanner) {
      this.scanners.add(testContext.scanner);
    }

    return finding;
  }

  /**
   * Add multiple vulnerabilities from a scan result
   */
  addFindings(
    vulnerabilities: Vulnerability[],
    testContext: Partial<TestContext> = {}
  ): SecurityFinding[] {
    return vulnerabilities.map((vuln) => this.addFinding(vuln, testContext));
  }

  /**
   * Convert a Vulnerability to a SecurityFinding with OWASP enrichment
   */
  private convertToSecurityFinding(
    vuln: Vulnerability,
    testContext: Partial<TestContext>
  ): SecurityFinding {
    // Get OWASP 2025 category from CWE
    const owaspInfo = this.getOWASPInfo(vuln.cwe);

    // Extract evidence
    const evidence = this.extractEvidence(vuln);

    return {
      id: vuln.id || uuidv4(),
      title: vuln.title,
      description: vuln.description,
      severity: vuln.severity,
      category: vuln.category,
      cwe: vuln.cwe,
      owasp2025: owaspInfo,
      testContext: {
        testName: testContext.testName || 'Unknown Test',
        testFile: testContext.testFile,
        scanner: testContext.scanner || (vuln.metadata?.scannerId as string),
        detector: testContext.detector || vuln.detectorId,
        detectorVersion: testContext.detectorVersion,
      },
      evidence,
      confidence: vuln.confidence ?? 0.8,
      timestamp: new Date(vuln.timestamp),
      remediation: vuln.remediation,
      references: vuln.references,
      confirmed: vuln.confirmed,
    };
  }

  /**
   * Get OWASP 2025 category info from a CWE
   */
  private getOWASPInfo(cwe?: string): OWASPInfo | undefined {
    if (!cwe) return undefined;

    const category = getOWASP2025Category(cwe);
    if (!category) return undefined;

    const stats = OWASP2025Stats[category];
    const name = OWASP_CATEGORY_NAMES[category];

    return {
      category,
      name,
      rank: stats?.rank ?? 0,
      prevalence: stats?.prevalence,
      description: stats?.description,
    };
  }

  /**
   * Extract structured evidence from a vulnerability
   */
  private extractEvidence(vuln: Vulnerability): FindingEvidence {
    const evidence = vuln.evidence || {};
    const metadata = vuln.metadata || {};

    // Extract payload from various possible locations
    const payload =
      (evidence as any)?.payload ||
      (evidence as any)?.payloadUsed ||
      (evidence as any)?.request?.body ||
      (metadata as any)?.payload;

    // Extract response snippet
    let responseSnippet = (evidence as any)?.response?.snippet;
    if (!responseSnippet && (evidence as any)?.response?.body) {
      const body = (evidence as any).response.body;
      responseSnippet =
        typeof body === 'string' ? body.substring(0, this.options.maxSnippetLength) : undefined;
    }

    return {
      url: vuln.url || (evidence as any)?.request?.url || '',
      payload: typeof payload === 'string' ? payload : JSON.stringify(payload),
      request: (evidence as any)?.request
        ? {
            method: (evidence as any).request.method || 'GET',
            url: (evidence as any).request.url || vuln.url || '',
            headers: (evidence as any).request.headers,
            body: (evidence as any).request.body,
          }
        : undefined,
      response: (evidence as any)?.response
        ? {
            status: (evidence as any).response.status || 0,
            headers: (evidence as any).response.headers,
            snippet: responseSnippet,
            bodyLength: (evidence as any).response.body?.length,
          }
        : undefined,
      attackSurface: (evidence as any)?.metadata?.surfaceName
        ? {
            type: (evidence as any).metadata?.contextInfo?.surfaceType || 'unknown',
            name: (evidence as any).metadata?.surfaceName,
            selector: (evidence as any).metadata?.selector,
          }
        : undefined,
      context: {
        confidence: vuln.confidence,
        detectorId: vuln.detectorId,
        ...((evidence as any)?.metadata || {}),
      },
    };
  }

  /**
   * Generate the summary statistics
   */
  private generateSummary(): ReportSummary {
    const bySeverity: Record<string, number> = {};
    const byOWASP: Record<string, number> = {};
    const byCWE: Record<string, number> = {};
    let highestSeverity: VulnerabilitySeverity | undefined;
    let totalConfidence = 0;
    let confirmedCount = 0;
    let potentialCount = 0;

    const severityOrder = [
      VulnerabilitySeverity.CRITICAL,
      VulnerabilitySeverity.HIGH,
      VulnerabilitySeverity.MEDIUM,
      VulnerabilitySeverity.LOW,
      VulnerabilitySeverity.INFO,
    ];

    for (const finding of this.findings) {
      // Count by severity
      bySeverity[finding.severity] = (bySeverity[finding.severity] || 0) + 1;

      // Track highest severity
      if (
        !highestSeverity ||
        severityOrder.indexOf(finding.severity) < severityOrder.indexOf(highestSeverity)
      ) {
        highestSeverity = finding.severity;
      }

      // Count by OWASP category
      if (finding.owasp2025) {
        const key = `${finding.owasp2025.category} - ${finding.owasp2025.name}`;
        byOWASP[key] = (byOWASP[key] || 0) + 1;
      }

      // Count by CWE
      if (finding.cwe) {
        byCWE[finding.cwe] = (byCWE[finding.cwe] || 0) + 1;
      }

      // Track confidence
      totalConfidence += finding.confidence;

      // Track confirmed vs potential
      if (finding.confirmed) {
        confirmedCount++;
      } else {
        potentialCount++;
      }
    }

    return {
      total: this.findings.length,
      bySeverity,
      byOWASP,
      byCWE,
      highestSeverity,
      averageConfidence: this.findings.length > 0 ? totalConfidence / this.findings.length : 0,
      confirmedCount,
      potentialCount,
    };
  }

  /**
   * Generate the complete security report
   */
  generateReport(): SecurityReport {
    const endTime = new Date();

    return {
      reportId: uuidv4(),
      title: this.options.title,
      target: this.options.target,
      generatedAt: endTime,
      duration: endTime.getTime() - this.startTime.getTime(),
      summary: this.generateSummary(),
      findings: this.findings,
      metadata: {
        version: this.options.version,
        scanners: Array.from(this.scanners),
        testFiles: Array.from(this.testFiles),
      },
    };
  }

  /**
   * Export report as JSON
   */
  toJSON(): string {
    return JSON.stringify(this.generateReport(), null, 2);
  }

  /**
   * Save JSON report to file
   */
  async saveJSON(outputPath: string): Promise<string> {
    await fs.promises.mkdir(path.dirname(outputPath), { recursive: true });
    await fs.promises.writeFile(outputPath, this.toJSON(), 'utf-8');
    return outputPath;
  }

  /**
   * Generate HTML report
   */
  toHTML(): string {
    const report = this.generateReport();
    return this.generateHTMLTemplate(report);
  }

  /**
   * Save HTML report to file
   */
  async saveHTML(outputPath: string): Promise<string> {
    await fs.promises.mkdir(path.dirname(outputPath), { recursive: true });
    await fs.promises.writeFile(outputPath, this.toHTML(), 'utf-8');
    return outputPath;
  }

  /**
   * Save both JSON and HTML reports
   */
  async saveReports(
    outputDir: string,
    baseName: string = 'security-report'
  ): Promise<{ json: string; html: string }> {
    const jsonPath = path.join(outputDir, `${baseName}.json`);
    const htmlPath = path.join(outputDir, `${baseName}.html`);

    await Promise.all([this.saveJSON(jsonPath), this.saveHTML(htmlPath)]);

    return { json: jsonPath, html: htmlPath };
  }

  /**
   * Generate HTML template for the report
   */
  private generateHTMLTemplate(report: SecurityReport): string {
    const severityColors: Record<string, string> = {
      critical: '#991b1b',
      high: '#dc2626',
      medium: '#d97706',
      low: '#2563eb',
      info: '#64748b',
    };

    const severityBadge = (severity: string) => {
      const color = severityColors[severity.toLowerCase()] || '#64748b';
      return `<span class="sev" style="background:${color}">${severity.toUpperCase()}</span>`;
    };

    const formatDate = (d: Date) => new Date(d).toISOString();

    const findingsHTML = report.findings
      .map(
        (f, i) => `
      <tr>
        <td>${i + 1}</td>
        <td>${severityBadge(f.severity)}</td>
        <td>
          <strong>${this.escapeHtml(f.title)}</strong><br/>
          <small>${this.escapeHtml(f.description.substring(0, 150))}${f.description.length > 150 ? '...' : ''}</small>
        </td>
        <td>
          ${f.cwe ? `<code>${f.cwe}</code>` : '-'}<br/>
          ${f.owasp2025 ? `<small class="owasp">${f.owasp2025.category}</small>` : ''}
        </td>
        <td>${(f.confidence * 100).toFixed(0)}%</td>
        <td><small>${this.escapeHtml(f.testContext.testName)}</small></td>
        <td>
          <details>
            <summary>View Evidence</summary>
            <div class="evidence-box">
              ${f.evidence.url ? `<div class="kv"><b>URL:</b> <code>${this.escapeHtml(f.evidence.url)}</code></div>` : ''}
              ${f.evidence.payload ? `<div class="kv"><b>Payload:</b> <code class="payload">${this.escapeHtml(f.evidence.payload)}</code></div>` : ''}
              ${f.evidence.attackSurface ? `<div class="kv"><b>Attack Surface:</b> ${f.evidence.attackSurface.type} - ${this.escapeHtml(f.evidence.attackSurface.name || '')}</div>` : ''}
              ${f.evidence.response?.status ? `<div class="kv"><b>Response:</b> ${f.evidence.response.status}</div>` : ''}
              ${f.evidence.response?.snippet ? `<div class="kv"><b>Response Snippet:</b></div><pre class="snippet">${this.escapeHtml(f.evidence.response.snippet)}</pre>` : ''}
              ${f.testContext.scanner ? `<div class="kv"><b>Scanner:</b> ${f.testContext.scanner}</div>` : ''}
              ${f.testContext.detector ? `<div class="kv"><b>Detector:</b> ${f.testContext.detector}</div>` : ''}
            </div>
          </details>
        </td>
      </tr>
    `
      )
      .join('\n');

    const owaspBreakdown = Object.entries(report.summary.byOWASP)
      .sort((a, b) => b[1] - a[1])
      .map(
        ([cat, count]) =>
          `<div class="owasp-item"><span class="owasp-cat">${cat}</span> <span class="owasp-count">${count}</span></div>`
      )
      .join('\n');

    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${this.escapeHtml(report.title)}</title>
  <style>
    * { box-sizing: border-box; }
    body { font-family: system-ui, -apple-system, sans-serif; margin: 0; padding: 24px; background: #f8fafc; color: #0f172a; }
    .container { max-width: 1400px; margin: 0 auto; }
    h1 { margin: 0 0 8px 0; font-size: 28px; }
    .meta { color: #64748b; margin-bottom: 24px; }
    .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin-bottom: 24px; }
    .card { background: white; border-radius: 8px; padding: 16px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
    .card-title { font-size: 12px; color: #64748b; text-transform: uppercase; margin-bottom: 8px; }
    .card-value { font-size: 32px; font-weight: 700; }
    .sev { display: inline-block; padding: 2px 8px; border-radius: 4px; color: white; font-size: 11px; font-weight: 600; text-transform: uppercase; }
    .severity-breakdown { display: flex; gap: 8px; flex-wrap: wrap; margin-top: 8px; }
    .severity-item { display: flex; align-items: center; gap: 4px; font-size: 13px; }
    .owasp-section { margin-bottom: 24px; }
    .owasp-item { display: flex; justify-content: space-between; padding: 8px 0; border-bottom: 1px solid #e2e8f0; }
    .owasp-cat { font-size: 14px; }
    .owasp-count { font-weight: 600; }
    table { width: 100%; border-collapse: collapse; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
    th { background: #f1f5f9; text-align: left; padding: 12px; font-size: 12px; text-transform: uppercase; color: #475569; }
    td { padding: 12px; border-top: 1px solid #e2e8f0; vertical-align: top; }
    tr:hover { background: #f8fafc; }
    .owasp { background: #dbeafe; color: #1e40af; padding: 2px 6px; border-radius: 4px; font-size: 11px; }
    details summary { cursor: pointer; color: #2563eb; font-size: 13px; }
    .evidence-box { background: #f1f5f9; border-radius: 6px; padding: 12px; margin-top: 8px; font-size: 13px; }
    .kv { margin: 6px 0; }
    .kv b { color: #475569; }
    code { background: #e2e8f0; padding: 2px 4px; border-radius: 3px; font-family: SFMono-Regular, Menlo, Consolas, monospace; font-size: 12px; }
    .payload { word-break: break-all; }
    .snippet { background: #0f172a; color: #e2e8f0; padding: 12px; border-radius: 6px; overflow-x: auto; font-size: 12px; max-height: 200px; }
    small { color: #64748b; }
    .footer { margin-top: 24px; text-align: center; font-size: 12px; color: #94a3b8; }
  </style>
</head>
<body>
  <div class="container">
    <h1>🛡️ ${this.escapeHtml(report.title)}</h1>
    <div class="meta">
      <strong>Target:</strong> ${this.escapeHtml(report.target)} | 
      <strong>Generated:</strong> ${formatDate(report.generatedAt)} |
      <strong>Duration:</strong> ${report.duration ? Math.round(report.duration / 1000) + 's' : 'N/A'}
    </div>

    <div class="summary">
      <div class="card">
        <div class="card-title">Total Findings</div>
        <div class="card-value">${report.summary.total}</div>
      </div>
      <div class="card">
        <div class="card-title">Highest Severity</div>
        <div class="card-value">${report.summary.highestSeverity ? severityBadge(report.summary.highestSeverity) : 'None'}</div>
      </div>
      <div class="card">
        <div class="card-title">Avg Confidence</div>
        <div class="card-value">${(report.summary.averageConfidence * 100).toFixed(0)}%</div>
      </div>
      <div class="card">
        <div class="card-title">Confirmed / Potential</div>
        <div class="card-value">${report.summary.confirmedCount} / ${report.summary.potentialCount}</div>
      </div>
    </div>

    <div class="card severity-breakdown-card" style="margin-bottom: 24px;">
      <div class="card-title">By Severity</div>
      <div class="severity-breakdown">
        ${Object.entries(report.summary.bySeverity)
          .map(
            ([sev, count]) =>
              `<div class="severity-item">${severityBadge(sev)} <span>${count}</span></div>`
          )
          .join('')}
      </div>
    </div>

    ${
      Object.keys(report.summary.byOWASP).length > 0
        ? `
    <div class="card owasp-section">
      <div class="card-title">OWASP Top 10 2025 Breakdown</div>
      ${owaspBreakdown}
    </div>
    `
        : ''
    }

    <h2>Findings</h2>
    <table>
      <thead>
        <tr>
          <th>#</th>
          <th>Severity</th>
          <th>Finding</th>
          <th>CWE / OWASP</th>
          <th>Confidence</th>
          <th>Test</th>
          <th>Evidence</th>
        </tr>
      </thead>
      <tbody>
        ${findingsHTML || '<tr><td colspan="7" style="text-align:center;padding:24px;">No vulnerabilities found! 🎉</td></tr>'}
      </tbody>
    </table>

    <div class="footer">
      Generated by Kinetic Security Scanner v${report.metadata?.version || '0.2.0'}
    </div>
  </div>
</body>
</html>`;
  }

  /**
   * Escape HTML special characters
   */
  private escapeHtml(text: string): string {
    return text
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  /**
   * Get current findings count
   */
  get count(): number {
    return this.findings.length;
  }

  /**
   * Clear all findings
   */
  clear(): void {
    this.findings = [];
    this.testFiles.clear();
    this.scanners.clear();
    this.startTime = new Date();
  }
}

/**
 * Global singleton instance for test integration
 */
let globalReporter: SecurityReportGenerator | null = null;

/**
 * Get or create the global security report generator
 */
export function getSecurityReporter(
  options?: SecurityReportGeneratorOptions
): SecurityReportGenerator {
  if (!globalReporter) {
    globalReporter = new SecurityReportGenerator(options);
  }
  return globalReporter;
}

/**
 * Reset the global reporter (for test cleanup)
 */
export function resetSecurityReporter(): void {
  globalReporter = null;
}
