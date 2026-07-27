import { IPassiveDetector } from '../core/interfaces/IPassiveDetector';
import { BaseScanner } from '../core/interfaces/IScanner';
import { InterceptedRequest, InterceptedResponse } from '../scanners/passive/NetworkInterceptor';
import { ScanConfiguration } from '../types/config';
import { HttpMethod, ScanStatus, VulnerabilitySeverity } from '../types/enums';
import { ScanResult, VulnerabilitySummary } from '../types/scan-result';
import { Vulnerability } from '../types/vulnerability';

/**
 * Executes one deliberate JSON POST and runs the passive detector set over the
 * request/response pair. It is intentionally not a payload fuzzer; active
 * testing remains the responsibility of targeted_scan.
 */
export class JsonEndpointProbeScanner extends BaseScanner {
  public readonly id = 'mcp-json-endpoint-probe';
  public readonly name = 'MCP JSON Endpoint Probe Scanner';
  public readonly version = '1.0.0';
  public readonly type = 'passive' as const;
  public readonly description =
    'Posts a supplied JSON object once and passively analyzes the response';

  private readonly body: Record<string, unknown>;
  private readonly requestHeaders: Record<string, string>;
  private readonly detectors: IPassiveDetector[] = [];

  constructor(body: Record<string, unknown>, requestHeaders: Record<string, string> = {}) {
    super();
    this.body = body;
    this.requestHeaders = requestHeaders;
  }

  public registerDetectors(detectors: IPassiveDetector[]): void {
    this.detectors.push(...detectors);
  }

  public override isEnabled(config: ScanConfiguration): boolean {
    return config.scanners.passive.enabled;
  }

  public async execute(): Promise<ScanResult> {
    const context = this.getContext();
    const { config, page } = context;
    const startTime = Date.now();
    const targetUrl = config.target.url;
    const requestHeaders = {
      ...this.requestHeaders,
      'Content-Type':
        this.requestHeaders['Content-Type'] ??
        this.requestHeaders['content-type'] ??
        'application/json',
    };

    const response = await page.request.fetch(targetUrl, {
      method: HttpMethod.POST,
      data: this.body,
      headers: requestHeaders,
      timeout: config.browser.timeout ?? 30_000,
    });

    const responseBody = await response.text();
    const request: InterceptedRequest = {
      id: `mcp-probe-request-${startTime}`,
      url: targetUrl,
      method: HttpMethod.POST,
      headers: requestHeaders,
      postData: JSON.stringify(this.body),
      resourceType: 'fetch',
      timestamp: startTime,
    };
    const interceptedResponse: InterceptedResponse = {
      id: `mcp-probe-response-${Date.now()}`,
      requestId: request.id,
      url: response.url(),
      status: response.status(),
      statusText: response.statusText(),
      headers: response.headers(),
      body: responseBody,
      contentType: response.headers()['content-type'] ?? null,
      timing: Date.now() - startTime,
      timestamp: Date.now(),
    };

    const vulnerabilities: Vulnerability[] = [];
    for (const detector of this.detectors) {
      const detected = await detector.detect({
        page,
        requests: [request],
        responses: [interceptedResponse],
      });
      vulnerabilities.push(...detected);
      detected.forEach((vulnerability) => context.emitVulnerability?.(vulnerability));
    }

    const endTime = Date.now();
    return {
      scanId: `mcp-json-probe-${startTime}`,
      targetUrl,
      status: ScanStatus.COMPLETED,
      startTime,
      endTime,
      duration: endTime - startTime,
      vulnerabilities,
      summary: this.summarize(vulnerabilities),
      config,
    };
  }

  private summarize(vulnerabilities: Vulnerability[]): VulnerabilitySummary {
    return {
      total: vulnerabilities.length,
      critical: vulnerabilities.filter(
        (vulnerability) => vulnerability.severity === VulnerabilitySeverity.CRITICAL
      ).length,
      high: vulnerabilities.filter(
        (vulnerability) => vulnerability.severity === VulnerabilitySeverity.HIGH
      ).length,
      medium: vulnerabilities.filter(
        (vulnerability) => vulnerability.severity === VulnerabilitySeverity.MEDIUM
      ).length,
      low: vulnerabilities.filter(
        (vulnerability) => vulnerability.severity === VulnerabilitySeverity.LOW
      ).length,
      info: vulnerabilities.filter(
        (vulnerability) => vulnerability.severity === VulnerabilitySeverity.INFO
      ).length,
    };
  }
}
