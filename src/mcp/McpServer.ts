import { ScanEngine } from '../core/engine/ScanEngine';
import { ActiveScanner } from '../scanners/active/ActiveScanner';
import { AttackSurfaceType } from '../scanners/active/DomExplorer';
import { PassiveScanner } from '../scanners/passive/PassiveScanner';
import { ScanConfiguration } from '../types/config';
import {
  AggressivenessLevel,
  BrowserType,
  LogLevel,
  ReportFormat,
  VerbosityLevel,
} from '../types/enums';
import { DetectorRegistry } from '../utils/DetectorRegistry';
import { registerBuiltInDetectors } from '../utils/builtInDetectors';

import { JsonEndpointProbeScanner } from './JsonEndpointProbeScanner';
import { ScopeGuard } from './ScopeGuard';

const MCP_PROTOCOL_VERSION = '2025-06-18';
const SUPPORTED_PROTOCOL_VERSIONS = new Set(['2024-11-05', '2025-03-26', MCP_PROTOCOL_VERSION]);
type McpToolName =
  | 'passive_check'
  | 'targeted_scan'
  | 'probe_json_endpoint'
  | 'scan_changed_routes';
const SENSITIVE_KEY =
  /^(?:authorization|proxy-authorization|cookie|set-cookie|x-api-key|api[-_]?key|password|passwd|secret|token|access[-_]?token|refresh[-_]?token|session(?:id)?|jwt)$/i;
const RAW_CONTENT_KEY = /^(?:body|postdata|post_data|html|content|responsebody|response_body)$/i;
const DEFAULT_ACTIVE_DETECTORS = ['sql-injection', 'xss', 'error-based'] as const;
const AVAILABLE_ACTIVE_DETECTORS = [
  ...DEFAULT_ACTIVE_DETECTORS,
  'path-traversal',
  'ssrf',
  'command-injection',
] as const;
const INJECTABLE_SURFACE_TYPES = [
  AttackSurfaceType.FORM_INPUT,
  AttackSurfaceType.URL_PARAMETER,
  AttackSurfaceType.COOKIE,
  AttackSurfaceType.JSON_BODY,
  AttackSurfaceType.API_PARAM,
] as const;
const PASSIVE_DETECTORS = [
  'sensitive-data',
  'header-security',
  'cookie-security',
  'insecure-transmission',
] as const;

type JsonRpcId = string | number | null;

export interface McpToolDefinition {
  name: McpToolName;
  title: string;
  description: string;
  inputSchema: Record<string, unknown>;
  outputSchema: Record<string, unknown>;
  annotations: Record<string, boolean>;
  safeByDefault: boolean;
}

export interface McpToolCallParams {
  name: string;
  arguments?: Record<string, unknown>;
}

export interface McpJsonRpcRequest {
  jsonrpc: '2.0';
  id?: JsonRpcId;
  method: string;
  params?: McpToolCallParams | Record<string, unknown>;
}

export interface McpJsonRpcResponse {
  jsonrpc: '2.0';
  id: JsonRpcId;
  result?: Record<string, unknown>;
  error?: {
    code: number;
    message: string;
  };
}

export interface McpToolResult {
  ok: boolean;
  tool: string;
  status: 'ok' | 'blocked' | 'error';
  summary: string;
  findings: Array<Record<string, unknown>>;
  guardrails: {
    blocked: boolean;
    reason: string[];
    targetEnvironment: string;
    isLocal: boolean;
    isProduction: boolean;
    scope: string[];
  };
  metadata?: Record<string, unknown>;
}

/**
 * Stdio MCP server for Kinetic. The transport is deliberately small, but it
 * implements the MCP lifecycle and standard tool response envelope so it can
 * be used by conforming desktop and CI clients without an SDK dependency.
 */
export class McpToolServer {
  private readonly tools: McpToolDefinition[];
  private initializationAccepted = false;
  private initialized = false;

  constructor() {
    this.tools = this.createToolDefinitions();
  }

  public listTools(): McpToolDefinition[] {
    return [...this.tools];
  }

  public async handleRequest(request: McpJsonRpcRequest): Promise<McpJsonRpcResponse | null> {
    if (request.jsonrpc !== '2.0' || !request.method) {
      return this.protocolError(request.id ?? null, -32600, 'Invalid Request');
    }

    if (request.method === 'initialize') {
      return this.handleInitialize(request);
    }

    if (request.method === 'notifications/initialized') {
      if (this.initializationAccepted) {
        this.initialized = true;
      }
      return null;
    }

    if (request.method.startsWith('notifications/')) {
      return null;
    }

    if (request.method === 'ping') {
      return this.success(request.id ?? null, {});
    }

    if (!this.initialized) {
      return this.protocolError(request.id ?? null, -32002, 'Server is not initialized');
    }

    if (request.method === 'tools/list') {
      return this.success(request.id ?? null, { tools: this.listTools() });
    }

    if (request.method === 'tools/call') {
      const params = request.params;
      if (!this.isToolCallParams(params)) {
        return this.protocolError(request.id ?? null, -32602, 'Invalid tools/call parameters');
      }

      const tool = this.getTool(params.name);
      if (!tool) {
        return this.protocolError(request.id ?? null, -32602, `Unknown tool: ${params.name}`);
      }

      const argumentsObj = params.arguments ?? {};
      const argumentErrors = this.validateToolArguments(tool.name, argumentsObj);
      if (argumentErrors.length > 0) {
        return this.protocolError(request.id ?? null, -32602, argumentErrors.join(' '));
      }

      const result = await this.callTool(tool.name, argumentsObj);
      return this.success(request.id ?? null, this.toMcpToolCallResult(result));
    }

    return this.protocolError(request.id ?? null, -32601, `Method not found: ${request.method}`);
  }

  public async callTool(
    toolName: string,
    argumentsObj: Record<string, unknown>
  ): Promise<McpToolResult> {
    const tool = this.getTool(toolName);
    if (!tool) {
      return this.toolError(toolName, 'Unknown MCP tool');
    }

    const argumentErrors = this.validateToolArguments(tool.name, argumentsObj);
    if (argumentErrors.length > 0) {
      return this.toolError(tool.name, argumentErrors.join(' '));
    }

    const url = typeof argumentsObj['url'] === 'string' ? argumentsObj['url'] : '';
    const scope = this.getScope(argumentsObj['scope']);
    const headers = this.getStringRecord(argumentsObj['headers']);
    const cookies = this.getStringRecord(argumentsObj['cookies']);
    const authToken =
      typeof argumentsObj['authToken'] === 'string' ? argumentsObj['authToken'] : undefined;
    const dryRun = argumentsObj['dryRun'] === true;
    const changedFiles = this.getStringArray(argumentsObj['changedFiles']) ?? [];
    const allowedHosts = this.getStringArray(argumentsObj['allowedHosts']);
    const allowedPaths = this.getStringArray(argumentsObj['allowedPaths']);
    const allowedMethods = this.getStringArray(argumentsObj['allowedMethods']);
    const body = this.getJsonObject(argumentsObj['body']);
    const httpMethod = this.getToolHttpMethod(tool.name);
    const guardrails = ScopeGuard.evaluate({
      targetUrl: url,
      allowRemote: argumentsObj['allowRemote'] === true,
      confirmProduction: argumentsObj['confirmProduction'] === true,
      allowedHosts,
      allowedPaths,
      allowedMethods,
      httpMethod,
      requireRemoteScope: tool.name === 'targeted_scan' || tool.name === 'probe_json_endpoint',
      enforceRemoteAuthorization: tool.name !== 'scan_changed_routes',
      scope,
    });

    if (!guardrails.allowed) {
      return {
        ok: false,
        tool: tool.name,
        status: 'blocked',
        summary: 'Execution blocked by safety guardrails.',
        findings: [],
        guardrails: this.toGuardrailMetadata(guardrails),
        metadata: {
          requestContext: this.requestContextMetadata(headers, cookies, authToken),
        },
      };
    }

    if (tool.name === 'scan_changed_routes') {
      const candidateRoutes = this.deriveCandidateRoutes(changedFiles);
      return {
        ok: true,
        tool: tool.name,
        status: 'ok',
        summary: `Scan plan created for ${candidateRoutes.length} candidate route(s).`,
        findings: [],
        guardrails: this.toGuardrailMetadata(guardrails),
        metadata: {
          scanPlan: {
            changedFiles,
            candidateRoutes,
            targetUrl: this.safeUrl(url),
          },
          requestContext: this.requestContextMetadata(headers, cookies, authToken),
        },
      };
    }

    if (dryRun) {
      const activeScanPlan =
        tool.name === 'targeted_scan'
          ? {
              maxPages: this.getBoundedInteger(argumentsObj['maxPages'], 3, 1, 10),
              maxDepth: this.getBoundedInteger(argumentsObj['maxDepth'], 1, 0, 3),
              safeMode: true,
              aggressiveness: AggressivenessLevel.LOW,
              detectors: this.getActiveDetectorSelection(argumentsObj),
              ...(this.getSurfaceTypeSelection(argumentsObj)
                ? { surfaceTypes: this.getSurfaceTypeSelection(argumentsObj) }
                : {}),
            }
          : {};

      return {
        ok: true,
        tool: tool.name,
        status: 'ok',
        summary: `Dry run plan created for ${tool.name}.`,
        findings: [],
        guardrails: this.toGuardrailMetadata(guardrails),
        metadata: {
          dryRun: true,
          scanPlan: {
            tool: tool.name,
            targetUrl: this.safeUrl(url),
            scope: guardrails.scope,
            httpMethod,
            ...activeScanPlan,
          },
          requestContext: this.requestContextMetadata(headers, cookies, authToken),
        },
      };
    }

    let engine: ScanEngine | undefined;
    try {
      const config = this.buildConfig(
        tool.name,
        url,
        argumentsObj,
        headers,
        cookies,
        authToken,
        scope,
        allowedHosts,
        allowedPaths
      );
      registerBuiltInDetectors();
      const registry = DetectorRegistry.getInstance();
      engine = new ScanEngine();

      if (tool.name === 'passive_check') {
        const passiveScanner = new PassiveScanner();
        passiveScanner.registerDetectors(registry.getPassiveDetectors(config.detectors));
        engine.registerScanner(passiveScanner);
      } else if (tool.name === 'probe_json_endpoint') {
        const probeScanner = new JsonEndpointProbeScanner(body!, config.target.customHeaders);
        probeScanner.registerDetectors(registry.getPassiveDetectors(config.detectors));
        engine.registerScanner(probeScanner);
      } else {
        const activeConfig = config.scanners.active;
        const activeScanner = new ActiveScanner({
          maxPages: activeConfig.maxPages,
          maxDepth: activeConfig.maxDepth,
          safeMode: activeConfig.safeMode,
          aggressiveness: activeConfig.aggressiveness,
          surfaceTypes: this.getSurfaceTypeSelection(argumentsObj),
        });
        activeScanner.registerDetectors(registry.getActiveDetectors(config.detectors));
        engine.registerScanner(activeScanner);
      }

      await engine.loadConfiguration(config);
      const result = await engine.scan();
      const mappedFindings: Array<Record<string, unknown>> = result.vulnerabilities.map(
        (vulnerability) => ({
          title: vulnerability.title,
          description: vulnerability.description,
          severity: vulnerability.severity,
          category: vulnerability.category,
          confidence: vulnerability.confidence,
          evidence: vulnerability.evidence,
          remediation: vulnerability.remediation,
          url: vulnerability.url,
        })
      );

      return {
        ok: true,
        tool: tool.name,
        status: 'ok',
        summary: `Scan completed with ${result.summary.total} finding(s).`,
        findings: this.formatFindingsForLlm(mappedFindings),
        guardrails: this.toGuardrailMetadata(guardrails),
        metadata: {
          durationMs: result.duration,
          scanId: result.scanId,
          requestContext: this.requestContextMetadata(headers, cookies, authToken),
        },
      };
    } catch (error) {
      return {
        ok: false,
        tool: tool.name,
        status: 'error',
        summary: this.safeErrorMessage(error),
        findings: [],
        guardrails: this.toGuardrailMetadata(guardrails),
        metadata: {
          requestContext: this.requestContextMetadata(headers, cookies, authToken),
        },
      };
    } finally {
      if (engine) {
        await engine.cleanup().catch(() => undefined);
      }
    }
  }

  public async runStdio(): Promise<void> {
    process.env['KINETIC_MCP_MODE'] = 'true';
    process.stdin.setEncoding('utf8');

    // Parse the stream directly instead of using readline. On Windows,
    // readline can defer pipe-delivered lines in a persistent child process
    // until stdin closes, which makes a stdio MCP session appear unresponsive.
    let requestQueue = Promise.resolve();
    let buffer = '';
    const enqueueLine = (line: string): void => {
      requestQueue = requestQueue.then(async () => {
        if (!line.trim()) {
          return;
        }

        try {
          const response = await this.handleStdioLine(line);
          if (response) {
            process.stdout.write(`${JSON.stringify(response)}\n`);
          }
        } catch {
          process.stdout.write(
            `${JSON.stringify(this.protocolError(null, -32603, 'Internal error'))}\n`
          );
        }
      });
    };

    process.stdin.on('data', (chunk: string) => {
      buffer += chunk;
      const lines = buffer.split(/\r?\n/);
      buffer = lines.pop() ?? '';
      lines.forEach(enqueueLine);
    });

    await new Promise<void>((resolve, reject) => {
      process.stdin.once('error', reject);
      process.stdin.once('end', () => {
        if (buffer.trim()) {
          enqueueLine(buffer);
        }
        void requestQueue.then(resolve, reject);
      });
    });
  }

  /** Converts framework findings into bounded, secret-safe output for an LLM. */
  public formatFindingsForLlm(
    findings: Array<Record<string, unknown>>
  ): Array<Record<string, unknown>> {
    return findings.map((finding) => ({
      endpoint: this.safeUrl(typeof finding['url'] === 'string' ? finding['url'] : undefined),
      severity: this.scalarText(finding['severity'], 'info'),
      summary: this.limitText(this.scalarText(finding['title'], 'Finding')),
      description: this.limitText(this.scalarText(finding['description'], '')),
      category: finding['category'] ?? undefined,
      confidence: finding['confidence'] ?? 0,
      evidence: this.redactEvidence(finding['evidence']),
      remediation: this.limitText(
        typeof finding['remediation'] === 'string'
          ? finding['remediation']
          : 'Review the related endpoint and apply secure coding practices.'
      ),
    }));
  }

  private createToolDefinitions(): McpToolDefinition[] {
    const outputSchema = {
      type: 'object',
      properties: {
        ok: { type: 'boolean' },
        tool: { type: 'string' },
        status: { enum: ['ok', 'blocked', 'error'] },
        summary: { type: 'string' },
        findings: { type: 'array', items: { type: 'object' } },
        guardrails: { type: 'object' },
      },
      required: ['ok', 'tool', 'status', 'summary', 'findings', 'guardrails'],
    };
    const commonProperties: Record<string, unknown> = {
      url: { type: 'string', format: 'uri', description: 'HTTP(S) URL to assess.' },
      allowRemote: {
        type: 'boolean',
        description: 'Explicit authorization to contact a non-local target.',
      },
      confirmProduction: {
        type: 'boolean',
        description: 'Explicit authorization for a production target.',
      },
      headers: {
        type: 'object',
        additionalProperties: { type: 'string' },
        description: 'Request headers. Values are never returned by the server.',
      },
      cookies: {
        type: 'object',
        additionalProperties: { type: 'string' },
        description:
          'Cookies to apply to the target origin. Values are never returned by the server.',
      },
      authToken: {
        type: 'string',
        description: 'Bearer token applied only to the target request context.',
      },
      dryRun: {
        type: 'boolean',
        description: 'Return the validated plan without contacting the target.',
      },
      allowedHosts: {
        type: 'array',
        items: { type: 'string' },
        description: 'Exact hosts or *.subdomain wildcards permitted for this run.',
      },
      allowedPaths: {
        type: 'array',
        items: { type: 'string' },
        description: 'Absolute path prefixes permitted for this run.',
      },
      scope: {
        type: 'object',
        properties: {
          include: { type: 'array', items: { type: 'string' } },
          exclude: { type: 'array', items: { type: 'string' } },
          stayOnDomain: { type: 'boolean' },
        },
        additionalProperties: false,
      },
    };
    const schema = (
      properties: Record<string, unknown>,
      required: string[]
    ): Record<string, unknown> => ({
      type: 'object',
      properties: { ...commonProperties, ...properties },
      required,
      additionalProperties: false,
    });

    return [
      {
        name: 'passive_check',
        title: 'Passive Security Check',
        description:
          'Inspect one URL for headers, cookies, transmission, and obvious sensitive-data issues without injecting payloads.',
        inputSchema: schema({}, ['url']),
        outputSchema,
        annotations: {
          readOnlyHint: true,
          destructiveHint: false,
          idempotentHint: true,
          openWorldHint: true,
        },
        safeByDefault: true,
      },
      {
        name: 'targeted_scan',
        title: 'Targeted Active Scan',
        description:
          'Run a low-aggressiveness, safe-mode active scan in an explicit URL scope. Optional detector and injectable-surface filters bound the scan. Remote scans require host and path allow-lists.',
        inputSchema: schema(
          {
            maxPages: { type: 'integer', minimum: 1, maximum: 10, default: 3 },
            maxDepth: { type: 'integer', minimum: 0, maximum: 3, default: 1 },
            detectors: {
              type: 'array',
              items: { type: 'string', enum: AVAILABLE_ACTIVE_DETECTORS },
              description:
                'Optional active detector IDs. Defaults to SQL injection, XSS, and error disclosure.',
            },
            surfaceTypes: {
              type: 'array',
              items: { type: 'string', enum: INJECTABLE_SURFACE_TYPES },
              description: 'Optional injectable attack-surface types to test.',
            },
          },
          ['url']
        ),
        outputSchema,
        annotations: {
          readOnlyHint: false,
          destructiveHint: true,
          idempotentHint: false,
          openWorldHint: true,
        },
        safeByDefault: true,
      },
      {
        name: 'probe_json_endpoint',
        title: 'JSON Endpoint Probe',
        description:
          'POST one supplied JSON object and passively inspect the request/response pair. This does not fuzz the payload.',
        inputSchema: schema(
          {
            body: { type: 'object', description: 'JSON object to send once as the POST body.' },
            allowedMethods: {
              type: 'array',
              items: { type: 'string' },
              description: 'Optional method scope; it must include POST.',
            },
          },
          ['url', 'body']
        ),
        outputSchema,
        annotations: {
          readOnlyHint: false,
          destructiveHint: false,
          idempotentHint: false,
          openWorldHint: true,
        },
        safeByDefault: true,
      },
      {
        name: 'scan_changed_routes',
        title: 'Changed-Route Scan Plan',
        description:
          'Convert provided changed route or source-file hints into a scoped scan plan without contacting the target.',
        inputSchema: schema(
          {
            changedFiles: {
              type: 'array',
              items: { type: 'string' },
              description: 'Route paths or changed source-file paths from CI.',
            },
          },
          ['url', 'changedFiles']
        ),
        outputSchema,
        annotations: {
          readOnlyHint: true,
          destructiveHint: false,
          idempotentHint: true,
          openWorldHint: false,
        },
        safeByDefault: true,
      },
    ];
  }

  private handleInitialize(request: McpJsonRpcRequest): McpJsonRpcResponse {
    const params = this.isRecord(request.params) ? request.params : undefined;
    const protocolVersion = params?.['protocolVersion'];
    if (typeof protocolVersion !== 'string' || !SUPPORTED_PROTOCOL_VERSIONS.has(protocolVersion)) {
      return this.protocolError(
        request.id ?? null,
        -32602,
        `Unsupported protocol version: ${typeof protocolVersion === 'string' ? protocolVersion : ''}`
      );
    }

    this.initializationAccepted = true;
    this.initialized = false;
    return this.success(request.id ?? null, {
      protocolVersion,
      capabilities: {
        tools: { listChanged: false },
      },
      serverInfo: {
        name: 'kinetic-dast',
        version: '0.2.0',
      },
      instructions:
        'Use dryRun first for active scans. Remote active scans require allowRemote, and host/path scope allow-lists. Production scans additionally require confirmProduction.',
    });
  }

  private async handleStdioLine(line: string): Promise<McpJsonRpcResponse | null> {
    let parsed: unknown;
    try {
      // PowerShell and a few Windows MCP clients prefix the first pipe-delivered
      // JSON-RPC line with a UTF-8 BOM. It is transport metadata, not JSON.
      parsed = JSON.parse(line.replace(/^\uFEFF/, ''));
    } catch {
      return this.protocolError(null, -32700, 'Parse error');
    }

    if (
      !this.isRecord(parsed) ||
      parsed['jsonrpc'] !== '2.0' ||
      typeof parsed['method'] !== 'string'
    ) {
      return this.protocolError(this.getRequestId(parsed), -32600, 'Invalid Request');
    }

    const id = this.getRequestId(parsed);
    if (parsed['id'] !== undefined && id === null && parsed['id'] !== null) {
      return this.protocolError(null, -32600, 'Invalid Request id');
    }

    return this.handleRequest({
      jsonrpc: '2.0',
      id: parsed['id'] as JsonRpcId | undefined,
      method: parsed['method'],
      params: this.isRecord(parsed['params']) ? parsed['params'] : undefined,
    });
  }

  private buildConfig(
    toolName: McpToolName,
    targetUrl: string,
    argumentsObj: Record<string, unknown>,
    headers: Record<string, string> | undefined,
    cookies: Record<string, string> | undefined,
    authToken: string | undefined,
    scope: { include?: string[]; exclude?: string[]; stayOnDomain?: boolean } | undefined,
    allowedHosts: string[] | undefined,
    allowedPaths: string[] | undefined
  ): ScanConfiguration {
    const maxPages = this.getBoundedInteger(argumentsObj['maxPages'], 3, 1, 10);
    const maxDepth = this.getBoundedInteger(argumentsObj['maxDepth'], 1, 0, 3);
    const isPassive = toolName === 'passive_check' || toolName === 'probe_json_endpoint';
    const enabledDetectors = isPassive
      ? [...PASSIVE_DETECTORS]
      : this.getActiveDetectorSelection(argumentsObj);
    const customHeaders = { ...(headers ?? {}) };

    if (
      authToken &&
      !Object.keys(customHeaders).some((header) => header.toLowerCase() === 'authorization')
    ) {
      customHeaders['Authorization'] = `Bearer ${authToken}`;
    }

    const cookieEntries = Object.entries(cookies ?? {}).map(([name, value]) => ({
      name,
      value,
      domain: new URL(targetUrl).hostname,
      path: '/',
    }));

    return {
      target: {
        url: targetUrl,
        authentication: undefined,
        customHeaders,
        cookies: cookieEntries,
        scope: {
          include: scope?.include ?? [],
          exclude: scope?.exclude ?? [],
          // Active scans are always confined to the target origin; retaining
          // this marker makes the restriction visible in persisted config.
          stayOnDomain: true,
          allowedHosts: allowedHosts ?? [],
          allowedPaths: allowedPaths ?? [],
        },
        maxPages,
        crawlDepth: maxDepth,
      },
      scanners: {
        active: {
          enabled: !isPassive,
          safeMode: true,
          aggressiveness: AggressivenessLevel.LOW,
          maxDepth,
          maxPages,
        },
        passive: {
          enabled: isPassive,
          downloads: true,
        },
      },
      detectors: {
        enabled: enabledDetectors,
        disabled: [],
        tuning: {},
      },
      browser: {
        type: BrowserType.CHROMIUM,
        headless: true,
        slowMo: 0,
        timeout: 30_000,
      },
      reporting: {
        formats: [ReportFormat.JSON],
        outputDir: 'reports',
        verbosity: VerbosityLevel.NORMAL,
      },
      advanced: {
        parallelism: 1,
        logLevel: LogLevel.INFO,
        rateLimit: 5,
      },
    };
  }

  private validateToolArguments(
    toolName: McpToolName,
    argumentsObj: Record<string, unknown>
  ): string[] {
    const errors: string[] = [];
    if (typeof argumentsObj['url'] !== 'string' || !argumentsObj['url'].trim()) {
      errors.push('url must be a non-empty string.');
    }

    for (const booleanName of ['allowRemote', 'confirmProduction', 'dryRun']) {
      const value = argumentsObj[booleanName];
      if (value !== undefined && typeof value !== 'boolean') {
        errors.push(`${booleanName} must be a boolean.`);
      }
    }

    for (const arrayName of ['allowedHosts', 'allowedPaths', 'allowedMethods', 'changedFiles']) {
      const value = argumentsObj[arrayName];
      if (
        value !== undefined &&
        (!Array.isArray(value) || !value.every((entry) => typeof entry === 'string'))
      ) {
        errors.push(`${arrayName} must be an array of strings.`);
      }
    }

    for (const recordName of ['headers', 'cookies']) {
      const value = argumentsObj[recordName];
      if (value !== undefined && !this.isStringRecord(value)) {
        errors.push(`${recordName} must be an object with string values.`);
      }
    }

    const scope = argumentsObj['scope'];
    if (scope !== undefined && !this.isScope(scope)) {
      errors.push(
        'scope must contain only string-array include/exclude fields and an optional boolean stayOnDomain.'
      );
    }

    if (toolName === 'targeted_scan') {
      this.validateBoundedInteger(argumentsObj['maxPages'], 'maxPages', 1, 10, errors);
      this.validateBoundedInteger(argumentsObj['maxDepth'], 'maxDepth', 0, 3, errors);

      const selectedDetectors = argumentsObj['detectors'];
      if (selectedDetectors !== undefined) {
        const detectorIds = this.getStringArray(selectedDetectors);
        if (!detectorIds?.length) {
          errors.push('detectors must be a non-empty array of active detector IDs.');
        } else {
          const unsupported = detectorIds.filter(
            (detectorId) =>
              !AVAILABLE_ACTIVE_DETECTORS.includes(
                detectorId as (typeof AVAILABLE_ACTIVE_DETECTORS)[number]
              )
          );
          if (unsupported.length > 0) {
            errors.push(`Unsupported targeted_scan detector IDs: ${unsupported.join(', ')}.`);
          }
        }
      }

      const selectedSurfaceTypes = argumentsObj['surfaceTypes'];
      if (selectedSurfaceTypes !== undefined) {
        const surfaceTypes = this.getStringArray(selectedSurfaceTypes);
        if (!surfaceTypes?.length) {
          errors.push('surfaceTypes must be a non-empty array of injectable attack-surface types.');
        } else {
          const unsupported = surfaceTypes.filter(
            (surfaceType) =>
              !INJECTABLE_SURFACE_TYPES.includes(
                surfaceType as (typeof INJECTABLE_SURFACE_TYPES)[number]
              )
          );
          if (unsupported.length > 0) {
            errors.push(`Unsupported targeted_scan surfaceTypes: ${unsupported.join(', ')}.`);
          }
        }
      }

      if (argumentsObj['allowedMethods'] !== undefined) {
        errors.push(
          'allowedMethods is not supported by targeted_scan because discovered requests may use multiple methods.'
        );
      }
    } else if (
      argumentsObj['detectors'] !== undefined ||
      argumentsObj['surfaceTypes'] !== undefined
    ) {
      errors.push('detectors and surfaceTypes are supported only by targeted_scan.');
    }

    if (toolName === 'passive_check' && argumentsObj['allowedMethods'] !== undefined) {
      const methods = this.getStringArray(argumentsObj['allowedMethods']) ?? [];
      if (!methods.some((method) => method.toUpperCase() === 'GET')) {
        errors.push('allowedMethods for passive_check must include GET.');
      }
    }

    if (toolName === 'probe_json_endpoint') {
      if (!this.getJsonObject(argumentsObj['body'])) {
        errors.push('body must be a JSON object for probe_json_endpoint.');
      }
      const methods = this.getStringArray(argumentsObj['allowedMethods']);
      if (methods && !methods.some((method) => method.toUpperCase() === 'POST')) {
        errors.push('allowedMethods for probe_json_endpoint must include POST.');
      }
    }

    if (toolName === 'scan_changed_routes') {
      const changedFiles = this.getStringArray(argumentsObj['changedFiles']);
      if (!changedFiles) {
        errors.push('changedFiles must be provided for scan_changed_routes.');
      } else if (changedFiles.length > 100) {
        errors.push('changedFiles may contain at most 100 entries.');
      }
    }

    return errors;
  }

  private toMcpToolCallResult(result: McpToolResult): Record<string, unknown> {
    const structuredContent = result as unknown as Record<string, unknown>;
    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify(
            {
              tool: result.tool,
              status: result.status,
              summary: result.summary,
              findings: result.findings,
              guardrails: result.guardrails,
            },
            null,
            2
          ),
        },
      ],
      structuredContent,
      isError: !result.ok,
    };
  }

  private toGuardrailMetadata(
    guardrails: ReturnType<typeof ScopeGuard.evaluate>
  ): McpToolResult['guardrails'] {
    return {
      blocked: !guardrails.allowed,
      reason: guardrails.reason,
      targetEnvironment: guardrails.targetEnvironment,
      isLocal: guardrails.isLocal,
      isProduction: guardrails.isProduction,
      scope: guardrails.scope,
    };
  }

  private toolError(tool: string, summary: string): McpToolResult {
    return {
      ok: false,
      tool,
      status: 'error',
      summary,
      findings: [],
      guardrails: {
        blocked: false,
        reason: [],
        targetEnvironment: 'unknown',
        isLocal: false,
        isProduction: false,
        scope: [],
      },
    };
  }

  private requestContextMetadata(
    headers: Record<string, string> | undefined,
    cookies: Record<string, string> | undefined,
    authToken: string | undefined
  ): Record<string, unknown> {
    return {
      headerNames: Object.keys(headers ?? {}),
      cookieNames: Object.keys(cookies ?? {}),
      bearerAuthConfigured: Boolean(authToken),
    };
  }

  private deriveCandidateRoutes(changedFiles: string[]): string[] {
    const routes = new Set<string>();
    for (const changedFile of changedFiles) {
      const normalized = changedFile.replace(/\\/g, '/').trim();
      if (!normalized) {
        continue;
      }
      if (normalized.startsWith('/')) {
        routes.add(normalized);
        continue;
      }

      const routeMarker = normalized.match(/(?:^|\/)(?:api|routes?|pages?)(\/.*)$/i);
      if (routeMarker?.[1]) {
        const route = routeMarker[1]
          .replace(/\.(?:[cm]?[jt]sx?|vue|svelte)$/i, '')
          .replace(/\/index$/i, '/');
        routes.add(route.startsWith('/') ? route : `/${route}`);
      }
    }
    return Array.from(routes).sort();
  }

  private redactEvidence(value: unknown, key?: string, depth = 0): unknown {
    if (key && SENSITIVE_KEY.test(key)) {
      return '[REDACTED]';
    }
    if (key && RAW_CONTENT_KEY.test(key)) {
      return '[OMITTED: untrusted response content]';
    }
    if (key && /^(?:url|uri|endpoint|href|location)$/i.test(key) && typeof value === 'string') {
      return this.safeUrl(value) ?? '[invalid URL]';
    }
    if (typeof value === 'string') {
      if (this.looksLikeCredential(value)) {
        return '[REDACTED]';
      }
      return this.limitText(value);
    }
    if (
      typeof value === 'number' ||
      typeof value === 'boolean' ||
      value === null ||
      value === undefined
    ) {
      return value;
    }
    if (depth >= 5) {
      return '[OMITTED: maximum evidence depth reached]';
    }
    if (Array.isArray(value)) {
      return value.slice(0, 20).map((item) => this.redactEvidence(item, undefined, depth + 1));
    }
    if (this.isRecord(value)) {
      const namedSecret = typeof value['name'] === 'string' && SENSITIVE_KEY.test(value['name']);
      return Object.fromEntries(
        Object.entries(value)
          .slice(0, 30)
          .map(([entryKey, entryValue]) => [
            entryKey,
            namedSecret && entryKey === 'value'
              ? '[REDACTED]'
              : this.redactEvidence(entryValue, entryKey, depth + 1),
          ])
      );
    }
    if (typeof value === 'bigint') {
      return value.toString();
    }
    return '[OMITTED: unsupported evidence value]';
  }

  private scalarText(value: unknown, fallback: string): string {
    if (typeof value === 'string') {
      return value;
    }
    if (typeof value === 'number' || typeof value === 'boolean' || typeof value === 'bigint') {
      return value.toString();
    }
    return fallback;
  }

  private looksLikeCredential(value: string): boolean {
    return (
      /^(?:Bearer|Basic)\s+\S+/i.test(value) ||
      /^[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}$/.test(value)
    );
  }

  private safeErrorMessage(error: unknown): string {
    const message = error instanceof Error ? error.message : String(error);
    return this.limitText(
      message
        .replace(/(?:Bearer|Basic)\s+[^\s,;]+/gi, '$1 [REDACTED]')
        .replace(/(?:password|token|secret|api[_-]?key)=([^\s&]+)/gi, '$1=[REDACTED]')
        .replace(/https?:\/\/[^\s'"`]+/gi, (url) => this.safeUrl(url) ?? '[invalid URL]')
    );
  }

  private safeUrl(value: string | undefined): string | undefined {
    if (!value) {
      return undefined;
    }
    try {
      const parsed = new URL(value);
      parsed.username = '';
      parsed.password = '';
      parsed.search = '';
      parsed.hash = '';
      return parsed.toString();
    } catch {
      return this.limitText(value);
    }
  }

  private limitText(value: string): string {
    const normalized = Array.from(value, (character) => {
      const codePoint = character.charCodeAt(0);
      return codePoint < 32 || codePoint === 127 ? ' ' : character;
    })
      .join('')
      .trim();
    return normalized.length > 2_000 ? `${normalized.slice(0, 2_000)}…` : normalized;
  }

  private getTool(name: string): McpToolDefinition | undefined {
    return this.tools.find((tool) => tool.name === name);
  }

  private getToolHttpMethod(toolName: McpToolName): string | undefined {
    if (toolName === 'passive_check') {
      return 'GET';
    }
    if (toolName === 'probe_json_endpoint') {
      return 'POST';
    }
    return undefined;
  }

  private getActiveDetectorSelection(argumentsObj: Record<string, unknown>): string[] {
    const requested = this.getStringArray(argumentsObj['detectors']);
    return requested?.length ? [...new Set(requested)] : [...DEFAULT_ACTIVE_DETECTORS];
  }

  private getSurfaceTypeSelection(
    argumentsObj: Record<string, unknown>
  ): AttackSurfaceType[] | undefined {
    const requested = this.getStringArray(argumentsObj['surfaceTypes']);
    if (!requested?.length) {
      return undefined;
    }

    return requested
      .filter((surfaceType) =>
        INJECTABLE_SURFACE_TYPES.includes(surfaceType as (typeof INJECTABLE_SURFACE_TYPES)[number])
      )
      .map((surfaceType) => surfaceType as AttackSurfaceType);
  }

  private getScope(
    value: unknown
  ): { include?: string[]; exclude?: string[]; stayOnDomain?: boolean } | undefined {
    if (!this.isScope(value)) {
      return undefined;
    }
    return {
      include: this.getStringArray(value['include']),
      exclude: this.getStringArray(value['exclude']),
      stayOnDomain: value['stayOnDomain'] === true,
    };
  }

  private getStringArray(value: unknown): string[] | undefined {
    return Array.isArray(value) && value.every((entry) => typeof entry === 'string')
      ? value
      : undefined;
  }

  private getStringRecord(value: unknown): Record<string, string> | undefined {
    return this.isStringRecord(value) ? value : undefined;
  }

  private getJsonObject(value: unknown): Record<string, unknown> | undefined {
    return this.isRecord(value) ? value : undefined;
  }

  private getBoundedInteger(
    value: unknown,
    defaultValue: number,
    minimum: number,
    maximum: number
  ): number {
    if (value === undefined) {
      return defaultValue;
    }
    return typeof value === 'number' &&
      Number.isInteger(value) &&
      value >= minimum &&
      value <= maximum
      ? value
      : defaultValue;
  }

  private validateBoundedInteger(
    value: unknown,
    name: string,
    minimum: number,
    maximum: number,
    errors: string[]
  ): void {
    if (
      value !== undefined &&
      (!Number.isInteger(value) || typeof value !== 'number' || value < minimum || value > maximum)
    ) {
      errors.push(`${name} must be an integer between ${minimum} and ${maximum}.`);
    }
  }

  private isToolCallParams(value: unknown): value is McpToolCallParams {
    return (
      this.isRecord(value) &&
      typeof value['name'] === 'string' &&
      (value['arguments'] === undefined || this.isRecord(value['arguments']))
    );
  }

  private isScope(value: unknown): value is Record<string, unknown> {
    if (!this.isRecord(value)) {
      return false;
    }
    const allowedKeys = new Set(['include', 'exclude', 'stayOnDomain']);
    return (
      Object.keys(value).every((key) => allowedKeys.has(key)) &&
      (value['include'] === undefined || this.getStringArray(value['include']) !== undefined) &&
      (value['exclude'] === undefined || this.getStringArray(value['exclude']) !== undefined) &&
      (value['stayOnDomain'] === undefined || typeof value['stayOnDomain'] === 'boolean')
    );
  }

  private isStringRecord(value: unknown): value is Record<string, string> {
    return this.isRecord(value) && Object.values(value).every((entry) => typeof entry === 'string');
  }

  private isRecord(value: unknown): value is Record<string, unknown> {
    return typeof value === 'object' && value !== null && !Array.isArray(value);
  }

  private getRequestId(value: unknown): JsonRpcId {
    if (!this.isRecord(value)) {
      return null;
    }
    const id = value['id'];
    return typeof id === 'string' || typeof id === 'number' || id === null ? id : null;
  }

  private success(id: JsonRpcId, result: Record<string, unknown>): McpJsonRpcResponse {
    return { jsonrpc: '2.0', id, result };
  }

  private protocolError(id: JsonRpcId, code: number, message: string): McpJsonRpcResponse {
    return { jsonrpc: '2.0', id, error: { code, message } };
  }
}
