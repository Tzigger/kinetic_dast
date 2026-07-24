import { LogLevel } from '../types/enums';
import { TargetValidator } from '../utils/TargetValidator';

export interface ScopeGuardOptions {
  targetUrl: string;
  /** Required for any non-local target. */
  allowRemote?: boolean;
  /** Required in addition to allowRemote for production targets. */
  confirmProduction?: boolean;
  /** Exact hosts, or wildcard subdomains in the form *.example.com. */
  allowedHosts?: string[];
  /** Absolute path prefixes that the scanner may visit. */
  allowedPaths?: string[];
  /** Optional allow-list of methods for a tool with one known request method. */
  allowedMethods?: string[];
  /** The method the requested tool will use. */
  httpMethod?: string;
  /** Require an explicit host and path allow-list for non-local scans. */
  requireRemoteScope?: boolean;
  /** Set false only for a plan that never opens a target connection. */
  enforceRemoteAuthorization?: boolean;
  scope?: {
    include?: string[];
    exclude?: string[];
    stayOnDomain?: boolean;
  };
}

export interface ScopeGuardResult {
  allowed: boolean;
  reason: string[];
  targetEnvironment: string;
  isLocal: boolean;
  isProduction: boolean;
  scope: string[];
}

/**
 * Validates an MCP target before any browser or network activity starts.
 *
 * This intentionally has stricter semantics than the general scanner target
 * validator: MCP calls may be model initiated, so remote active scans need an
 * explicit, narrow authorization scope.
 */
export class ScopeGuard {
  public static evaluate(options: ScopeGuardOptions): ScopeGuardResult {
    const reason: string[] = [];
    let target: URL;

    try {
      target = new URL(options.targetUrl);
    } catch {
      return this.blockedInvalidTarget(reason);
    }

    if (!['http:', 'https:'].includes(target.protocol)) {
      reason.push('Target URL must use HTTP or HTTPS');
    }

    if (target.username || target.password) {
      reason.push('Target URL must not contain credentials; use headers or authToken instead');
    }

    if (/%2f|%5c|%2e/i.test(target.pathname)) {
      reason.push('Target URL path must not contain encoded separators or traversal segments');
    }

    const validator = new TargetValidator(LogLevel.ERROR);
    const validation = validator.validateUrl(options.targetUrl);
    if (!validation.isValid) {
      reason.push('Target URL is invalid');
    }

    const allowedHosts = this.normalizeHosts(options.allowedHosts, reason);
    const allowedPaths = this.normalizePaths(options.allowedPaths, reason, 'allowedPaths');
    const includedPaths = this.normalizePaths(options.scope?.include, reason, 'scope.include');
    const excludedPaths = this.normalizePaths(options.scope?.exclude, reason, 'scope.exclude');

    if (options.enforceRemoteAuthorization !== false) {
      if (!validation.isLocal && !options.allowRemote) {
        reason.push('Remote targets require explicit allowRemote=true');
      }

      if (validation.isProduction && !options.confirmProduction) {
        reason.push('Production targets require explicit confirmProduction=true');
      }
    }

    if (options.requireRemoteScope && !validation.isLocal) {
      if (allowedHosts.length === 0) {
        reason.push('Remote scans require a non-empty allowedHosts scope');
      }
      if (allowedPaths.length === 0 && includedPaths.length === 0) {
        reason.push('Remote scans require allowedPaths or scope.include');
      }
    }

    if (allowedHosts.length > 0 && !this.matchesHost(target.hostname, allowedHosts)) {
      reason.push('Host is not included in allowedHosts');
    }

    if (allowedPaths.length > 0 && !this.matchesPath(target.pathname, allowedPaths)) {
      reason.push('Path is not included in allowedPaths');
    }

    if (includedPaths.length > 0 && !this.matchesPath(target.pathname, includedPaths)) {
      reason.push('Path is not included in scope.include');
    }

    if (excludedPaths.length > 0 && this.matchesPath(target.pathname, excludedPaths)) {
      reason.push('Path is excluded by scope.exclude');
    }

    if (options.allowedMethods?.length) {
      const allowedMethods = options.allowedMethods.map((method) => method.toUpperCase());
      if (!options.httpMethod) {
        reason.push('allowedMethods cannot be enforced because the tool has no fixed HTTP method');
      } else if (!allowedMethods.includes(options.httpMethod.toUpperCase())) {
        reason.push('HTTP method is not included in allowedMethods');
      }
    }

    return {
      allowed: reason.length === 0,
      reason,
      targetEnvironment: validation.environment,
      isLocal: validation.isLocal,
      isProduction: validation.isProduction,
      scope: this.describeScope(allowedHosts, allowedPaths, includedPaths, excludedPaths, options.scope),
    };
  }

  public static matchesHost(hostname: string, allowedHosts: string[]): boolean {
    const normalizedHostname = hostname.toLowerCase().replace(/\.$/, '');
    return allowedHosts.some((allowedHost) => {
      if (allowedHost.startsWith('*.')) {
        const domain = allowedHost.slice(2);
        return normalizedHostname.endsWith(`.${domain}`);
      }
      return normalizedHostname === allowedHost;
    });
  }

  public static matchesPath(pathname: string, allowedPaths: string[]): boolean {
    return allowedPaths.some((allowedPath) => {
      if (allowedPath === '/') {
        return true;
      }
      return pathname === allowedPath || pathname.startsWith(`${allowedPath}/`);
    });
  }

  private static blockedInvalidTarget(reason: string[]): ScopeGuardResult {
    reason.push('Target URL is invalid');
    return {
      allowed: false,
      reason,
      targetEnvironment: 'unknown',
      isLocal: false,
      isProduction: false,
      scope: [],
    };
  }

  private static normalizeHosts(hosts: string[] | undefined, reason: string[]): string[] {
    if (!hosts) {
      return [];
    }

    const normalized = new Set<string>();
    for (const host of hosts) {
      const value = host.trim().toLowerCase().replace(/\.$/, '');
      if (!value || /[/:?#@\s]/.test(value) || (value.includes('*') && !value.startsWith('*.'))) {
        reason.push('allowedHosts must contain hostnames or *.hostname wildcards');
        continue;
      }
      normalized.add(value);
    }
    return Array.from(normalized);
  }

  private static normalizePaths(
    paths: string[] | undefined,
    reason: string[],
    optionName: string
  ): string[] {
    if (!paths) {
      return [];
    }

    const normalized = new Set<string>();
    for (const path of paths) {
      const value = path.trim();
      if (!value.startsWith('/') || value.includes('?') || value.includes('#') || /%2f|%5c|%2e/i.test(value)) {
        reason.push(`${optionName} must contain absolute, non-encoded path prefixes`);
        continue;
      }
      const normalizedPath = value.length > 1 ? value.replace(/\/+$/, '') : value;
      normalized.add(normalizedPath);
    }
    return Array.from(normalized);
  }

  private static describeScope(
    allowedHosts: string[],
    allowedPaths: string[],
    includedPaths: string[],
    excludedPaths: string[],
    scope: ScopeGuardOptions['scope']
  ): string[] {
    return [
      ...allowedHosts.map((host) => `host:${host}`),
      ...allowedPaths.map((path) => `path:${path}`),
      ...includedPaths.map((path) => `include:${path}`),
      ...excludedPaths.map((path) => `exclude:${path}`),
      ...(scope?.stayOnDomain ? ['stayOnDomain:true'] : []),
    ];
  }
}
