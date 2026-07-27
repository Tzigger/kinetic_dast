import { VulnerabilitySeverity } from '../../src/types/enums';

export interface ExpectedFinding {
  endpoint: '/' | '/socket.io/';
  title: string;
  severity: VulnerabilitySeverity;
  cwe: string;
}

export interface ExpectedActiveFinding {
  title: string;
  severity: VulnerabilitySeverity;
  category: string;
  cwe: string;
}

/**
 * Findings confirmed by the hardening MCP on the stock local Juice Shop image.
 * They remain intentionally vulnerable so this suite verifies Kinetic's ability
 * to surface them; it is not an assertion that Juice Shop is hardened.
 */
export const mcpConfirmedPassiveFindings: ExpectedFinding[] = [
  {
    endpoint: '/',
    title: 'Missing Security Header: Strict-Transport-Security',
    severity: VulnerabilitySeverity.HIGH,
    cwe: 'CWE-319',
  },
  {
    endpoint: '/',
    title: 'Missing Security Header: Content-Security-Policy',
    severity: VulnerabilitySeverity.HIGH,
    cwe: 'CWE-79',
  },
  {
    endpoint: '/',
    title: 'Missing Security Header: X-Xss-Protection',
    severity: VulnerabilitySeverity.LOW,
    cwe: 'CWE-79',
  },
  {
    endpoint: '/',
    title: 'Missing Security Header: Referrer-Policy',
    severity: VulnerabilitySeverity.LOW,
    cwe: 'CWE-200',
  },
  {
    endpoint: '/',
    title: 'Missing Security Header: Permissions-Policy',
    severity: VulnerabilitySeverity.LOW,
    cwe: 'CWE-16',
  },
  {
    endpoint: '/',
    title: 'Cross-Domain Misconfiguration',
    severity: VulnerabilitySeverity.MEDIUM,
    cwe: 'CWE-942',
  },
  {
    endpoint: '/',
    title: 'Tech Detected - Google Font API',
    severity: VulnerabilitySeverity.INFO,
    cwe: 'CWE-200',
  },
  {
    endpoint: '/',
    title: 'HTTP Transmission on Localhost',
    severity: VulnerabilitySeverity.INFO,
    cwe: 'CWE-319',
  },
  {
    endpoint: '/socket.io/',
    title: 'Missing Security Header: Strict-Transport-Security',
    severity: VulnerabilitySeverity.HIGH,
    cwe: 'CWE-319',
  },
  {
    endpoint: '/socket.io/',
    title: 'Missing Security Header: Content-Security-Policy',
    severity: VulnerabilitySeverity.HIGH,
    cwe: 'CWE-79',
  },
  {
    endpoint: '/socket.io/',
    title: 'Missing Security Header: X-Frame-Options',
    severity: VulnerabilitySeverity.MEDIUM,
    cwe: 'CWE-1021',
  },
  {
    endpoint: '/socket.io/',
    title: 'Missing Security Header: X-Content-Type-Options',
    severity: VulnerabilitySeverity.MEDIUM,
    cwe: 'CWE-16',
  },
  {
    endpoint: '/socket.io/',
    title: 'Missing Security Header: X-Xss-Protection',
    severity: VulnerabilitySeverity.LOW,
    cwe: 'CWE-79',
  },
  {
    endpoint: '/socket.io/',
    title: 'Missing Security Header: Referrer-Policy',
    severity: VulnerabilitySeverity.LOW,
    cwe: 'CWE-200',
  },
  {
    endpoint: '/socket.io/',
    title: 'Missing Security Header: Permissions-Policy',
    severity: VulnerabilitySeverity.LOW,
    cwe: 'CWE-16',
  },
  {
    endpoint: '/socket.io/',
    title: 'HTTP Transmission on Localhost',
    severity: VulnerabilitySeverity.INFO,
    cwe: 'CWE-319',
  },
];

/**
 * Active findings confirmed through the MCP after an explicit local dry run.
 * The tests below invoke Kinetic's public scanning APIs rather than
 * reimplementing payloads or checking Juice Shop's DOM directly.
 */
export const mcpConfirmedActiveFindings = {
  hashRouteXss: {
    title: 'Cross-Site Scripting (reflected)',
    severity: VulnerabilitySeverity.HIGH,
    category: 'xss',
    cwe: 'CWE-79',
  },
  loginAuthenticationBypass: {
    title: 'SQL Injection (Authentication Bypass)',
    severity: VulnerabilitySeverity.CRITICAL,
    category: 'injection',
    cwe: 'CWE-89',
  },
  loginBooleanBasedSqli: {
    title: 'SQL Injection (boolean-based)',
    severity: VulnerabilitySeverity.CRITICAL,
    category: 'injection',
    cwe: 'CWE-89',
  },
} as const satisfies Record<string, ExpectedActiveFinding>;
