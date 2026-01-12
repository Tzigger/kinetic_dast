/**
 * Error patterns that indicate potential vulnerabilities
 */

/**
 * SQL error patterns
 */
export const SQL_ERROR_PATTERNS = [
  // Generic SQL
  /SQL syntax.*?error/i,
  /syntax error.*?SQL/i,
  /unclosed quotation mark/i,
  /quoted string not properly terminated/i,

  // MySQL
  /mysql_fetch_array\(\)/i,
  /mysql_fetch_assoc\(\)/i,
  /mysql_num_rows\(\)/i,
  /You have an error in your SQL syntax/i,
  /supplied argument is not a valid MySQL/i,

  // PostgreSQL
  /PostgreSQL.*?ERROR/i,
  /pg_query\(\)/i,
  /pg_exec\(\)/i,
  /unterminated quoted string/i,

  // MSSQL
  /Microsoft SQL Server/i,
  /ODBC SQL Server Driver/i,
  /SQLServer JDBC Driver/i,
  /OLE DB.*?SQL Server/i,
  /Unclosed quotation mark after the character string/i,

  // Oracle
  /ORA-\d{5}/i,
  /Oracle.*?Driver/i,
  /oracle\.jdbc/i,

  // SQLite
  /SQLite\/JDBCDriver/i,
  /System\.Data\.SQLite/i,
];

/**
 * Relaxed SQL error patterns for testing (bWAPP)
 */
export const BWAPP_SQL_PATTERNS = [
  /Warning:.*mysql/i,
  /mysqli_.*\(\).*expects/i,
  /Undefined index:/i,
  /syntax.*near/i,
  /You have an error in your SQL syntax/i,
  /mysql_fetch_array/i,
  /mysql_num_rows/i,
];

/**
 * Generic application error patterns
 */
export const APPLICATION_ERROR_PATTERNS = [
  /internal server error/i,
  /500 Internal Server Error/i,
  /runtime error/i,
  /fatal error/i,
  /exception/i,
  /stack trace/i,
  /error in your application/i,
];

/**
 * Stack trace patterns (information disclosure)
 */
export const STACK_TRACE_PATTERNS = [
  // Python
  /Traceback \(most recent call last\)/i,
  /File ".*?", line \d+/i,

  // Java
  /at java\./i,
  /at javax\./i,
  /at org\./i,
  /\.java:\d+\)/i,
  /Exception in thread/i,

  // .NET
  /at System\./i,
  /\.cs:line \d+/i,
  /Server Error in '\/'/i,

  // PHP
  /Fatal error:/i,
  /Warning:/i,
  /on line \d+ in/i,
  /Call Stack:/i,

  // Node.js
  /at [A-Za-z]+\s+\(.*?:\d+:\d+\)/i,
  /at Module\./i,
];

/**
 * Sensitive path disclosure patterns
 */
export const PATH_DISCLOSURE_PATTERNS = [
  // Windows paths
  /[A-Z]:\\[^<>"']+/i,
  /\\\\[A-Za-z0-9_.-]+\\/i,

  // Unix paths
  /\/(?:home|usr|var|etc)\/[^\s<>"']+/i,
  /\/[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+\//i,
];

/**
 * Database error patterns
 */
export const DATABASE_ERROR_PATTERNS = [
  /database error/i,
  /db error/i,
  /connection.*?failed/i,
  /could not connect/i,
  /unable to connect/i,
  /access denied for user/i,
];

/**
 * Authentication error patterns
 */
export const AUTH_ERROR_PATTERNS = [
  /authentication failed/i,
  /invalid credentials/i,
  /access denied/i,
  /unauthorized/i,
  /permission denied/i,
  /insufficient privileges/i,
];

/**
 * Command injection detection patterns
 */
export const COMMAND_INJECTION_ERROR_PATTERNS = [
  /sh: .*?: command not found/i,
  /bash: .*?: command not found/i,
  /is not recognized as an internal or external command/i,
  /cannot execute/i,
];

/**
 * All error patterns combined
 */
export const ALL_ERROR_PATTERNS = [
  ...SQL_ERROR_PATTERNS,
  ...APPLICATION_ERROR_PATTERNS,
  ...STACK_TRACE_PATTERNS,
  ...PATH_DISCLOSURE_PATTERNS,
  ...DATABASE_ERROR_PATTERNS,
  ...AUTH_ERROR_PATTERNS,
  ...COMMAND_INJECTION_ERROR_PATTERNS,
];

/**
 * Check if text contains error patterns
 */
export function containsErrorPattern(text: string): boolean {
  return ALL_ERROR_PATTERNS.some((pattern) => pattern.test(text));
}

/**
 * Find all matching error patterns
 */
export function findErrorPatterns(text: string): { pattern: RegExp; matches: string[] }[] {
  const results: { pattern: RegExp; matches: string[] }[] = [];

  for (const pattern of ALL_ERROR_PATTERNS) {
    const matches = text.match(pattern);
    if (matches && matches.length > 0) {
      results.push({ pattern, matches });
    }
  }

  return results;
}

/**
 * Check if text contains error patterns (permissive mode)
 */
export function containsErrorPatternPermissive(text: string): boolean {
  return containsErrorPattern(text) || BWAPP_SQL_PATTERNS.some((pattern) => pattern.test(text));
}

/**
 * Categorize error type
 */
export function categorizeError(text: string): string | null {
  if (SQL_ERROR_PATTERNS.some((p) => p.test(text))) return 'SQL Error';
  if (STACK_TRACE_PATTERNS.some((p) => p.test(text))) return 'Stack Trace';
  if (PATH_DISCLOSURE_PATTERNS.some((p) => p.test(text))) return 'Path Disclosure';
  if (DATABASE_ERROR_PATTERNS.some((p) => p.test(text))) return 'Database Error';
  if (AUTH_ERROR_PATTERNS.some((p) => p.test(text))) return 'Authentication Error';
  if (COMMAND_INJECTION_ERROR_PATTERNS.some((p) => p.test(text))) return 'Command Injection';
  if (APPLICATION_ERROR_PATTERNS.some((p) => p.test(text))) return 'Application Error';

  return null;
}
