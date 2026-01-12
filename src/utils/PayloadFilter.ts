/**
 * PayloadFilter - Filters out destructive payloads for safe mode operation
 *
 * Prevents injection of payloads that could:
 * - Modify, delete, or corrupt data (DROP, DELETE, TRUNCATE, etc)
 * - Execute system commands (xp_cmdshell, system(), etc)
 * - Cause denial of service
 * - Expose sensitive operations
 */

import { LogLevel } from '../types/enums';

import { Logger } from './logger/Logger';

/**
 * Destructive keywords that indicate payloads which could damage data
 */
const DESTRUCTIVE_KEYWORDS = [
  // SQL Commands
  'DROP',
  'DELETE',
  'TRUNCATE',
  'ALTER',
  'CREATE',
  'INSERT',
  'UPDATE',
  'EXEC',
  'EXECUTE',
  'GRANT',
  'REVOKE',

  // System Command Execution
  'xp_',
  'xp_cmdshell',
  'xp_dirtree',
  'system()',
  'exec(',
  'shell_exec',
  'proc_open',
  'passthru',
  'popen',
  'eval',

  // File Operations
  'INTO OUTFILE',
  'INTO DUMPFILE',
  'LOAD_FILE',
  'chmod',
  'mkdir',
  'rmdir',
  'unlink',
  'fopen',
  'fwrite',
  'file_put_contents',

  // Process Control
  'waitfor',
  'sleep',
  'benchmark',
  'randomblob',

  // Dangerous Functions
  'load_file',
  'into outfile',
  'copy',
  'COPY TO',
];

/**
 * Dangerous patterns that should be blocked in safe mode
 */
const DANGEROUS_PATTERNS = [
  // DROP statements
  /DROP\s+(TABLE|DATABASE|SCHEMA|INDEX|TRIGGER|PROCEDURE|FUNCTION)/i,

  // DELETE operations
  /DELETE\s+FROM\s+\w+/i,

  // TRUNCATE operations
  /TRUNCATE\s+(TABLE\s+)?\w+/i,

  // ALTER TABLE operations that modify schema
  /ALTER\s+TABLE\s+\w+\s+(DROP|MODIFY|CHANGE|RENAME)/i,

  // INSERT/UPDATE that might be destructive
  /INSERT\s+INTO\s+\w+\s*\(/i,
  /UPDATE\s+\w+\s+SET/i,

  // System execution
  /xp_cmdshell|xp_dirtree|xp_regread|xp_regwrite/i,

  // Shell commands
  /shell_exec|system\(|passthru\(|exec\(|proc_open|popen/i,

  // Dangerous SQL functions
  /INTO\s+OUTFILE|INTO\s+DUMPFILE|LOAD_FILE|COPY\s+TO/i,

  // Privilege escalation
  /GRANT\s+ALL|REVOKE\s+ALL|WITH\s+GRANT\s+OPTION/i,
];

/**
 * Payloads that are generally safe to test (informational only)
 * Note: Kept as reference for future enhancement
 */
// const SAFE_PAYLOAD_PATTERNS = [
//   // SQL injection detection (non-destructive)
//   /^'?\s*(OR|AND)\s+['"]?\d['"]?\s*=\s*['"]?\d['"]?/i,
//   // ... additional patterns
// ];

export class PayloadFilter {
  private logger: Logger;

  constructor(logLevel: LogLevel = LogLevel.INFO) {
    this.logger = new Logger(logLevel, 'PayloadFilter');
  }

  /**
   * Check if a payload is safe to inject (doesn't contain destructive operations)
   */
  public isSafe(payload: string): boolean {
    if (!payload) return true;

    // Check against dangerous patterns
    for (const pattern of DANGEROUS_PATTERNS) {
      if (pattern.test(payload)) {
        this.logger.debug(`Blocked destructive payload: ${payload.substring(0, 50)}...`);
        return false;
      }
    }

    return true;
  }

  /**
   * Filter out destructive payloads from a list
   */
  public filterPayloads(payloads: string[]): string[] {
    const safe = payloads.filter((payload) => this.isSafe(payload));

    if (safe.length < payloads.length) {
      const blocked = payloads.length - safe.length;
      this.logger.info(
        `Filtered out ${blocked} destructive payload(s) in safe mode. ` +
          `(${safe.length}/${payloads.length} payloads remain safe)`
      );
    }

    return safe;
  }

  /**
   * Get all destructive keywords as a regex
   */
  public getDestructiveKeywordsRegex(): RegExp {
    const escaped = DESTRUCTIVE_KEYWORDS.map((k) => k.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'));
    return new RegExp(`\\b(${escaped.join('|')})\\b`, 'i');
  }

  /**
   * Check if payload contains destructive keywords
   */
  public containsDestructiveKeywords(payload: string): boolean {
    return this.getDestructiveKeywordsRegex().test(payload);
  }

  /**
   * Categorize payload safety
   */
  public getSafetyLevel(payload: string): 'safe' | 'warning' | 'dangerous' {
    if (!this.isSafe(payload)) {
      return 'dangerous';
    }

    if (this.containsDestructiveKeywords(payload)) {
      return 'warning';
    }

    return 'safe';
  }

  /**
   * Get filtering statistics
   */
  public getFilterStats(originalPayloads: string[]): {
    total: number;
    safe: number;
    dangerous: number;
    warning: number;
  } {
    let safe = 0;
    let dangerous = 0;
    let warning = 0;

    for (const payload of originalPayloads) {
      const level = this.getSafetyLevel(payload);
      if (level === 'safe') safe++;
      else if (level === 'dangerous') dangerous++;
      else if (level === 'warning') warning++;
    }

    return {
      total: originalPayloads.length,
      safe,
      dangerous,
      warning,
    };
  }
}
