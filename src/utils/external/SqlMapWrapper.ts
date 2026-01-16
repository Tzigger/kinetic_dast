import { spawn } from 'child_process';
import { Logger } from '../logger/Logger';
import { LogLevel } from '../../types/enums';

export interface SqlMapOptions {
  url: string;
  method?: string;
  data?: string;
  cookie?: string;
  headers?: Record<string, string>;
  batch?: boolean;
  risk?: number;
  level?: number;
}

export interface SqlMapVulnerability {
  parameter: string;
  type: string;
  title: string;
  payload: string;
}

export interface SqlMapResult {
  success: boolean;
  vulnerabilities: SqlMapVulnerability[];
  rawOutput: string;
}

export class SqlMapWrapper {
  private logger: Logger;
  private executable: string = 'sqlmap';

  constructor() {
    this.logger = new Logger(LogLevel.INFO, 'SqlMapWrapper');
  }

  public async scan(options: SqlMapOptions): Promise<SqlMapResult> {
    return new Promise((resolve) => {
      // Build sqlmap command
      const args: string[] = [];

      // Add URL - for REST APIs, add a test marker if none exists
      let targetUrl = options.url;
      if (!targetUrl.includes('?') && !options.data) {
        // For REST-style APIs like /users/v1/admin, sqlmap needs a testable point
        // Add * marker directly to the last path segment (not as a new segment)
        if (targetUrl.endsWith('/')) {
          // URL like /users/v1/ - add test value with marker
          targetUrl = targetUrl + 'test*';
        } else {
          // URL like /users/v1/admin - append marker to existing value
          targetUrl = targetUrl + '*';
        }
      }
      args.push('-u', targetUrl);

      // Batch mode (non-interactive)
      args.push('--batch');

      // Method
      if (options.method && options.method.toUpperCase() !== 'GET') {
        args.push(`--method=${options.method}`);
      }

      // Data for POST requests
      if (options.data) {
        args.push(`--data=${options.data}`);
      }

      // Cookies
      if (options.cookie) {
        args.push(`--cookie=${options.cookie}`);
      }

      // Risk and Level for thoroughness
      args.push(`--risk=${options.risk || 2}`);
      args.push(`--level=${options.level || 2}`);

      // Threads for faster execution (but not too fast to miss vulns)
      args.push('--threads=3');
      args.push('--timeout=15');

      // Output controls - removed -o flag (optimization was skipping tests)
      args.push('--disable-coloring');
      args.push('--flush-session'); // Fresh scan each time
      args.push('-v', '1'); // Verbose level for debugging

      this.logger.info(`Starting sqlmap scan for ${options.url}`);
      this.logger.debug(`Command: sqlmap ${args.join(' ')}`);

      const process = spawn(this.executable, args);
      let output = '';

      process.stdout.on('data', (data) => {
        const chunk = data.toString();
        output += chunk;
        // Log important lines for debugging
        if (
          chunk.includes('injectable') ||
          chunk.includes('vulnerable') ||
          chunk.includes('Parameter:')
        ) {
          this.logger.info(`[SQLMAP] ${chunk.trim()}`);
        }
      });

      process.stderr.on('data', (data) => {
        output += data.toString();
      });

      process.on('close', (code) => {
        this.logger.info(`sqlmap finished with code ${code}`);
        
        const vulnerabilities = this.parseOutput(output);

        if (vulnerabilities.length > 0) {
          this.logger.info(`Found ${vulnerabilities.length} SQL injection vulnerabilities!`);
        }

        resolve({
          success: code === 0,
          vulnerabilities,
          rawOutput: output,
        });
      });

      process.on('error', (err) => {
        this.logger.error(`Failed to start sqlmap: ${err.message}`);
        resolve({
          success: false,
          vulnerabilities: [],
          rawOutput: err.message,
        });
      });
    });
  }

  private parseOutput(output: string): SqlMapVulnerability[] {
    const vulns: SqlMapVulnerability[] = [];
    const lines = output.split('\n');

    let currentParam = '';
    let currentType = '';
    let currentTitle = '';

    for (const rawLine of lines) {
      const line = rawLine.trim();

      // Standard sqlmap vulnerability report format
      if (line.startsWith('Parameter:')) {
        currentParam = line.substring('Parameter:'.length).trim();
        currentType = '';
        currentTitle = '';
      } else if (line.startsWith('Type:')) {
        currentType = line.substring('Type:'.length).trim();
      } else if (line.startsWith('Title:')) {
        currentTitle = line.substring('Title:'.length).trim();
      } else if (line.startsWith('Payload:')) {
        const payload = line.substring('Payload:'.length).trim();

        if (currentParam && currentType) {
          vulns.push({
            parameter: currentParam,
            type: currentType,
            title: currentTitle || currentType,
            payload: payload,
          });
        }
      }

      // Catch heuristic findings like "might be injectable"
      // Format: "[INFO] heuristic (basic) test shows that URI parameter '#1*' might be injectable (possible DBMS: 'SQLite')"
      if (line.includes('might be injectable')) {
        // Match patterns like "parameter '#1*' might be injectable" or "URI parameter '#1*' might be injectable"
        const paramMatch = line.match(/parameter\s+'([^']+)'\s+might be injectable/i);
        const param = paramMatch?.[1] ?? 'unknown';
        const dbmsMatch = line.match(/possible DBMS:\s+'([^']+)'/);
        const dbms = dbmsMatch?.[1] ?? 'Unknown';

        // Try to find the probe payload that caused this detection
        // sqlmap uses heuristic payloads like: ) AND 5351=5351 AND (
        const probePayload = `' AND 1=1-- (${dbms} probe)`;

        vulns.push({
          parameter: param,
          type: 'Heuristic Detection',
          title: `Potential SQL Injection (${dbms})`,
          payload: probePayload,
        });
      }

      // Catch "appears to be injectable" confirmations
      // Format: "[INFO] URI parameter '#1*' appears to be 'SQLite AND boolean-based blind...' injectable"
      if (line.includes("appears to be") && line.includes("injectable")) {
        const confirmMatch = line.match(/parameter\s+'([^']+)'\s+appears to be\s+'([^']+)'\s+injectable/i);
        if (confirmMatch && confirmMatch[1] && confirmMatch[2]) {
          // Extract technique info for payload
          const technique = confirmMatch[2];
          let samplePayload = '';
          
          // Generate representative payload based on technique
          if (technique.includes('boolean-based')) {
            samplePayload = "' AND 1=1 AND 'a'='a";
          } else if (technique.includes('time-based')) {
            samplePayload = "'; WAITFOR DELAY '0:0:5'--";
          } else if (technique.includes('error-based')) {
            samplePayload = "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(0x71,(SELECT database()),0x71,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--";
          } else if (technique.includes('UNION')) {
            samplePayload = "' UNION SELECT NULL,NULL,NULL--";
          } else {
            samplePayload = `[${technique}]`;
          }

          vulns.push({
            parameter: confirmMatch[1],
            type: technique,
            title: `SQL Injection Confirmed: ${technique}`,
            payload: samplePayload,
          });
        }
      }
    }

    // Deduplicate by parameter + type
    const seen = new Set<string>();
    return vulns.filter((v) => {
      const key = `${v.parameter}-${v.type}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
  }
}
