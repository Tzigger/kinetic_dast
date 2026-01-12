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
      const args = ['-u', options.url, '--batch'];

      if (options.method) args.push(`--method=${options.method}`);
      if (options.data) args.push(`--data=${options.data}`);
      if (options.cookie) args.push(`--cookie=${options.cookie}`);
      if (options.risk) args.push(`--risk=${options.risk}`);
      if (options.level) args.push(`--level=${options.level}`);

      // Optimization: Disable banner, beep, etc.
      args.push('--banner', '--disable-coloring');

      this.logger.info(`Starting sqlmap scan for ${options.url}`);

      const process = spawn(this.executable, args);
      let output = '';

      process.stdout.on('data', (data) => {
        const chunk = data.toString();
        output += chunk;
      });

      process.stderr.on('data', (data) => {
        output += data.toString();
      });

      process.on('close', (code) => {
        this.logger.info(`sqlmap finished with code ${code}`);
        const vulnerabilities = this.parseOutput(output);
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
    }

    return vulns;
  }
}
