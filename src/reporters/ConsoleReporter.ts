import chalk from 'chalk';
import ora from 'ora';

import { ScanResult, ScanConfiguration } from '../types';
import { ReportFormat } from '../types/enums';
import { Vulnerability } from '../types/vulnerability';

import { BaseReporter } from './base/IReporter';

export class ConsoleReporter extends BaseReporter {
  private spinner = ora({ spinner: 'dots' });
  private vulnCount = 0;

  getFormat(): ReportFormat {
    return ReportFormat.CONSOLE;
  }

  override async onScanStarted(scanId: string, config: ScanConfiguration): Promise<void> {
    this.config = config; // Store config for later use
    this.spinner.start(`Starting scan ${scanId} on ${config.target.url}`);
    return Promise.resolve();
  }

  override async onScannerStarted(scannerType: string): Promise<void> {
    this.spinner.text = `Running scanner: ${scannerType}`;
    return Promise.resolve();
  }

  override async onVulnerability(v: Vulnerability): Promise<void> {
    this.vulnCount += 1;
    const sev = v.severity.toUpperCase();
    const sevColor =
      String(v.severity) === 'critical'
        ? chalk.bgRed.white
        : String(v.severity) === 'high'
          ? chalk.red
          : String(v.severity) === 'medium'
            ? chalk.yellow
            : String(v.severity) === 'low'
              ? chalk.blue
              : chalk.gray;
    this.spinner.stop();
    // eslint-disable-next-line no-console
    console.log(`${sevColor(` ${sev} `)} ${chalk.bold(v.title)} ${chalk.gray(`(${v.category})`)}`);
    this.spinner.start();
    return Promise.resolve();
  }

  override async onScannerCompleted(scannerType: string): Promise<void> {
    this.spinner.text = `Completed: ${scannerType}`;
    return Promise.resolve();
  }

  override async onScanCompleted(result: ScanResult): Promise<void> {
    this.spinner.stop();
    const s = result.summary;
    // eslint-disable-next-line no-console
    console.log(
      chalk.bold(`\nScan complete in ${result.duration}ms: `) +
        `${s.total} vulns (C:${s.critical} H:${s.high} M:${s.medium} L:${s.low} I:${s.info})\n`
    );
    return Promise.resolve();
  }
}
