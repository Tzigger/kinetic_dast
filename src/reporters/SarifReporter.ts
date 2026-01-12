import * as fs from 'fs';
import * as path from 'path';

import { ReportFormat } from '../types/enums';
import { ScanResult } from '../types/scan-result';

import { BaseReporter } from './base/IReporter';

export class SarifReporter extends BaseReporter {
  getFormat(): ReportFormat {
    return ReportFormat.SARIF;
  }

  override async generate(result: ScanResult): Promise<void> {
    const sarif = this.toSarif(result);
    const dir = this.options.outputDir;
    const fileName = (this.options.fileNameTemplate || 'scan-{{scanId}}.sarif').replace(
      /\{\{scanId\}\}/g,
      result.scanId
    );
    const outPath = path.join(dir, fileName);
    await fs.promises.mkdir(path.dirname(outPath), { recursive: true });
    await fs.promises.writeFile(outPath, JSON.stringify(sarif, null, 2), 'utf-8');
  }

  private toSarif(result: ScanResult): Record<string, unknown> {
    const toolName = 'kinetic';
    const rulesMap: Record<string, unknown> = {};
    const results = result.vulnerabilities.map((v, idx) => {
      const ruleId = v.cwe || v.category || `VULN-${idx}`;
      if (!rulesMap[ruleId]) {
        rulesMap[ruleId] = {
          id: ruleId,
          name: v.title,
          shortDescription: { text: v.title },
          fullDescription: { text: v.description || v.title },
          help: { text: v.remediation || '' },
          properties: { category: v.category, severity: v.severity },
        };
      }
      const payload =
        v.evidence?.payload ||
        (v.evidence?.metadata ? v.evidence.metadata['payload'] : undefined) ||
        v.evidence?.request?.body ||
        v.evidence?.element?.payload;

      return {
        ruleId,
        level: this.severityToSarif(v.severity),
        message: { text: v.title },
        properties: payload ? { payload } : undefined,
        locations: [
          {
            physicalLocation: {
              artifactLocation: { uri: v.url || result.targetUrl },
            },
          },
        ],
      };
    });

    return {
      $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
      version: '2.1.0',
      runs: [
        {
          tool: {
            driver: {
              name: toolName,
              rules: Object.values(rulesMap),
            },
          },
          results,
        },
      ],
    };
  }

  private severityToSarif(sev: unknown): 'error' | 'warning' | 'note' {
    if (sev === 'critical' || sev === 'high') return 'error';
    if (sev === 'medium') return 'warning';
    return 'note';
  }
}
