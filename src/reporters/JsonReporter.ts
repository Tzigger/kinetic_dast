import * as fs from 'fs';
import * as path from 'path';

import { ReportFormat } from '../types/enums';
import { ScanResult } from '../types/scan-result';

import { BaseReporter } from './base/IReporter';

export class JsonReporter extends BaseReporter {
  getFormat() {
    return ReportFormat.JSON;
  }

  override async generate(result: ScanResult): Promise<void> {
    const dir = this.options.outputDir;
    const fileName = (this.options.fileNameTemplate || 'scan-{{scanId}}.json').replace(
      /\{\{scanId\}\}/g,
      result.scanId
    );
    const outPath = path.join(dir, fileName);
    await fs.promises.mkdir(path.dirname(outPath), { recursive: true });
    await fs.promises.writeFile(outPath, JSON.stringify(result, null, 2), 'utf-8');
  }
}
