import * as fs from 'fs';
import * as path from 'path';

import Handlebars from 'handlebars';

import { ScanConfiguration } from '../types/config';
import { ReportFormat } from '../types/enums';
import { ScanResult } from '../types/scan-result';

import { BaseReporter, ReporterInitOptions } from './base/IReporter';

export class HtmlReporter extends BaseReporter {
  private template?: Handlebars.TemplateDelegate;

  getFormat(): ReportFormat {
    return ReportFormat.HTML;
  }

  override async init(config: ScanConfiguration, options: ReporterInitOptions): Promise<void> {
    await super.init(config, options);
    const candidateTemplates = [
      path.join(__dirname, 'templates', 'report.hbs'),
      // useful when running from source without copied assets
      path.join(process.cwd(), 'src', 'reporters', 'templates', 'report.hbs'),
    ];
    let source: string | undefined;
    for (const candidate of candidateTemplates) {
      try {
        source = await fs.promises.readFile(candidate, 'utf-8');
        break;
      } catch (_) {
        // continue to next candidate
      }
    }
    if (!source) {
      // Fallback minimal template
      source = `<!doctype html><html><head><meta charset="utf-8"/><title>DAST Report</title>
      <style>body{font-family:system-ui,Arial,sans-serif;padding:24px;color:#0f172a}
      .sev{padding:2px 6px;border-radius:4px;color:white;font-size:12px}
      .critical{background:#991b1b}.high{background:#dc2626}.medium{background:#d97706}
      .low{background:#2563eb}.info{background:#64748b}
      table{border-collapse:collapse;width:100%} td,th{border:1px solid #e2e8f0;padding:8px;vertical-align:top}
      th{background:#f1f5f9;text-align:left}
      details summary{cursor:pointer;color:#0f172a;font-weight:600}
      .details-box{background:#f8fafc;border:1px solid #e2e8f0;border-radius:6px;padding:8px;margin-top:6px;font-size:13px}
      .kv{margin:4px 0}
      .mono{font-family:SFMono-Regular,Menlo,Consolas,monospace}
      .block{background:#0f172a0d;padding:6px;border-radius:4px;max-height:160px;overflow:auto;white-space:pre-wrap;word-break:break-word}
      small{color:#64748b}</style></head>
      <body><h1>DAST Report</h1>
      <p><b>Target:</b> {{targetUrl}} | <b>Duration:</b> {{duration}}ms</p>
      <p><b>Total:</b> {{summary.total}} | C:{{summary.critical}} H:{{summary.high}} M:{{summary.medium}} L:{{summary.low}} I:{{summary.info}}</p>
      <h2>Findings</h2>
      <table><thead><tr><th>Severity</th><th>Title</th><th>Category</th><th>Confidence</th><th>URL</th><th>Details</th></tr></thead>
      <tbody>{{#each vulnerabilities}}
        <tr>
          <td><span class="sev {{severity}}">{{severity}}</span></td>
          <td>{{title}}<br/><small>{{description}}</small></td>
          <td>{{category}}</td>
          <td>{{confidence}}</td>
          <td>{{#if url}}{{url}}{{else}}{{location.url}}{{/if}}</td>
          <td><details><summary>View</summary><div class="details-box">
            {{#if timestamp}}<div class="kv"><b>Detected:</b> {{timestamp}}</div>{{/if}}
            {{#if evidence.source}}<div class="kv"><b>Source:</b> {{evidence.source}}</div>{{/if}}
            {{#if evidence.request.method}}<div class="kv"><b>Method:</b> {{evidence.request.method}}</div>{{/if}}
            <div class="kv"><b>Surface:</b> {{#if evidence.metadata.surfaceName}}{{evidence.metadata.surfaceName}}{{else}}n/a{{/if}}{{#if evidence.metadata.contextInfo.surfaceType}} ({{evidence.metadata.contextInfo.surfaceType}}){{/if}}</div>
            {{#if evidence.payloadUsed}}<div class="kv"><b>Payload:</b> <span class="mono">{{evidence.payloadUsed}}</span></div>{{else}}{{#if evidence.payload}}<div class="kv"><b>Payload:</b> <span class="mono">{{evidence.payload}}</span></div>{{else}}{{#if evidence.metadata.payload}}<div class="kv"><b>Payload:</b> <span class="mono">{{evidence.metadata.payload}}</span></div>{{else}}{{#if evidence.request.body}}<div class="kv"><b>Payload:</b> <span class="mono">{{evidence.request.body}}</span></div>{{else}}{{#if evidence.element.payload}}<div class="kv"><b>Payload:</b> <span class="mono">{{evidence.element.payload}}</span></div>{{/if}}{{/if}}{{/if}}{{/if}}{{/if}}
            {{#if evidence.metadata.contextInfo.injectionContext}}<div class="kv"><b>Context:</b> {{evidence.metadata.contextInfo.injectionContext}}</div>{{/if}}
            {{#if evidence.request.url}}<div class="kv"><b>Request URL:</b> {{evidence.request.url}}</div>{{/if}}
            {{#if evidence.request.body}}<div class="kv"><b>Request Body:</b></div><pre class="block">{{evidence.request.body}}</pre>{{/if}}
            {{#if evidence.response.snippet}}<div class="kv"><b>Response Snippet:</b></div><pre class="block">{{evidence.response.snippet}}</pre>{{else}}{{#if evidence.response.body}}<div class="kv"><b>Response Body:</b></div><pre class="block">{{evidence.response.body}}</pre>{{/if}}{{/if}}
          </div></details></td>
        </tr>
      {{/each}}</tbody></table></body></html>`;
    }
    this.template = Handlebars.compile(source);
  }

  override async generate(result: ScanResult): Promise<void> {
    if (!this.template) return;
    const html = this.template(result);
    const dir = this.options.outputDir;
    const fileName = (this.options.fileNameTemplate || 'scan-{{scanId}}.html').replace(
      /\{\{scanId\}\}/g,
      result.scanId
    );
    const outPath = path.join(dir, fileName);
    await fs.promises.mkdir(path.dirname(outPath), { recursive: true });
    await fs.promises.writeFile(outPath, html, 'utf-8');
  }
}
