#!/usr/bin/env node

/*
 * Produces a transparent, non-blocking full dependency audit report. The
 * runtime-dependency audit remains a release gate because those are the
 * packages shipped to consumers.
 */

const { spawnSync } = require('node:child_process');
const { appendFileSync, writeFileSync } = require('node:fs');
const { resolve } = require('node:path');

const outputPath = resolve(process.env.AUDIT_REPORT_OUTPUT ?? 'dependency-audit-report.json');
const [command, args] =
  process.platform === 'win32'
    ? [process.env.ComSpec ?? 'cmd.exe', ['/d', '/s', '/c', 'npm audit --json']]
    : ['npm', ['audit', '--json']];
const audit = spawnSync(command, args, {
  encoding: 'utf8',
  stdio: ['ignore', 'pipe', 'pipe'],
});

if (audit.error) {
  throw audit.error;
}

let report;
try {
  report = JSON.parse(audit.stdout);
} catch (error) {
  const details = audit.stderr.trim();
  throw new Error(`npm audit did not return JSON: ${details}`, { cause: error });
}

writeFileSync(outputPath, `${JSON.stringify(report, null, 2)}\n`);

const vulnerabilities = report.metadata?.vulnerabilities;
if (!vulnerabilities) {
  throw new Error('npm audit JSON did not include vulnerability metadata.');
}

const total = vulnerabilities.total ?? 0;
const summary = [
  `Full dependency audit: ${total} finding(s)`,
  `critical=${vulnerabilities.critical ?? 0}`,
  `high=${vulnerabilities.high ?? 0}`,
  `moderate=${vulnerabilities.moderate ?? 0}`,
  `low=${vulnerabilities.low ?? 0}`,
].join(', ');
console.log(summary);
console.log(`Detailed JSON report: ${outputPath}`);

if (process.env.GITHUB_STEP_SUMMARY) {
  appendFileSync(
    process.env.GITHUB_STEP_SUMMARY,
    [
      '## Full dependency audit (informational)',
      '',
      `- Findings: **${total}** (critical: ${vulnerabilities.critical ?? 0}, high: ${
        vulnerabilities.high ?? 0
      }, moderate: ${vulnerabilities.moderate ?? 0}, low: ${vulnerabilities.low ?? 0})`,
      '- The blocking runtime audit covers dependencies shipped to package consumers.',
      '- This full report keeps upstream development-tooling advisories visible until compatible fixes exist.',
      '',
    ].join('\n')
  );
}
