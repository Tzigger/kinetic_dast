#!/usr/bin/env node

/*
 * Enforces the complete ESLint policy on code changed from the target branch.
 *
 * Kinetic has pre-existing lint debt outside this pull request. Failing every
 * PR on that baseline would make the check non-actionable, but silently
 * disabling type-aware rules would be worse. This script lints each changed
 * TypeScript source file with the normal configuration and fails if a finding
 * lands on a line added or modified by the change set.
 */

const { execFileSync } = require('node:child_process');
const { existsSync, readFileSync } = require('node:fs');
const { relative, resolve } = require('node:path');
const { ESLint } = require('eslint');

function runGit(args) {
  try {
    return execFileSync('git', args, {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
    }).trim();
  } catch {
    return undefined;
  }
}

function resolveMergeBase() {
  const candidates = [process.env.LINT_BASE_REF, 'origin/main', 'main', 'HEAD^'].filter(Boolean);

  for (const candidate of candidates) {
    const mergeBase = runGit(['merge-base', candidate, 'HEAD']);
    if (mergeBase) {
      return mergeBase;
    }
  }

  return undefined;
}

function collectChangedLines(diff) {
  const changedLines = new Map();
  let currentFile;

  for (const line of diff.split(/\r?\n/)) {
    if (line.startsWith('+++ ')) {
      const path = line.slice(4);
      currentFile = path.startsWith('b/') ? path.slice(2) : undefined;
      continue;
    }

    const hunk = /^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@/.exec(line);
    if (!hunk || !currentFile) {
      continue;
    }

    const start = Number(hunk[1]);
    const count = hunk[2] === undefined ? 1 : Number(hunk[2]);
    if (count === 0) {
      continue;
    }

    const fileLines = changedLines.get(currentFile) ?? new Set();
    for (let lineNumber = start; lineNumber < start + count; lineNumber += 1) {
      fileLines.add(lineNumber);
    }
    changedLines.set(currentFile, fileLines);
  }

  return changedLines;
}

function collectEveryLine(file) {
  const lineCount = readFileSync(file, 'utf8').split(/\r?\n/).length;
  return new Set(Array.from({ length: lineCount }, (_, index) => index + 1));
}

async function main() {
  const mergeBase = resolveMergeBase();
  if (!mergeBase) {
    console.error('Unable to determine a lint baseline. Set LINT_BASE_REF to a reachable Git ref.');
    process.exitCode = 2;
    return;
  }

  const filesInDiff = (
    runGit(['diff', '--name-only', '--diff-filter=ACMR', mergeBase, '--', 'src']) ?? ''
  ).split(/\r?\n/);
  const untrackedFiles = (
    runGit(['ls-files', '--others', '--exclude-standard', '--', 'src']) ?? ''
  ).split(/\r?\n/);
  const changedFiles = [...new Set([...filesInDiff, ...untrackedFiles])].filter(
    (file) => file.endsWith('.ts') && existsSync(resolve(file))
  );

  if (changedFiles.length === 0) {
    console.log(`No TypeScript source changes since ${mergeBase.slice(0, 12)}.`);
    return;
  }

  const diff = runGit(['diff', '--unified=0', '--diff-filter=ACMR', mergeBase, '--', 'src']) ?? '';
  const changedLines = collectChangedLines(diff);
  for (const file of untrackedFiles) {
    if (file.endsWith('.ts') && existsSync(resolve(file))) {
      changedLines.set(file, collectEveryLine(file));
    }
  }
  const eslint = new ESLint();
  const results = await eslint.lintFiles(changedFiles);
  const violations = [];

  for (const result of results) {
    const repositoryPath = relative(process.cwd(), result.filePath).replace(/\\/g, '/');
    const lines = changedLines.get(repositoryPath);

    for (const message of result.messages) {
      if (!lines || message.fatal || message.line === undefined || lines.has(message.line)) {
        violations.push({ file: repositoryPath, ...message });
      }
    }
  }

  if (violations.length === 0) {
    console.log(
      `Changed-code lint passed for ${changedFiles.length} file(s) against ${mergeBase.slice(0, 12)}.`
    );
    return;
  }

  console.error(`Changed-code lint found ${violations.length} violation(s):`);
  for (const violation of violations) {
    const position = `${violation.file}:${violation.line ?? 0}:${violation.column ?? 0}`;
    const rule = violation.ruleId ? ` [${violation.ruleId}]` : '';
    console.error(`${position}${rule} ${violation.message}`);
  }
  process.exitCode = 1;
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
