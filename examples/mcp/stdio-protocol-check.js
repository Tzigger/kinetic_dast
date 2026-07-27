#!/usr/bin/env node
const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs');

const repoRoot = path.resolve(__dirname, '..', '..');
const serverPath = path.join(repoRoot, 'dist', 'cli', 'index.js');

if (!fs.existsSync(serverPath)) {
  console.error(`Server entrypoint not found at ${serverPath}`);
  console.error('Please run: npm run build');
  process.exit(1);
}

const child = spawn(process.execPath, [serverPath, '--mcp'], {
  cwd: repoRoot,
  stdio: ['pipe', 'pipe', 'pipe'],
});

let stdoutBuffer = '';
let stderrBuffer = '';
let completed = false;

child.stdout.on('data', (chunk) => {
  stdoutBuffer += chunk.toString();
});

child.stderr.on('data', (chunk) => {
  stderrBuffer += chunk.toString();
});

function sendRequest(request) {
  child.stdin.write(`${JSON.stringify(request)}\n`);
}

function validateStdoutLines() {
  const lines = stdoutBuffer
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);

  const parsed = [];
  const invalid = lines.filter((line) => {
    try {
      parsed.push(JSON.parse(line));
      return false;
    } catch {
      return true;
    }
  });

  return {
    lines,
    parsed,
    invalid,
  };
}

child.on('error', (error) => {
  console.error('Failed to start MCP server:', error.message);
  process.exit(1);
});

setTimeout(() => {
  sendRequest({
    jsonrpc: '2.0',
    id: 1,
    method: 'initialize',
    params: {
      protocolVersion: '2025-06-18',
      capabilities: {},
      clientInfo: { name: 'kinetic-mcp-protocol-check', version: '1.0.0' },
    },
  });
}, 500);

setTimeout(() => {
  sendRequest({ jsonrpc: '2.0', method: 'notifications/initialized' });
}, 750);

setTimeout(() => {
  sendRequest({ jsonrpc: '2.0', id: 2, method: 'tools/list' });
}, 1000);

setTimeout(() => {
  sendRequest({
    jsonrpc: '2.0',
    id: 3,
    method: 'tools/call',
    params: {
      name: 'passive_check',
      arguments: {
        url: 'http://localhost:3000',
        dryRun: true,
      },
    },
  });
}, 1250);

setTimeout(() => {
  child.kill();
  completed = true;
}, 3000);

setTimeout(() => {
  if (!completed) {
    child.kill();
  }

  const validation = validateStdoutLines();
  console.log('=== STDIO protocol check ===');
  console.log(`stdout lines: ${validation.lines.length}`);
  console.log(`stderr lines: ${stderrBuffer.split(/\r?\n/).filter(Boolean).length}`);
  console.log(`stdout invalid JSON lines: ${validation.invalid.length}`);

  if (validation.invalid.length > 0) {
    console.log('Invalid stdout content:');
    console.log(validation.invalid.join('\n'));
    process.exit(1);
  }

  const ids = validation.parsed.map((response) => response.id);
  const hasInitialize = validation.parsed.some(
    (response) => response.id === 1 && response.result?.protocolVersion === '2025-06-18'
  );
  const hasTools = validation.parsed.some(
    (response) => response.id === 2 && Array.isArray(response.result?.tools)
  );
  const hasToolResult = validation.parsed.some(
    (response) => response.id === 3 && Array.isArray(response.result?.content)
  );

  if (validation.parsed.length !== 3 || JSON.stringify(ids) !== JSON.stringify([1, 2, 3]) || !hasInitialize || !hasTools || !hasToolResult) {
    console.error('MCP handshake or tool responses were incomplete.');
    process.exit(1);
  }

  console.log('STDIO protocol and MCP lifecycle look valid.');
}, 3500);
