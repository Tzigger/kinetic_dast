#!/usr/bin/env node
const { spawn } = require('child_process');
const path = require('path');

const repoRoot = path.resolve(__dirname, '..', '..');
const serverPath = path.join(repoRoot, 'dist', 'cli', 'index.js');

if (!require('fs').existsSync(serverPath)) {
  console.error(`Server entrypoint not found at ${serverPath}`);
  console.error('Please run: npm run build');
  process.exit(1);
}

const child = spawn(process.execPath, [serverPath, '--mcp'], {
  cwd: repoRoot,
  stdio: ['pipe', 'pipe', 'inherit'],
});

let buffer = '';

function sendRequest(request) {
  child.stdin.write(`${JSON.stringify(request)}\n`);
}

child.stdout.on('data', (chunk) => {
  buffer += chunk.toString();
  const lines = buffer.split('\n');
  buffer = lines.pop() || '';

  for (const line of lines) {
    if (!line.trim()) continue;
 try {
      const parsed = JSON.parse(line);
      console.log(JSON.stringify(parsed, null, 2));
    } catch (error) {
      // Skip non-JSON lines (logs, etc.)
      if (!line.startsWith('{') && !line.startsWith('[')) {
        continue;
      }
      console.error('Failed to parse response:', line);
    }
  }
});

child.on('error', (error) => {
  console.error('Failed to start MCP server:', error.message);
  process.exit(1);
});

child.on('exit', (code, signal) => {
  if (code !== 0 && signal !== 'SIGTERM') {
    console.error(`MCP server exited with code ${code}`);
  }
});

setTimeout(() => {
  sendRequest({
    jsonrpc: '2.0',
    id: 1,
    method: 'initialize',
    params: {
      protocolVersion: '2025-06-18',
      capabilities: {},
      clientInfo: { name: 'kinetic-mcp-smoke-test', version: '1.0.0' },
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
}, 3000);
