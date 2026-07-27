# MCP configuration example for Kinetic DAST

This folder contains example configuration files for running the Kinetic DAST MCP server from AI clients such as Cursor or Claude Desktop.

## Prerequisites

- Node.js 18+
- Dependencies installed in the repository:

```bash
npm install
```

## Start the MCP server

From the repository root, run:

```bash
node dist/cli/index.js --mcp
```

If you prefer the TypeScript entrypoint during development:

```bash
npx ts-node src/cli/index.ts --mcp
```

## Cursor configuration

Create or edit the Cursor MCP configuration file and add a server entry like this:

```json
{
  "mcpServers": {
    "kinetic-dast": {
      "command": "node",
      "args": [
        "/absolute/path/to/kinetic_dast-main/dist/cli/index.js",
        "--mcp"
      ]
    }
  }
}
```

> Replace `/absolute/path/to/kinetic_dast-main` with your actual repository path.

## Claude Desktop configuration

In Claude Desktop, add a similar MCP server entry in the configuration file:

```json
{
  "mcpServers": {
    "kinetic-dast": {
      "command": "node",
      "args": [
        "/absolute/path/to/kinetic_dast-main/dist/cli/index.js",
        "--mcp"
      ]
    }
  }
}
```

> Replace `/absolute/path/to/kinetic_dast-main` with your actual repository path.

## Configuration file locations

- **Cursor**: `~/.cursor/mcp.json` (macOS/Linux) or `%APPDATA%\Cursor\mcp.json` (Windows)
- **Claude Desktop**: `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or `%APPDATA%\Claude\claude_desktop_config.json` (Windows)

## Smoke test scripts

Three lightweight verification scripts are available:

- Node.js smoke test: [smoke-test.js](smoke-test.js)
- PowerShell smoke test: [smoke-test.ps1](smoke-test.ps1)
- STDIO protocol checker: [stdio-protocol-check.js](stdio-protocol-check.js)

Run the Node.js smoke test with:

```bash
node examples/mcp/smoke-test.js
```

Run the protocol checker with:

```bash
node examples/mcp/stdio-protocol-check.js
```

Or the PowerShell version with:

```powershell
powershell -ExecutionPolicy Bypass -File .\examples\mcp\smoke-test.ps1
```

## Notes

- The server follows the MCP initialization lifecycle. MCP clients handle this automatically; raw stdio clients must send `initialize` followed by `notifications/initialized` before `tools/list` or `tools/call`.
- Supported tools include `passive_check`, `targeted_scan`, `probe_json_endpoint`, and `scan_changed_routes`.
- You can supply optional `headers`, `cookies`, `authToken`, `dryRun`, `allowedHosts`, `allowedPaths`, and `scope` values to tailor the request and enforce scope. Header, cookie, token, and raw response-body values are never echoed in tool results.
- Networked tools on non-local targets require `allowRemote: true`. Production targets additionally require `confirmProduction: true`. `scan_changed_routes` creates a local plan and never contacts the target. Remote `targeted_scan` and `probe_json_endpoint` calls also require `allowedHosts` plus `allowedPaths` (or `scope.include`).
- `probe_json_endpoint` sends one supplied JSON object with POST and passively assesses the request/response pair; it does not fuzz the body. If `allowedMethods` is supplied to that tool, it must include `POST`.
- The server is intentionally conservative and blocks dangerous actions unless the scope and guardrails allow them.
