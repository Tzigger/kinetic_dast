# Usage examples for Kinetic DAST MCP

These examples show how to invoke the MCP tools from an AI client that supports MCP tools.

## Example 1: passive security check on a local app

```json
{
  "name": "passive_check",
  "arguments": {
    "url": "http://localhost:3000",
    "dryRun": true
  }
}
```

## Example 2: targeted active scan on a local endpoint

```json
{
  "name": "targeted_scan",
  "arguments": {
    "url": "http://localhost:3000/login",
    "maxPages": 2,
    "maxDepth": 1,
    "scope": {
      "include": ["/login", "/api/auth"],
      "stayOnDomain": true
    }
  }
}
```

## Example 3: probe a JSON endpoint with a payload

```json
{
  "name": "probe_json_endpoint",
  "arguments": {
    "url": "http://localhost:3000/api/search",
    "body": {"q":"test"},
    "headers": {
      "X-Test-Header": "demo"
    },
    "cookies": {
      "session": "demo"
    },
    "authToken": "demo-token",
    "allowedHosts": ["localhost"],
    "allowedPaths": ["/api/search"],
    "allowedMethods": ["POST"],
    "scope": {
      "include": ["/api/search"],
      "stayOnDomain": true
    }
  }
}
```

## Example 4: create a dry-run scan plan for changed routes

```json
{
  "name": "scan_changed_routes",
  "arguments": {
    "url": "http://localhost:3000",
    "changedFiles": ["/api/login", "/api/logout"],
    "dryRun": true,
    "allowedHosts": ["localhost"],
    "allowedPaths": ["/api"],
    "scope": {
      "stayOnDomain": true
    }
  }
}
```

## Cursor / Copilot / Claude Desktop integration notes

- Cursor, Copilot and Claude Desktop can connect to the MCP server over stdio.
- Use the config example in [examples/mcp/cursor-claude-config.json](cursor-claude-config.json).
- The server returns structured results with:
  - `status`
  - `summary`
  - `findings`
  - `guardrails`
  - `metadata`
