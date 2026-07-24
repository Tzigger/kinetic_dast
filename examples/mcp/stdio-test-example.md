# STDIO test example for Kinetic DAST MCP

This example sends the MCP lifecycle handshake and then invokes Kinetic over stdio. MCP desktop clients perform the lifecycle automatically; include it when testing the raw protocol yourself.

## 1. Start the server

From the repository root:

```bash
node dist/cli/index.js --mcp
```

## 2. Initialize the MCP session

```json
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"manual-test","version":"1.0.0"}}}
```

After the server replies, send this notification (it has no response):

```json
{"jsonrpc":"2.0","method":"notifications/initialized"}
```

## 3. List tools and invoke one

```json
{"jsonrpc":"2.0","id":2,"method":"tools/list"}
```

```json
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"passive_check","arguments":{"url":"http://localhost:3000","dryRun":true}}}
```

A scoped local active scan can be requested like this:

```json
{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"targeted_scan","arguments":{"url":"http://localhost:3000/login","maxPages":2,"maxDepth":1,"scope":{"include":["/login","/api/auth"],"stayOnDomain":true}}}}
```

The JSON probe posts exactly one JSON object and passively assesses the resulting request/response pair:

```json
{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"probe_json_endpoint","arguments":{"url":"http://localhost:3000/api/search","body":{"q":"test"},"headers":{"X-Test-Header":"demo"},"cookies":{"session":"demo"},"authToken":"demo-token","allowedMethods":["POST"],"scope":{"include":["/api/search"],"stayOnDomain":true}}}}
```

For remote active scans and JSON probes, add `allowRemote: true`, `allowedHosts`, and `allowedPaths` (or `scope.include`). Production targets also require `confirmProduction: true`.

## Expected tool response

Each successful `tools/call` returns standard MCP `content` plus `structuredContent` for a pipeline to consume:

```json
{
  "jsonrpc": "2.0",
  "id": 3,
  "result": {
    "content": [{ "type": "text", "text": "..." }],
    "structuredContent": {
      "ok": true,
      "tool": "passive_check",
      "status": "ok",
      "summary": "Dry run plan created for passive_check.",
      "findings": [],
      "guardrails": { "blocked": false, "reason": [], "scope": [] }
    },
    "isError": false
  }
}
```

Credential values and raw target response bodies are never echoed in MCP results.
