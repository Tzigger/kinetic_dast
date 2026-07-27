# Claude Desktop Configuration Example

Copy this configuration to your Claude Desktop config file and adjust the path.

## Claude Desktop Config File Location

- **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`

## Configuration

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

## Instructions

1. Replace `/absolute/path/to/kinetic_dast-main` with your actual repository path
2. Example on Windows: `"D:/Projects/kinetic_dast-main/dist/cli/index.js"`
3. Example on macOS/Linux: `"/Users/username/projects/kinetic_dast-main/dist/cli/index.js"`
4. Save the configuration file
5. Restart Claude Desktop
6. The kinetic-dast MCP server will be available in your Claude Desktop session
