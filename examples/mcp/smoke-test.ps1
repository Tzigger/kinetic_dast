$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$serverPath = Join-Path $repoRoot 'dist/cli/index.js'

if (-not (Test-Path $serverPath)) {
    Write-Error "Server entrypoint not found at $serverPath. Please run: npm run build"
    exit 1
}

$startInfo = [System.Diagnostics.ProcessStartInfo]::new()
$startInfo.FileName = 'node'
$startInfo.Arguments = ('"{0}" --mcp' -f $serverPath)
$startInfo.WorkingDirectory = $repoRoot
$startInfo.UseShellExecute = $false
$startInfo.CreateNoWindow = $true
$startInfo.RedirectStandardInput = $true
$startInfo.RedirectStandardOutput = $true
$startInfo.RedirectStandardError = $true

$process = [System.Diagnostics.Process]::new()
$process.StartInfo = $startInfo
[void]$process.Start()

$requests = @(
    '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"kinetic-mcp-powershell-smoke-test","version":"1.0.0"}}}',
    '{"jsonrpc":"2.0","method":"notifications/initialized"}',
    '{"jsonrpc":"2.0","id":2,"method":"tools/list"}',
    '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"passive_check","arguments":{"url":"http://localhost:3000","dryRun":true}}}'
)

foreach ($request in $requests) {
    $process.StandardInput.WriteLine($request)
}
$process.StandardInput.Close()
$outputTask = $process.StandardOutput.ReadToEndAsync()
$errorTask = $process.StandardError.ReadToEndAsync()
$process.WaitForExit()

$output = $outputTask.GetAwaiter().GetResult().Trim()
$errors = $errorTask.GetAwaiter().GetResult().Trim()
if ($errors) {
    Write-Error $errors
}
if ($process.ExitCode -ne 0 -or -not $output) {
    Write-Error 'MCP smoke test did not return protocol responses.'
    exit 1
}

$output
