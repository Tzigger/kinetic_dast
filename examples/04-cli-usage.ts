/**
 * Kinetic DAST - CLI Usage Example
 * 
 * The CLI is the easiest way to run security scans. No code needed!
 * 
 * QUICK START:
 * ────────────────────────────────────────────────────────────────────
 * 
 * 1. Build the CLI:
 *    npm run build
 * 
 * 2. Run a quick passive scan:
 *    npx kinetic http://testphp.vulnweb.com --passive
 * 
 * 3. Run an active scan (tests for SQLi, XSS, etc.):
 *    npx kinetic http://testphp.vulnweb.com --active
 * 
 * 4. Run both passive and active:
 *    npx kinetic http://testphp.vulnweb.com
 * 
 * CLI OPTIONS:
 * ────────────────────────────────────────────────────────────────────
 * 
 * Basic Usage:
 *   kinetic <url>                    Run both passive and active scans
 *   kinetic <url> --passive          Only passive scan (fast)
 *   kinetic <url> --active           Only active scan (thorough)
 * 
 * Output Formats:
 *   --formats console               Print to terminal (default)
 *   --formats json                  Output JSON file
 *   --formats html                  Generate HTML report
 *   --formats sarif                 SARIF format for CI/CD
 *   --formats json,html,sarif       Multiple formats
 * 
 * Scan Options:
 *   --max-pages 5                   Limit pages to scan
 *   --aggressiveness low|medium|high  Control scan intensity
 *   --headless false                Show browser window (debugging)
 *   --timeout 60000                 Set timeout in milliseconds
 * 
 * Detector Options:
 *   --detectors all                 Use all detectors
 *   --detectors sqli,xss            Only specific detectors
 *   --detectors sql,xss,injection   Multiple specific detectors
 * 
 * EXAMPLES:
 * ────────────────────────────────────────────────────────────────────
 * 
 * Example 1: Quick security check (CI/CD friendly)
 *   npx kinetic http://myapp.com --passive --formats sarif
 * 
 * Example 2: Thorough scan with HTML report
 *   npx kinetic http://myapp.com --active --formats html --max-pages 10
 * 
 * Example 3: Test only for SQL injection
 *   npx kinetic http://myapp.com --active --detectors sqli
 * 
 * Example 4: Debug mode (visible browser)
 *   npx kinetic http://myapp.com --headless false
 * 
 * Example 5: Using a config file
 *   npx kinetic --config dast.config.json
 * 
 * CONFIG FILE (dast.config.json):
 * ────────────────────────────────────────────────────────────────────
 * 
 * For complex scans, use a config file:
 * 
 * {
 *   "target": {
 *     "url": "http://myapp.com",
 *     "maxPages": 10,
 *     "timeout": 60000
 *   },
 *   "scanners": {
 *     "passive": { "enabled": true },
 *     "active": { 
 *       "enabled": true,
 *       "aggressiveness": "medium"
 *     }
 *   },
 *   "detectors": {
 *     "enabled": ["sqli", "xss", "injection"],
 *     "sensitivity": "normal"
 *   },
 *   "reporting": {
 *     "formats": ["json", "html"],
 *     "outputDir": "./security-reports"
 *   }
 * }
 * 
 * CI/CD INTEGRATION:
 * ────────────────────────────────────────────────────────────────────
 * 
 * GitHub Actions Example:
 * 
 * - name: Security Scan
 *   run: |
 *     npx kinetic ${{ env.TARGET_URL }} --formats sarif --output security.sarif
 *     
 * - name: Upload SARIF
 *   uses: github/codeql-action/upload-sarif@v2
 *   with:
 *     sarif_file: security.sarif
 * 
 * EXIT CODES:
 * ────────────────────────────────────────────────────────────────────
 * 
 * 0 = No vulnerabilities found (or only INFO level)
 * 1 = Vulnerabilities found
 * 2 = Scan error
 * 
 * This allows you to fail CI/CD builds when vulnerabilities are found.
 */

// This file is documentation only - see the CLI at src/cli/index.ts
console.log('📖 This file contains CLI documentation.');
console.log('Run: npx kinetic --help for usage information.');
