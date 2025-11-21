/**
 * OWASP Top 10 2025 to CWE Mapping
 * 
 * Complete mapping of OWASP Top 10 2025 categories to their CWEs
 * Based on official OWASP Top 10 2025 release
 */

export enum OWASP2025Category {
  A01_BROKEN_ACCESS_CONTROL = 'A01:2025',
  A02_SECURITY_MISCONFIGURATION = 'A02:2025',
  A03_SOFTWARE_SUPPLY_CHAIN = 'A03:2025',
  A04_CRYPTOGRAPHIC_FAILURES = 'A04:2025',
  A05_INJECTION = 'A05:2025',
  A06_INSECURE_DESIGN = 'A06:2025',
  A07_AUTHENTICATION_FAILURES = 'A07:2025',
  A08_SOFTWARE_DATA_INTEGRITY = 'A08:2025',
  A09_LOGGING_ALERTING_FAILURES = 'A09:2025',
  A10_MISHANDLING_EXCEPTIONAL_CONDITIONS = 'A10:2025',
}

/**
 * A01:2025 - Broken Access Control (40 CWEs)
 * Includes SSRF rolled in from 2021
 */
export const A01_BROKEN_ACCESS_CONTROL_CWES = [
  'CWE-22',   // Path Traversal
  'CWE-23',   // Relative Path Traversal
  'CWE-35',   // Path Traversal: '.../...//'
  'CWE-59',   // Improper Link Resolution Before File Access
  'CWE-200',  // Exposure of Sensitive Information
  'CWE-201',  // Insertion of Sensitive Information Into Sent Data
  'CWE-219',  // Storage of File with Sensitive Data Under Web Root
  'CWE-264',  // Permissions, Privileges, and Access Controls
  'CWE-275',  // Permission Issues
  'CWE-276',  // Incorrect Default Permissions
  'CWE-284',  // Improper Access Control
  'CWE-285',  // Improper Authorization
  'CWE-352',  // CSRF
  'CWE-359',  // Exposure of Private Personal Information
  'CWE-377',  // Insecure Temporary File
  'CWE-402',  // Transmission of Private Resources into a New Sphere
  'CWE-425',  // Direct Request (Forced Browsing)
  'CWE-441',  // Unintended Proxy or Intermediary
  'CWE-497',  // Exposure of Sensitive System Information
  'CWE-538',  // Insertion of Sensitive Information into Externally-Accessible File
  'CWE-540',  // Inclusion of Sensitive Information in Source Code
  'CWE-548',  // Exposure of Information Through Directory Listing
  'CWE-552',  // Files or Directories Accessible to External Parties
  'CWE-566',  // Authorization Bypass Through User-Controlled SQL Primary Key
  'CWE-601',  // URL Redirection to Untrusted Site (Open Redirect)
  'CWE-639',  // Authorization Bypass Through User-Controlled Key (IDOR)
  'CWE-651',  // Exposure of WSDL File Containing Sensitive Information
  'CWE-668',  // Exposure of Resource to Wrong Sphere
  'CWE-706',  // Use of Incorrectly-Resolved Name or Reference
  'CWE-862',  // Missing Authorization
  'CWE-863',  // Incorrect Authorization
  'CWE-913',  // Improper Control of Dynamically-Managed Code Resources
  'CWE-918',  // Server-Side Request Forgery (SSRF) - NEW in 2025
  'CWE-922',  // Insecure Storage of Sensitive Information
  'CWE-1275', // Sensitive Cookie with Improper SameSite Attribute
  'CWE-552',  // Files or Directories Accessible to External Parties
  'CWE-434',  // Unrestricted Upload of File with Dangerous Type
  'CWE-829',  // Inclusion of Functionality from Untrusted Control Sphere
  'CWE-98',   // Improper Control of Filename for Include/Require Statement
  'CWE-99',   // Improper Control of Resource Identifiers
];

/**
 * A02:2025 - Security Misconfiguration (16 CWEs)
 * Moved from #5 to #2
 */
export const A02_SECURITY_MISCONFIGURATION_CWES = [
  'CWE-2',    // Environmental Security Flaws
  'CWE-11',   // ASP.NET Misconfiguration: Creating Debug Binary
  'CWE-13',   // ASP.NET Misconfiguration: Password in Configuration File
  'CWE-15',   // External Control of System or Configuration Setting
  'CWE-16',   // Configuration
  'CWE-260',  // Password in Configuration File
  'CWE-315',  // Cleartext Storage of Sensitive Information in a Cookie
  'CWE-520',  // .NET Misconfiguration: Use of Impersonation
  'CWE-526',  // Exposure of Sensitive Information Through Environmental Variables
  'CWE-537',  // Java Runtime Error Message Containing Sensitive Information
  'CWE-541',  // Inclusion of Sensitive Information in an Include File
  'CWE-547',  // Use of Hard-coded, Security-relevant Constants
  'CWE-611',  // Improper Restriction of XML External Entity Reference
  'CWE-614',  // Sensitive Cookie in HTTPS Session Without 'Secure' Attribute
  'CWE-756',  // Missing Custom Error Page
  'CWE-942',  // Overly Permissive Cross-domain Whitelist
];

/**
 * A03:2025 - Software Supply Chain Failures (5 CWEs)
 * Expansion of A06:2021 - NEW focus area
 */
export const A03_SOFTWARE_SUPPLY_CHAIN_CWES = [
  'CWE-829',  // Inclusion of Functionality from Untrusted Control Sphere
  'CWE-830',  // Inclusion of Web Functionality from an Untrusted Source
  'CWE-915',  // Improperly Controlled Modification of Dynamically-Determined Object Attributes
  'CWE-1104', // Use of Unmaintained Third Party Components
  'CWE-1329', // Reliance on Component That is Not Updateable
];

/**
 * A04:2025 - Cryptographic Failures (32 CWEs)
 * Falls from #2 to #4
 */
export const A04_CRYPTOGRAPHIC_FAILURES_CWES = [
  'CWE-261',  // Weak Encoding for Password
  'CWE-296',  // Improper Following of a Certificate's Chain of Trust
  'CWE-310',  // Cryptographic Issues
  'CWE-319',  // Cleartext Transmission of Sensitive Information
  'CWE-321',  // Use of Hard-coded Cryptographic Key
  'CWE-322',  // Key Exchange without Entity Authentication
  'CWE-323',  // Reusing a Nonce, Key Pair in Encryption
  'CWE-324',  // Use of a Key Past its Expiration Date
  'CWE-325',  // Missing Required Cryptographic Step
  'CWE-326',  // Inadequate Encryption Strength
  'CWE-327',  // Use of a Broken or Risky Cryptographic Algorithm
  'CWE-328',  // Reversible One-Way Hash
  'CWE-329',  // Not Using a Random IV with CBC Mode
  'CWE-330',  // Use of Insufficiently Random Values
  'CWE-331',  // Insufficient Entropy
  'CWE-335',  // Incorrect Usage of Seeds in Pseudo-Random Number Generator
  'CWE-336',  // Same Seed in Pseudo-Random Number Generator
  'CWE-337',  // Predictable Seed in Pseudo-Random Number Generator
  'CWE-338',  // Use of Cryptographically Weak Pseudo-Random Number Generator
  'CWE-340',  // Generation of Predictable Numbers or Identifiers
  'CWE-347',  // Improper Verification of Cryptographic Signature
  'CWE-523',  // Unprotected Transport of Credentials
  'CWE-757',  // Selection of Less-Secure Algorithm During Negotiation
  'CWE-759',  // Use of a One-Way Hash without a Salt
  'CWE-760',  // Use of a One-Way Hash with a Predictable Salt
  'CWE-780',  // Use of RSA Algorithm without OAEP
  'CWE-818',  // Insufficient Transport Layer Protection
  'CWE-916',  // Use of Password Hash With Insufficient Computational Effort
  'CWE-261',  // Weak Encoding for Password
  'CWE-312',  // Cleartext Storage of Sensitive Information
  'CWE-311',  // Missing Encryption of Sensitive Data
  'CWE-326',  // Inadequate Encryption Strength
];

/**
 * A05:2025 - Injection (38 CWEs)
 * Falls from #3 to #5
 */
export const A05_INJECTION_CWES = [
  'CWE-20',   // Improper Input Validation
  'CWE-74',   // Improper Neutralization of Special Elements in Output
  'CWE-75',   // Failure to Sanitize Special Elements into a Different Plane
  'CWE-77',   // Command Injection
  'CWE-78',   // OS Command Injection
  'CWE-79',   // Cross-site Scripting (XSS)
  'CWE-80',   // Improper Neutralization of Script-Related HTML Tags
  'CWE-83',   // Improper Neutralization of Script in Attributes in a Web Page
  'CWE-87',   // Improper Neutralization of Alternate XSS Syntax
  'CWE-88',   // Argument Injection
  'CWE-89',   // SQL Injection
  'CWE-90',   // LDAP Injection
  'CWE-91',   // XML Injection
  'CWE-93',   // Improper Neutralization of CRLF Sequences
  'CWE-94',   // Code Injection
  'CWE-95',   // Improper Neutralization of Directives in Dynamically Evaluated Code
  'CWE-96',   // Improper Neutralization of Directives in Statically Saved Code
  'CWE-97',   // Improper Neutralization of Server-Side Includes (SSI)
  'CWE-98',   // PHP Remote File Inclusion
  'CWE-99',   // Improper Control of Resource Identifiers
  'CWE-100',  // Deprecated: Was catch-all for input validation issues
  'CWE-113',  // Improper Neutralization of CRLF Sequences in HTTP Headers
  'CWE-116',  // Improper Encoding or Escaping of Output
  'CWE-138',  // Improper Neutralization of Special Elements
  'CWE-184',  // Incomplete List of Disallowed Inputs
  'CWE-470',  // Use of Externally-Controlled Input to Select Classes or Code
  'CWE-471',  // Modification of Assumed-Immutable Data
  'CWE-564',  // SQL Injection: Hibernate
  'CWE-610',  // Externally Controlled Reference to a Resource in Another Sphere
  'CWE-643',  // Improper Neutralization of Data within XPath Expressions
  'CWE-644',  // Improper Neutralization of HTTP Headers for Scripting Syntax
  'CWE-652',  // Improper Neutralization of Data within XQuery Expressions
  'CWE-917',  // Expression Language Injection
  'CWE-1236', // Improper Neutralization of Formula Elements in a CSV File
  'CWE-694',  // Use of Multiple Resources with Duplicate Identifier
  'CWE-917',  // Improper Neutralization of Special Elements used in an Expression Language Statement
  'CWE-943',  // Improper Neutralization of Special Elements in Data Query Logic
  'CWE-1333', // Inefficient Regular Expression Complexity (ReDoS)
];

/**
 * A06:2025 - Insecure Design (CWEs vary)
 * Slides from #4 to #6
 */
export const A06_INSECURE_DESIGN_CWES = [
  'CWE-73',   // External Control of File Name or Path
  'CWE-183',  // Permissive List of Allowed Inputs
  'CWE-209',  // Generation of Error Message Containing Sensitive Information
  'CWE-213',  // Exposure of Sensitive Information Due to Incompatible Policies
  'CWE-235',  // Improper Handling of Extra Parameters
  'CWE-256',  // Unprotected Storage of Credentials
  'CWE-257',  // Storing Passwords in a Recoverable Format
  'CWE-266',  // Incorrect Privilege Assignment
  'CWE-269',  // Improper Privilege Management
  'CWE-280',  // Improper Handling of Insufficient Permissions or Privileges
  'CWE-311',  // Missing Encryption of Sensitive Data
  'CWE-312',  // Cleartext Storage of Sensitive Information
  'CWE-313',  // Cleartext Storage in a File or on Disk
  'CWE-316',  // Cleartext Storage of Sensitive Information in Memory
  'CWE-419',  // Unprotected Primary Channel
  'CWE-430',  // Deployment of Wrong Handler
  'CWE-434',  // Unrestricted Upload of File with Dangerous Type
  'CWE-444',  // Inconsistent Interpretation of HTTP Requests
  'CWE-451',  // User Interface (UI) Misrepresentation of Critical Information
  'CWE-472',  // External Control of Assumed-Immutable Web Parameter
  'CWE-501',  // Trust Boundary Violation
  'CWE-522',  // Insufficiently Protected Credentials
  'CWE-525',  // Use of Web Browser Cache Containing Sensitive Information
  'CWE-539',  // Use of Persistent Cookies Containing Sensitive Information
  'CWE-579',  // J2EE Bad Practices: Non-serializable Object Stored in Session
  'CWE-598',  // Use of GET Request Method With Sensitive Query Strings
  'CWE-602',  // Client-Side Enforcement of Server-Side Security
  'CWE-642',  // External Control of Critical State Data
  'CWE-646',  // Reliance on File Name or Extension of Externally-Supplied File
  'CWE-650',  // Trusting HTTP Permission Methods on the Server Side
  'CWE-653',  // Insufficient Compartmentalization
  'CWE-656',  // Reliance on Security Through Obscurity
  'CWE-657',  // Violation of Secure Design Principles
  'CWE-799',  // Improper Control of Interaction Frequency
  'CWE-807',  // Reliance on Untrusted Inputs in a Security Decision
  'CWE-840',  // Business Logic Errors
  'CWE-841',  // Improper Enforcement of Behavioral Workflow
  'CWE-927',  // Use of Implicit Intent for Sensitive Communication
  'CWE-1021', // Improper Restriction of Rendered UI Layers or Frames (Clickjacking)
  'CWE-1173', // Improper Use of Validation Framework
];

/**
 * A07:2025 - Authentication Failures (36 CWEs)
 * Maintains position at #7
 */
export const A07_AUTHENTICATION_FAILURES_CWES = [
  'CWE-255',  // Credentials Management Errors
  'CWE-259',  // Use of Hard-coded Password
  'CWE-287',  // Improper Authentication
  'CWE-288',  // Authentication Bypass Using an Alternate Path or Channel
  'CWE-290',  // Authentication Bypass by Spoofing
  'CWE-294',  // Authentication Bypass by Capture-replay
  'CWE-295',  // Improper Certificate Validation
  'CWE-297',  // Improper Validation of Certificate with Host Mismatch
  'CWE-300',  // Channel Accessible by Non-Endpoint
  'CWE-302',  // Authentication Bypass by Assumed-Immutable Data
  'CWE-304',  // Missing Critical Step in Authentication
  'CWE-306',  // Missing Authentication for Critical Function
  'CWE-307',  // Improper Restriction of Excessive Authentication Attempts
  'CWE-346',  // Origin Validation Error
  'CWE-384',  // Session Fixation
  'CWE-521',  // Weak Password Requirements
  'CWE-522',  // Insufficiently Protected Credentials
  'CWE-598',  // Use of GET Request Method With Sensitive Query Strings
  'CWE-603',  // Use of Client-Side Authentication
  'CWE-613',  // Insufficient Session Expiration
  'CWE-620',  // Unverified Password Change
  'CWE-640',  // Weak Password Recovery Mechanism for Forgotten Password
  'CWE-798',  // Use of Hard-coded Credentials
  'CWE-1216', // Lockout Mechanism Errors
  'CWE-308',  // Use of Single-factor Authentication
  'CWE-319',  // Cleartext Transmission of Sensitive Information
  'CWE-523',  // Unprotected Transport of Credentials
  'CWE-549',  // Missing Password Field Masking
  'CWE-565',  // Reliance on Cookies without Validation and Integrity Checking
  'CWE-568',  // finalize() Method Without super.finalize()
  'CWE-640',  // Weak Password Recovery Mechanism for Forgotten Password
  'CWE-645',  // Overly Restrictive Account Lockout Mechanism
  'CWE-759',  // Use of a One-Way Hash without a Salt
  'CWE-760',  // Use of a One-Way Hash with a Predictable Salt
  'CWE-916',  // Use of Password Hash With Insufficient Computational Effort
  'CWE-1390', // Weak Authentication
];

/**
 * A08:2025 - Software and Data Integrity Failures (CWEs)
 * Continues at #8
 */
export const A08_SOFTWARE_DATA_INTEGRITY_CWES = [
  'CWE-345',  // Insufficient Verification of Data Authenticity
  'CWE-353',  // Missing Support for Integrity Check
  'CWE-426',  // Untrusted Search Path
  'CWE-494',  // Download of Code Without Integrity Check
  'CWE-502',  // Deserialization of Untrusted Data
  'CWE-565',  // Reliance on Cookies without Validation and Integrity Checking
  'CWE-784',  // Reliance on Cookies without Validation and Integrity Checking in a Security Decision
  'CWE-829',  // Inclusion of Functionality from Untrusted Control Sphere
  'CWE-830',  // Inclusion of Web Functionality from an Untrusted Source
  'CWE-915',  // Improperly Controlled Modification of Dynamically-Determined Object Attributes
];

/**
 * A09:2025 - Logging & Alerting Failures (CWEs)
 * Retains position at #9
 */
export const A09_LOGGING_ALERTING_FAILURES_CWES = [
  'CWE-117',  // Improper Output Neutralization for Logs
  'CWE-223',  // Omission of Security-relevant Information
  'CWE-532',  // Insertion of Sensitive Information into Log File
  'CWE-778',  // Insufficient Logging
  'CWE-117',  // Improper Output Neutralization for Logs
  'CWE-223',  // Omission of Security-relevant Information
  'CWE-532',  // Insertion of Sensitive Information into Log File
  'CWE-778',  // Insufficient Logging
];

/**
 * A10:2025 - Mishandling of Exceptional Conditions (24 CWEs)
 * NEW category for 2025
 */
export const A10_MISHANDLING_EXCEPTIONAL_CONDITIONS_CWES = [
  'CWE-248',  // Uncaught Exception
  'CWE-252',  // Unchecked Return Value
  'CWE-253',  // Incorrect Check of Function Return Value
  'CWE-390',  // Detection of Error Condition Without Action
  'CWE-391',  // Unchecked Error Condition
  'CWE-392',  // Missing Report of Error Condition
  'CWE-396',  // Declaration of Catch for Generic Exception
  'CWE-397',  // Declaration of Throws for Generic Exception
  'CWE-404',  // Improper Resource Shutdown or Release
  'CWE-431',  // Missing Handler
  'CWE-476',  // NULL Pointer Dereference
  'CWE-600',  // Uncaught Exception in Servlet
  'CWE-703',  // Improper Check or Handling of Exceptional Conditions
  'CWE-705',  // Incorrect Control Flow Scoping
  'CWE-754',  // Improper Check for Unusual or Exceptional Conditions
  'CWE-755',  // Improper Handling of Exceptional Conditions
  'CWE-756',  // Missing Custom Error Page
  'CWE-757',  // Selection of Less-Secure Algorithm During Negotiation
  'CWE-230',  // Improper Handling of Missing Values
  'CWE-231',  // Improper Handling of Extra Values
  'CWE-232',  // Improper Handling of Undefined Values
  'CWE-233',  // Improper Handling of Parameters
  'CWE-393',  // Return of Wrong Status Code
  'CWE-544',  // Missing Standardized Error Handling Mechanism
];

/**
 * Get OWASP 2025 category for a CWE
 */
export function getOWASP2025Category(cwe: string): OWASP2025Category | null {
  const cweNum = cwe.replace('CWE-', '');
  
  if (A01_BROKEN_ACCESS_CONTROL_CWES.includes(`CWE-${cweNum}`)) {
    return OWASP2025Category.A01_BROKEN_ACCESS_CONTROL;
  }
  if (A02_SECURITY_MISCONFIGURATION_CWES.includes(`CWE-${cweNum}`)) {
    return OWASP2025Category.A02_SECURITY_MISCONFIGURATION;
  }
  if (A03_SOFTWARE_SUPPLY_CHAIN_CWES.includes(`CWE-${cweNum}`)) {
    return OWASP2025Category.A03_SOFTWARE_SUPPLY_CHAIN;
  }
  if (A04_CRYPTOGRAPHIC_FAILURES_CWES.includes(`CWE-${cweNum}`)) {
    return OWASP2025Category.A04_CRYPTOGRAPHIC_FAILURES;
  }
  if (A05_INJECTION_CWES.includes(`CWE-${cweNum}`)) {
    return OWASP2025Category.A05_INJECTION;
  }
  if (A06_INSECURE_DESIGN_CWES.includes(`CWE-${cweNum}`)) {
    return OWASP2025Category.A06_INSECURE_DESIGN;
  }
  if (A07_AUTHENTICATION_FAILURES_CWES.includes(`CWE-${cweNum}`)) {
    return OWASP2025Category.A07_AUTHENTICATION_FAILURES;
  }
  if (A08_SOFTWARE_DATA_INTEGRITY_CWES.includes(`CWE-${cweNum}`)) {
    return OWASP2025Category.A08_SOFTWARE_DATA_INTEGRITY;
  }
  if (A09_LOGGING_ALERTING_FAILURES_CWES.includes(`CWE-${cweNum}`)) {
    return OWASP2025Category.A09_LOGGING_ALERTING_FAILURES;
  }
  if (A10_MISHANDLING_EXCEPTIONAL_CONDITIONS_CWES.includes(`CWE-${cweNum}`)) {
    return OWASP2025Category.A10_MISHANDLING_EXCEPTIONAL_CONDITIONS;
  }
  
  return null;
}

/**
 * Get all CWEs for an OWASP 2025 category
 */
export function getCWEsForOWASPCategory(category: OWASP2025Category): string[] {
  switch (category) {
    case OWASP2025Category.A01_BROKEN_ACCESS_CONTROL:
      return A01_BROKEN_ACCESS_CONTROL_CWES;
    case OWASP2025Category.A02_SECURITY_MISCONFIGURATION:
      return A02_SECURITY_MISCONFIGURATION_CWES;
    case OWASP2025Category.A03_SOFTWARE_SUPPLY_CHAIN:
      return A03_SOFTWARE_SUPPLY_CHAIN_CWES;
    case OWASP2025Category.A04_CRYPTOGRAPHIC_FAILURES:
      return A04_CRYPTOGRAPHIC_FAILURES_CWES;
    case OWASP2025Category.A05_INJECTION:
      return A05_INJECTION_CWES;
    case OWASP2025Category.A06_INSECURE_DESIGN:
      return A06_INSECURE_DESIGN_CWES;
    case OWASP2025Category.A07_AUTHENTICATION_FAILURES:
      return A07_AUTHENTICATION_FAILURES_CWES;
    case OWASP2025Category.A08_SOFTWARE_DATA_INTEGRITY:
      return A08_SOFTWARE_DATA_INTEGRITY_CWES;
    case OWASP2025Category.A09_LOGGING_ALERTING_FAILURES:
      return A09_LOGGING_ALERTING_FAILURES_CWES;
    case OWASP2025Category.A10_MISHANDLING_EXCEPTIONAL_CONDITIONS:
      return A10_MISHANDLING_EXCEPTIONAL_CONDITIONS_CWES;
    default:
      return [];
  }
}

/**
 * Statistics for OWASP Top 10 2025
 */
export const OWASP2025Stats = {
  [OWASP2025Category.A01_BROKEN_ACCESS_CONTROL]: {
    rank: 1,
    prevalence: '3.73%',
    cweCount: 40,
    description: 'Violations of access control policy, including SSRF',
  },
  [OWASP2025Category.A02_SECURITY_MISCONFIGURATION]: {
    rank: 2,
    prevalence: '3.00%',
    cweCount: 16,
    description: 'Insecure default configs, incomplete configs, misconfigured headers',
  },
  [OWASP2025Category.A03_SOFTWARE_SUPPLY_CHAIN]: {
    rank: 3,
    prevalence: 'Limited',
    cweCount: 5,
    description: 'Compromises in dependencies, build systems, distribution',
    highestExploit: true,
  },
  [OWASP2025Category.A04_CRYPTOGRAPHIC_FAILURES]: {
    rank: 4,
    prevalence: '3.80%',
    cweCount: 32,
    description: 'Failures related to cryptography leading to data exposure',
  },
  [OWASP2025Category.A05_INJECTION]: {
    rank: 5,
    prevalence: 'High',
    cweCount: 38,
    description: 'XSS, SQL injection, command injection, etc.',
    mostTested: true,
  },
  [OWASP2025Category.A06_INSECURE_DESIGN]: {
    rank: 6,
    prevalence: 'Medium',
    cweCount: 40,
    description: 'Missing or ineffective control design',
  },
  [OWASP2025Category.A07_AUTHENTICATION_FAILURES]: {
    rank: 7,
    prevalence: 'Medium',
    cweCount: 36,
    description: 'Broken authentication and session management',
  },
  [OWASP2025Category.A08_SOFTWARE_DATA_INTEGRITY]: {
    rank: 8,
    prevalence: 'Low',
    cweCount: 10,
    description: 'Code/data integrity failures, insecure deserialization',
  },
  [OWASP2025Category.A09_LOGGING_ALERTING_FAILURES]: {
    rank: 9,
    prevalence: 'Low',
    cweCount: 4,
    description: 'Insufficient logging, monitoring, and alerting',
  },
  [OWASP2025Category.A10_MISHANDLING_EXCEPTIONAL_CONDITIONS]: {
    rank: 10,
    prevalence: 'Medium',
    cweCount: 24,
    description: 'Improper error handling, failing open, logical errors',
    newIn2025: true,
  },
};
