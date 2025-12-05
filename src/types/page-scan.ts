/**
 * Page Vulnerability Scan Types
 * 
 * Types for targeted page scanning - scan only specified pages
 * instead of crawling the entire application.
 */

import { VulnerabilityCategory } from './enums';

/**
 * Configuration for a single page to scan
 */
export interface PageTarget {
  /** URL or path to the page (e.g., '/login', '/register', 'http://example.com/login') */
  url: string;
  
  /** Human-readable name for the page */
  name?: string;
  
  /** Description of the page's purpose */
  description?: string;
  
  /** Specific vulnerability categories to test on this page */
  testCategories?: VulnerabilityCategory[];
  
  /** Whether to fill forms before testing (default: true) */
  fillForms?: boolean;
  
  /** Custom form values to use for this page */
  formValues?: Record<string, string>;
  
  /** Wait condition before scanning */
  waitFor?: PageWaitCondition;
  
  /** Actions to perform before scanning */
  preActions?: PageAction[];
  
  /** Whether to include this page in scan (default: true) */
  enabled?: boolean;
}

/**
 * Wait condition before scanning a page
 */
export interface PageWaitCondition {
  /** Type of wait condition */
  type: 'selector' | 'navigation' | 'networkidle' | 'timeout' | 'function';
  
  /** Value for the wait condition (selector, URL pattern, timeout ms, or function) */
  value?: string | number;
  
  /** Timeout for the wait condition in ms */
  timeout?: number;
}

/**
 * Action to perform on a page
 */
export interface PageAction {
  /** Type of action */
  type: 'click' | 'fill' | 'select' | 'hover' | 'wait' | 'scroll' | 'navigate' | 'dismiss-dialog';
  
  /** CSS selector for the target element */
  selector?: string;
  
  /** Value for fill/select actions */
  value?: string;
  
  /** Timeout for this action */
  timeout?: number;
  
  /** Description of the action */
  description?: string;
}

/**
 * Configuration for page vulnerability scan
 */
export interface PageScanConfig {
  /** Base URL of the application */
  baseUrl: string;
  
  /** Pages to scan */
  pages: PageTarget[];
  
  /** Whether to scan pages in parallel (default: false for stability) */
  parallel?: boolean;
  
  /** Global timeout for page operations in ms */
  pageTimeout?: number;
  
  /** Delay between page scans in ms */
  delayBetweenPages?: number;
  
  /** Whether to continue on page errors (default: true) */
  continueOnError?: boolean;
  
  /** Global pre-scan actions (e.g., dismiss cookie banners) */
  globalPreActions?: PageAction[];
  
  /** Authentication to perform before page scans */
  authentication?: PageAuthConfig;
}

/**
 * Authentication configuration for page scans
 */
export interface PageAuthConfig {
  /** Login page URL */
  loginUrl: string;
  
  /** Actions to perform authentication */
  loginActions: PageAction[];
  
  /** Selector or URL to verify successful login */
  successIndicator?: {
    type: 'selector' | 'url';
    value: string;
  };
}

/**
 * Result for a single page scan
 */
export interface PageScanResult {
  /** Page that was scanned */
  page: PageTarget;
  
  /** Whether the scan was successful */
  success: boolean;
  
  /** Error message if scan failed */
  error?: string;
  
  /** Number of vulnerabilities found on this page */
  vulnerabilityCount: number;
  
  /** Time taken to scan this page in ms */
  duration: number;
  
  /** Attack surfaces found on this page */
  attackSurfacesFound: number;
  
  /** Forms found on this page */
  formsFound: number;
  
  /** API calls intercepted */
  apiCallsIntercepted: number;
}

/**
 * Aggregated result for page vulnerability scan
 */
export interface PageVulnerabilityScanResult {
  /** All page results */
  pageResults: PageScanResult[];
  
  /** Total vulnerabilities found */
  totalVulnerabilities: number;
  
  /** Pages successfully scanned */
  successfulPages: number;
  
  /** Pages that failed */
  failedPages: number;
  
  /** Total scan duration in ms */
  totalDuration: number;
  
  /** Summary by page */
  summary: {
    pageName: string;
    pageUrl: string;
    vulnerabilities: number;
    status: 'success' | 'failed' | 'skipped';
  }[];
}

/**
 * Common page patterns for quick setup
 */
export const CommonPagePatterns = {
  /** Authentication pages */
  AUTH_PAGES: [
    { url: '/login', name: 'Login Page' },
    { url: '/register', name: 'Registration Page' },
    { url: '/signup', name: 'Signup Page' },
    { url: '/forgot-password', name: 'Forgot Password Page' },
    { url: '/reset-password', name: 'Reset Password Page' },
    { url: '/logout', name: 'Logout Page' },
  ],
  
  /** User profile pages */
  USER_PAGES: [
    { url: '/profile', name: 'Profile Page' },
    { url: '/settings', name: 'Settings Page' },
    { url: '/account', name: 'Account Page' },
    { url: '/preferences', name: 'Preferences Page' },
  ],
  
  /** Search and data entry */
  INPUT_PAGES: [
    { url: '/search', name: 'Search Page' },
    { url: '/contact', name: 'Contact Page' },
    { url: '/feedback', name: 'Feedback Page' },
    { url: '/comment', name: 'Comment Page' },
  ],
  
  /** E-commerce pages */
  ECOMMERCE_PAGES: [
    { url: '/cart', name: 'Shopping Cart' },
    { url: '/checkout', name: 'Checkout Page' },
    { url: '/payment', name: 'Payment Page' },
    { url: '/order', name: 'Order Page' },
  ],
  
  /** Juice Shop specific pages */
  JUICE_SHOP_PAGES: [
    { url: '/#/login', name: 'Juice Shop Login' },
    { url: '/#/register', name: 'Juice Shop Register' },
    { url: '/#/forgot-password', name: 'Juice Shop Forgot Password' },
    { url: '/#/search', name: 'Juice Shop Search' },
    { url: '/#/contact', name: 'Juice Shop Contact' },
    { url: '/#/complain', name: 'Juice Shop Complaint' },
    { url: '/#/basket', name: 'Juice Shop Basket' },
    { url: '/#/address/select', name: 'Juice Shop Address' },
    { url: '/#/recycle', name: 'Juice Shop Recycle' },
    { url: '/#/track-result', name: 'Juice Shop Order Tracking' },
  ],
} as const;

/**
 * Juice Shop page configurations with pre-actions
 */
export const JuiceShopPages: PageTarget[] = [
  {
    url: '/#/login',
    name: 'Login Page',
    description: 'Main login page with email/password fields',
    fillForms: true,
    formValues: {
      'email': "test@test.com' OR '1'='1",
      'password': 'test123',
    },
    preActions: [
      { type: 'dismiss-dialog', description: 'Close welcome dialog' },
    ],
  },
  {
    url: '/#/register',
    name: 'Registration Page',
    description: 'User registration with multiple input fields',
    fillForms: true,
    formValues: {
      'emailControl': '<script>alert("xss")</script>@test.com',
      'passwordControl': 'Test1234!',
      'repeatPasswordControl': 'Test1234!',
      'securityQuestion': '1',
      'securityAnswer': "<img src=x onerror='alert(1)'>",
    },
  },
  {
    url: '/#/forgot-password',
    name: 'Forgot Password Page',
    description: 'Password reset with security question',
    fillForms: true,
  },
  {
    url: '/#/search?q=test',
    name: 'Search Page',
    description: 'Product search - potential XSS vector',
    testCategories: ['xss' as VulnerabilityCategory],
  },
  {
    url: '/#/contact',
    name: 'Contact Page',
    description: 'Contact form - multiple input vectors',
  },
  {
    url: '/#/complain',
    name: 'Complaint Page',
    description: 'File upload and complaint submission',
  },
];
