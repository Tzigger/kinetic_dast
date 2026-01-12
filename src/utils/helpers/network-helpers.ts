/**
 * Parse URL and extract components
 */
export function parseUrl(url: string): URL | null {
  try {
    return new URL(url);
  } catch {
    return null;
  }
}

/**
 * Check if URL is in scope
 */
export function isUrlInScope(
  url: string,
  includePatterns: string[],
  excludePatterns: string[]
): boolean {
  // Check exclude patterns first
  for (const pattern of excludePatterns) {
    if (matchesPattern(url, pattern)) {
      return false;
    }
  }

  // If no include patterns, everything is in scope
  if (includePatterns.length === 0) {
    return true;
  }

  // Check include patterns
  for (const pattern of includePatterns) {
    if (matchesPattern(url, pattern)) {
      return true;
    }
  }

  return false;
}

/**
 * Match URL against pattern (regex)
 */
export function matchesPattern(url: string, pattern: string): boolean {
  try {
    const regex = new RegExp(pattern);
    return regex.test(url);
  } catch {
    // If pattern is not a valid regex, do string comparison
    return url.includes(pattern);
  }
}

/**
 * Check if URL is same origin
 */
export function isSameOrigin(url1: string, url2: string): boolean {
  const parsed1 = parseUrl(url1);
  const parsed2 = parseUrl(url2);

  if (!parsed1 || !parsed2) {
    return false;
  }

  return parsed1.origin === parsed2.origin;
}

/**
 * Extract domain from URL
 */
export function extractDomain(url: string): string | null {
  const parsed = parseUrl(url);
  return parsed ? parsed.hostname : null;
}

/**
 * Check if URL is external
 */
export function isExternalUrl(url: string, baseUrl: string): boolean {
  return !isSameOrigin(url, baseUrl);
}

/**
 * Normalize URL (remove fragments, trailing slashes, etc.)
 */
export function normalizeUrl(url: string): string {
  const parsed = parseUrl(url);
  if (!parsed) {
    return url;
  }

  // Remove fragment
  parsed.hash = '';

  // Remove trailing slash
  let pathname = parsed.pathname;
  if (pathname.endsWith('/') && pathname.length > 1) {
    pathname = pathname.slice(0, -1);
  }
  parsed.pathname = pathname;

  return parsed.toString();
}

/**
 * Normalize URL for payload correlation/matching.
 * Intentionally drops query + fragment and keeps only origin + pathname.
 */
export function normalizeUrlForMatching(url: string): string {
  const parsed = parseUrl(url);
  if (!parsed) return url;
  return `${parsed.origin}${parsed.pathname}`;
}

/**
 * Extract query parameters from URL
 */
export function extractQueryParams(url: string): Record<string, string> {
  const parsed = parseUrl(url);
  if (!parsed) {
    return {};
  }

  const params: Record<string, string> = {};
  parsed.searchParams.forEach((value, key) => {
    params[key] = value;
  });

  return params;
}

/**
 * Check if URL has query parameters
 */
export function hasQueryParams(url: string): boolean {
  const parsed = parseUrl(url);
  if (!parsed) {
    return false;
  }

  return parsed.search.length > 1; // > 1 because '?' counts
}

/**
 * Build URL with query parameters
 */
export function buildUrl(baseUrl: string, params: Record<string, string>): string {
  const parsed = parseUrl(baseUrl);
  if (!parsed) {
    return baseUrl;
  }

  Object.entries(params).forEach(([key, value]) => {
    parsed.searchParams.set(key, value);
  });

  return parsed.toString();
}

/**
 * Check if response is JSON
 */
export function isJsonResponse(headers: Record<string, string>): boolean {
  const contentType = headers['content-type'] || headers['Content-Type'] || '';
  return contentType.includes('application/json');
}

/**
 * Check if response is HTML
 */
export function isHtmlResponse(headers: Record<string, string>): boolean {
  const contentType = headers['content-type'] || headers['Content-Type'] || '';
  return contentType.includes('text/html');
}

/**
 * Check if resource is static
 */
export function isStaticResource(url: string): boolean {
  const staticExtensions = [
    '.jpg',
    '.jpeg',
    '.png',
    '.gif',
    '.svg',
    '.ico',
    '.css',
    '.woff',
    '.woff2',
    '.ttf',
    '.eot',
    '.mp4',
    '.mp3',
    '.pdf',
    '.zip',
  ];

  const lowerUrl = url.toLowerCase();
  return staticExtensions.some((ext) => lowerUrl.endsWith(ext));
}
