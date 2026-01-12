export type ReflectionContext = 'html-body' | 'html-attribute' | 'javascript' | 'url' | 'none';
export type EncodingType = 'none' | 'html' | 'url' | 'js' | 'mixed';
export type EncodingLevel = 'none' | 'partial' | 'full';

const escapeRegex = (value: string): string => value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

export const EXECUTION_INDICATOR_PATTERNS: RegExp[] = [
  /<script[^>]*>/i,
  /<\/script>/i,
  /on\w+\s*=\s*['"]/i,
  /javascript:/i,
  /data:text\/html/i,
  /<svg[^>]*onload=/i,
  /<img[^>]*onerror=/i,
  /eval\s*\(/i,
];

export function findReflectionPatterns(
  text: string,
  payload: string
): { pattern: RegExp; matches: string[] }[] {
  const encodedHtml = payload.replace(/</g, '&lt;').replace(/>/g, '&gt;');
  const urlEncoded = encodeURIComponent(payload);
  const doubleUrlEncoded = encodeURIComponent(urlEncoded);
  const jsEscaped = payload
    .replace(/</g, '\\x3c')
    .replace(/>/g, '\\x3e')
    .replace(/"/g, '\\x22')
    .replace(/'/g, '\\x27');

  const patterns = [
    new RegExp(escapeRegex(payload), 'i'),
    new RegExp(escapeRegex(encodedHtml), 'i'),
    new RegExp(escapeRegex(urlEncoded), 'i'),
    new RegExp(escapeRegex(doubleUrlEncoded), 'i'),
    new RegExp(escapeRegex(jsEscaped), 'i'),
  ];

  return patterns
    .map((pattern) => ({ pattern, matches: text.match(pattern) || [] }))
    .filter((entry) => entry.matches.length > 0);
}

export function detectHtmlEncoding(text: string, payload: string): EncodingType {
  const encoded = payload
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;');
  return text.includes(encoded) ? 'html' : 'none';
}

export function detectUrlEncoding(text: string, payload: string): EncodingType {
  const encoded = encodeURIComponent(payload);
  const doubleEncoded = encodeURIComponent(encoded);
  if (text.includes(doubleEncoded)) return 'url';
  return text.includes(encoded) ? 'url' : 'none';
}

export function detectJsEncoding(text: string, payload: string): EncodingType {
  const jsEscaped = payload
    .replace(/</g, '\\x3c')
    .replace(/>/g, '\\x3e')
    .replace(/"/g, '\\x22')
    .replace(/'/g, '\\x27');
  return text.includes(jsEscaped) ? 'js' : 'none';
}

export function detectEncodingLevel(text: string, payload: string): EncodingLevel {
  const rawPresent = text.includes(payload);
  const htmlEncoded = detectHtmlEncoding(text, payload) !== 'none';
  const urlEncoded = detectUrlEncoding(text, payload) !== 'none';
  const jsEncoded = detectJsEncoding(text, payload) !== 'none';

  const encodedPresent = htmlEncoded || urlEncoded || jsEncoded;

  if (encodedPresent && rawPresent) return 'partial';
  if (encodedPresent) return 'full';
  return 'none';
}

export function detectReflectionContext(html: string, payload: string): ReflectionContext {
  if (new RegExp(`<[^>]+${escapeRegex(payload)}[^>]*>`, 'i').test(html)) return 'html-attribute';
  if (new RegExp(`${escapeRegex(payload)}\s*["']?\s*>`, 'i').test(html)) return 'html-body';
  if (new RegExp(`script[^>]*>${escapeRegex(payload)}`, 'i').test(html)) return 'javascript';
  if (new RegExp(`(href|src)=["']?${escapeRegex(payload)}`, 'i').test(html)) return 'url';
  return 'none';
}

export function analyzeReflectionQuality(
  html: string,
  payload: string
): {
  exact: boolean;
  encoded: boolean;
  context: ReflectionContext;
  confidence: number;
} {
  const exact = html.includes(payload);
  const encoded = detectEncodingLevel(html, payload) !== 'none';
  const context = detectReflectionContext(html, payload);
  let confidence = 0;
  if (exact) confidence += 0.6;
  if (encoded) confidence += 0.2;
  if (context !== 'none') confidence += 0.2;
  return { exact, encoded, context, confidence: Math.min(1, confidence) };
}

export function calculateReflectionConfidence(
  reflectionQuality: ReturnType<typeof analyzeReflectionQuality>,
  executionIndicators: string[]
): number {
  let confidence = reflectionQuality.confidence;
  if (executionIndicators.length > 0) confidence += 0.2;
  if (reflectionQuality.exact && executionIndicators.length > 0)
    confidence = Math.min(1, confidence + 0.1);
  return Math.min(1, confidence);
}

export function findExecutionIndicators(text: string): string[] {
  return EXECUTION_INDICATOR_PATTERNS.filter((pattern) => pattern.test(text)).map((pattern) =>
    pattern.toString()
  );
}
