/**
 * Response comparison utilities for deep structural and content analysis.
 * Provides JSON diffs, similarity scoring, normalization, encoding detection,
 * and error pattern matching for verification techniques.
 */

import { calculateStructuralSimilarity, levenshteinDistance } from './statistical-helpers';
import {
  categorizeError,
  findErrorPatterns,
  SQL_ERROR_PATTERNS,
  STACK_TRACE_PATTERNS,
  PATH_DISCLOSURE_PATTERNS,
  COMMAND_INJECTION_ERROR_PATTERNS,
  APPLICATION_ERROR_PATTERNS,
} from '../patterns/error-patterns';

export interface JsonDiffResult {
  structuralChanges: string[];
  similarity: number;
  keyDifferences: { added: number; removed: number; modified: number };
  typeMismatches: string[];
}

export interface EncodingInfo {
  type: 'html' | 'url' | 'unicode' | 'base64' | 'none';
  confidence: number;
  examples: string[];
}

export interface ErrorMatchResult {
  matched: boolean;
  patterns: string[];
  category: string;
  snippets: string[];
  confidence: number;
}

/** Deep JSON diff capturing structural changes and similarity. */
export function deepJsonDiff(obj1: any, obj2: any): JsonDiffResult {
  const structuralChanges: string[] = [];
  const typeMismatches: string[] = [];
  const keyDifferences = { added: 0, removed: 0, modified: 0 };

  const walk = (a: any, b: any, path: string): void => {
    const aKeys = a && typeof a === 'object' ? Object.keys(a) : [];
    const bKeys = b && typeof b === 'object' ? Object.keys(b) : [];
    const allKeys = new Set([...aKeys, ...bKeys]);

    for (const key of allKeys) {
      const nextPath = path ? `${path}.${key}` : key;
      const aVal = a ? (a as any)[key] : undefined;
      const bVal = b ? (b as any)[key] : undefined;

      if (aVal === undefined && bVal !== undefined) {
        keyDifferences.added++;
        structuralChanges.push(`${nextPath} added`);
        continue;
      }
      if (aVal !== undefined && bVal === undefined) {
        keyDifferences.removed++;
        structuralChanges.push(`${nextPath} removed`);
        continue;
      }

      const typeA = getType(aVal);
      const typeB = getType(bVal);
      if (typeA !== typeB) {
        typeMismatches.push(`${nextPath}: ${typeA} -> ${typeB}`);
        keyDifferences.modified++;
        continue;
      }

      const bothObjects = typeA === 'object' || typeA === 'array';
      if (bothObjects) {
        walk(aVal, bVal, nextPath);
      } else if (aVal !== bVal) {
        keyDifferences.modified++;
        structuralChanges.push(`${nextPath} changed`);
      }
    }
  };

  walk(obj1, obj2, '');

  const similarity = calculateStructuralSimilarity(obj1, obj2);

  return { structuralChanges, similarity, keyDifferences, typeMismatches };
}

/** Content similarity using Levenshtein distance normalized by max length. */
export function calculateContentSimilarity(text1: string, text2: string): number {
  const a = text1 || '';
  const b = text2 || '';
  const maxLen = Math.max(a.length, b.length, 1);

  // For very large bodies, sample portions to avoid quadratic blowup
  const sample = (text: string): string => {
    if (text.length <= 10000) return text;
    const start = text.slice(0, 4000);
    const middle = text.slice(
      Math.floor(text.length / 2) - 2000,
      Math.floor(text.length / 2) + 2000
    );
    const end = text.slice(-4000);
    return `${start}${middle}${end}`;
  };

  const distance = levenshteinDistance(sample(a), sample(b));
  const similarity = 1 - distance / maxLen;
  return Math.max(0, Math.min(1, similarity));
}

/** Remove dynamic data to stabilize comparisons. */
export function normalizeResponse(body: string): string {
  if (!body) return '';
  return body
    .replace(/\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z/g, '') // ISO timestamps
    .replace(/\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b/gi, '') // UUIDs
    .replace(/session[_-]?id\s*[:=]\s*[A-Za-z0-9+/=\-_.]+/gi, '') // session ids
    .replace(/csrf[_-]?token\s*[:=]\s*[A-Za-z0-9+/=\-_.]+/gi, '') // csrf tokens
    .replace(/\d{10,13}/g, '') // long timestamps
    .trim();
}

/** Detect common encodings of a payload inside response text. */
export function detectEncoding(text: string, payload: string): EncodingInfo {
  const lowered = text || '';
  const markers: { type: EncodingInfo['type']; match: string }[] = [];

  if (lowered.includes('&lt;') || lowered.includes('&gt;')) {
    markers.push({ type: 'html', match: '&lt;' });
  }
  if (/%(3c|3e|22|27)/i.test(lowered)) {
    markers.push({ type: 'url', match: '%3c' });
  }
  if (/\\u00[a-f0-9]{2}/i.test(lowered)) {
    markers.push({ type: 'unicode', match: '\\u003c' });
  }
  if (/^[A-Za-z0-9+/=]+$/m.test(payload) && lowered.includes(payload)) {
    markers.push({ type: 'base64', match: payload.slice(0, 8) });
  }

  if (payload) {
    const encodedHtml = payload.replace(/</g, '&lt;').replace(/>/g, '&gt;');
    if (lowered.includes(encodedHtml)) markers.push({ type: 'html', match: encodedHtml });
    const encodedUrl = encodeURIComponent(payload);
    if (lowered.includes(encodedUrl)) markers.push({ type: 'url', match: encodedUrl });
    const unicodeEscaped = payload.replace(/</g, '\\u003c').replace(/>/g, '\\u003e');
    if (lowered.includes(unicodeEscaped)) markers.push({ type: 'unicode', match: unicodeEscaped });
  }

  if (!markers.length) {
    return { type: 'none', confidence: 0, examples: [] };
  }

  const top = markers[0]!;
  const confidence = Math.min(1, 0.5 + markers.length * 0.1);
  return { type: top.type, confidence, examples: markers.map((m) => m.match) };
}

/** Match error patterns with categorization and contextual snippets. */
export function matchErrorPatterns(text: string): ErrorMatchResult {
  if (!text) return { matched: false, patterns: [], category: '', snippets: [], confidence: 0 };

  const matches = findErrorPatterns(text) || [];
  const snippets: string[] = [];
  const seenPatterns = new Set<string>();

  for (const { pattern } of matches) {
    seenPatterns.add(pattern.source);
    const regex = new RegExp(
      pattern,
      pattern.flags.includes('g') ? pattern.flags : `${pattern.flags}g`
    );
    let exec: RegExpExecArray | null;
    while ((exec = regex.exec(text))) {
      const start = Math.max(0, exec.index - 50);
      const end = Math.min(text.length, exec.index + (exec[0]?.length || 0) + 50);
      snippets.push(text.slice(start, end));
      if (!regex.global) break;
    }
  }

  const category = categorizeError(text) || inferCategory(matches.map((m) => m.pattern));
  const confidence = Math.min(1, 0.4 + seenPatterns.size * 0.1);

  return {
    matched: seenPatterns.size > 0,
    patterns: Array.from(seenPatterns),
    category: category || '',
    snippets: snippets.slice(0, 5),
    confidence,
  };
}

// --- Internal helpers -----------------------------------------------------

function getType(value: any): string {
  if (Array.isArray(value)) return 'array';
  return typeof value;
}

function inferCategory(patterns: RegExp[]): string {
  const sources = patterns.map((p) => p.source);
  if (patterns.some((p) => SQL_ERROR_PATTERNS.includes(p))) return 'SQL Error';
  if (patterns.some((p) => STACK_TRACE_PATTERNS.includes(p))) return 'Stack Trace';
  if (patterns.some((p) => PATH_DISCLOSURE_PATTERNS.includes(p))) return 'Path Disclosure';
  if (patterns.some((p) => COMMAND_INJECTION_ERROR_PATTERNS.includes(p)))
    return 'Command Injection';
  if (patterns.some((p) => APPLICATION_ERROR_PATTERNS.includes(p))) return 'Application Error';
  return sources.length ? 'Error' : '';
}
