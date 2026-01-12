/**
 * Statistical helper utilities to improve verification accuracy.
 * Provides outlier detection, t-tests, confidence intervals, adaptive sampling,
 * and content/structure similarity helpers used by verification techniques.
 */

/** Outlier detection using the Interquartile Range (IQR) method. */
export function detectOutliers(samples: number[]): { cleaned: number[]; outliers: number[] } {
  if (!samples.length) return { cleaned: [], outliers: [] };
  const sorted = [...samples].sort((a, b) => a - b);
  const q1 = percentile(sorted, 0.25);
  const q3 = percentile(sorted, 0.75);
  const iqr = q3 - q1;
  const lower = q1 - 1.5 * iqr;
  const upper = q3 + 1.5 * iqr;
  const cleaned: number[] = [];
  const outliers: number[] = [];

  for (const s of sorted) {
    if (s < lower || s > upper) {
      outliers.push(s);
    } else {
      cleaned.push(s);
    }
  }

  return { cleaned: cleaned.length ? cleaned : sorted, outliers };
}

/** Two-sample Welch's t-test (unequal variances) with normal-approx p-value. */
export function performTTest(
  baseline: number[],
  withPayload: number[]
): { tStatistic: number; pValue: number; isSignificant: boolean } {
  if (baseline.length < 2 || withPayload.length < 2) {
    return { tStatistic: 0, pValue: 1, isSignificant: false };
  }

  const meanA = mean(baseline);
  const meanB = mean(withPayload);
  const varA = variance(baseline, meanA);
  const varB = variance(withPayload, meanB);
  const nA = baseline.length;
  const nB = withPayload.length;

  const numerator = meanB - meanA;
  const denom = Math.sqrt(varA / nA + varB / nB) || Number.EPSILON;
  const tStatistic = numerator / denom;

  // Welch–Satterthwaite approximation for degrees of freedom
  const dfNumerator = Math.pow(varA / nA + varB / nB, 2);
  const dfDenominator = Math.pow(varA / nA, 2) / (nA - 1) + Math.pow(varB / nB, 2) / (nB - 1);
  const degreesFreedom = Math.max(1, dfNumerator / (dfDenominator || Number.EPSILON));

  // Approximate two-tailed p-value using normal CDF fallback for large df
  const pValue = approximateTwoTailedPValue(tStatistic, degreesFreedom);
  const isSignificant = pValue < 0.05;

  return { tStatistic, pValue, isSignificant };
}

/** Confidence interval for the mean using z-score approximation. */
export function calculateConfidenceInterval(
  samples: number[],
  confidenceLevel: number = 0.95
): { lower: number; upper: number; mean: number } {
  if (!samples.length) return { lower: 0, upper: 0, mean: 0 };
  const m = mean(samples);
  const std = Math.sqrt(variance(samples, m));
  const z = zScoreForConfidence(confidenceLevel);
  const margin = z * (std / Math.sqrt(Math.max(1, samples.length)));
  return { lower: m - margin, upper: m + margin, mean: m };
}

/** Determine optimal sample size based on coefficient of variation (CV). */
export function determineOptimalSamples(initialSamples: number[], maxSamples: number): number {
  if (!initialSamples.length) return Math.min(5, maxSamples);
  const m = mean(initialSamples);
  const std = Math.sqrt(variance(initialSamples, m));
  const cv = m === 0 ? 0 : std / m;
  if (cv > 0.3) {
    // Increase samples when variance is high, but cap at maxSamples
    const proposed = Math.min(maxSamples, initialSamples.length + 2);
    return proposed;
  }
  return initialSamples.length;
}

/** Classic Levenshtein distance for content similarity. */
export function levenshteinDistance(str1: string, str2: string): number {
  const a = str1 ?? '';
  const b = str2 ?? '';
  const matrix: number[][] = Array.from({ length: a.length + 1 }, () =>
    new Array(b.length + 1).fill(0)
  );

  for (let i = 0; i <= a.length; i++) matrix[i]![0] = i;
  for (let j = 0; j <= b.length; j++) matrix[0]![j] = j;

  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      matrix[i]![j] = Math.min(
        matrix[i - 1]![j]! + 1,
        matrix[i]![j - 1]! + 1,
        matrix[i - 1]![j - 1]! + cost
      );
    }
  }

  return matrix[a.length]![b.length]!;
}

/** Structural similarity between two JSON-like objects (0-1). */
export function calculateStructuralSimilarity(obj1: any, obj2: any): number {
  const metrics1 = extractStructureMetrics(obj1);
  const metrics2 = extractStructureMetrics(obj2);

  if (metrics1.totalKeys === 0 && metrics2.totalKeys === 0) return 1;

  const keyScore =
    1 -
    Math.abs(metrics1.totalKeys - metrics2.totalKeys) /
      Math.max(metrics1.totalKeys, metrics2.totalKeys, 1);
  const depthScore =
    1 - Math.abs(metrics1.depth - metrics2.depth) / Math.max(metrics1.depth, metrics2.depth, 1);
  const arrayScore =
    1 - Math.abs(metrics1.arrays - metrics2.arrays) / Math.max(metrics1.arrays, metrics2.arrays, 1);

  return clamp((keyScore + depthScore + arrayScore) / 3, 0, 1);
}

// --- Internal helpers -----------------------------------------------------

function mean(arr: number[]): number {
  return arr.reduce((a, b) => a + b, 0) / Math.max(1, arr.length);
}

function variance(arr: number[], m: number): number {
  if (arr.length <= 1) return 0;
  return arr.reduce((sum, value) => sum + Math.pow(value - m, 2), 0) / (arr.length - 1);
}

function percentile(sorted: number[], p: number): number {
  if (!sorted.length) return 0;
  const idx = (sorted.length - 1) * p;
  const lower = Math.floor(idx);
  const upper = Math.ceil(idx);
  if (lower === upper) return sorted[lower] ?? 0;
  const weight = idx - lower;
  const lowerVal = sorted[lower] ?? 0;
  const upperVal = sorted[upper] ?? lowerVal;
  return lowerVal * (1 - weight) + upperVal * weight;
}

function clamp(value: number, min: number, max: number): number {
  return Math.min(max, Math.max(min, value));
}

function zScoreForConfidence(level: number): number {
  const clamped = clamp(level, 0.5, 0.999);
  // Common z-scores for typical confidence levels
  if (Math.abs(clamped - 0.9) < 0.001) return 1.645;
  if (Math.abs(clamped - 0.95) < 0.001) return 1.96;
  if (Math.abs(clamped - 0.98) < 0.001) return 2.33;
  if (Math.abs(clamped - 0.99) < 0.001) return 2.576;
  // Fallback using inverse error function approximation
  const twoSided = 1 - (1 - clamped) / 2;
  return inverseNormalCDF(twoSided);
}

function inverseNormalCDF(p: number): number {
  // Beasley-Springer/Moro approximation
  const a = [2.50662823884, -18.61500062529, 41.39119773534, -25.44106049637];
  const b = [-8.4735109309, 23.08336743743, -21.06224101826, 3.13082909833];
  const c = [
    0.3374754822726147, 0.9761690190917186, 0.1607979714918209, 0.0276438810333863,
    0.0038405729373609, 0.0003951896511919, 0.0000321767881768, 0.0000002888167364,
    0.0000003960315187,
  ];

  if (p < 0 || p > 1) return 0;
  if (p === 0) return -Infinity;
  if (p === 1) return Infinity;
  const y = p - 0.5;
  if (Math.abs(y) < 0.42) {
    const r = y * y;
    const num = a[0]! + a[1]! * r + a[2]! * r * r + a[3]! * r * r * r;
    const den = 1 + b[0]! * r + b[1]! * r * r + b[2]! * r * r * r + b[3]! * r * r * r * r;
    return (y * num) / den;
  }
  const r = y > 0 ? 1 - p : p;
  const s = Math.log(-Math.log(r));
  let t: number = c[0]!;
  for (let i = 1; i < c.length; i++) {
    t += (c[i] ?? 0) * Math.pow(s, i);
  }
  return y < 0 ? -t : t;
}

function normalCdf(x: number): number {
  return 0.5 * (1 + erf(x / Math.SQRT2));
}

function erf(x: number): number {
  // Numerical approximation (Abramowitz and Stegun)
  const sign = x < 0 ? -1 : 1;
  const a1 = 0.254829592;
  const a2 = -0.284496736;
  const a3 = 1.421413741;
  const a4 = -1.453152027;
  const a5 = 1.061405429;
  const p = 0.3275911;
  const absX = Math.abs(x);
  const t = 1 / (1 + p * absX);
  const y = 1 - ((((a5 * t + a4) * t + a3) * t + a2) * t + a1) * t * Math.exp(-absX * absX);
  return sign * y;
}

function approximateTwoTailedPValue(t: number, df: number): number {
  // For df > 30, use normal approximation; otherwise adjust slightly
  const absT = Math.abs(t);
  const adjusted = df > 30 ? absT : absT * Math.sqrt((df - 2) / df);
  const tail = 1 - normalCdf(adjusted);
  return clamp(2 * tail, 0, 1);
}

function extractStructureMetrics(obj: any): { totalKeys: number; arrays: number; depth: number } {
  const seen = new Set<any>();
  const walk = (value: any, depth: number): { keys: number; arrays: number; maxDepth: number } => {
    if (value === null || typeof value !== 'object' || seen.has(value)) {
      return { keys: 0, arrays: 0, maxDepth: depth };
    }
    seen.add(value);
    let keys = 0;
    let arrays = Array.isArray(value) ? 1 : 0;
    let maxDepth = depth;
    for (const key of Object.keys(value)) {
      keys += 1;
      const child = walk(value[key], depth + 1);
      keys += child.keys;
      arrays += child.arrays;
      maxDepth = Math.max(maxDepth, child.maxDepth);
    }
    return { keys, arrays, maxDepth };
  };
  const res = walk(obj, 1);
  return { totalKeys: res.keys, arrays: res.arrays, depth: res.maxDepth };
}
