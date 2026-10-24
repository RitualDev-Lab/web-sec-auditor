/**
 * Calculates the Shannon Entropy of a given string.
 * Measures information density / randomness.
 *
 * Random hex string (16 chars): ~3.5 - 4.0
 * Random base64 string (32 chars): ~4.5 - 5.5
 * English words: ~2.0 - 3.2
 */
export function calculateShannonEntropy(str: string): number {
  if (!str || str.length === 0) return 0;

  const frequencies = new Map<string, number>();
  for (const char of str) {
    frequencies.set(char, (frequencies.get(char) || 0) + 1);
  }

  let entropy = 0;
  const len = str.length;

  for (const count of frequencies.values()) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }

  return Number(entropy.toFixed(3));
}

/**
 * Redacts a secret token to safely surface in scan reports without disclosing plaintext credentials.
 * E.g., 'AKIAIOSFODNN7EXAMPLE' -> 'AKIA**************LE'
 */
export function maskSecret(secret: string, keepPrefix = 4, keepSuffix = 2): string {
  if (!secret) return "";
  if (secret.length <= keepPrefix + keepSuffix) {
    return "*".repeat(secret.length);
  }

  const prefix = secret.slice(0, keepPrefix);
  const suffix = keepSuffix > 0 ? secret.slice(-keepSuffix) : "";
  const maskedLength = secret.length - keepPrefix - keepSuffix;
  return `${prefix}${"*".repeat(maskedLength)}${suffix}`;
}
