import type { RuleMatch } from "../types/index.js";

/**
 * Scan content using a RegExp and return exact line, column, and trimmed code snippet for each match.
 * Skips empty lines and comment lines (//, #, *, /*) to eliminate false positives in docs and comments.
 */
export function findMatchesInContent(
  content: string,
  regex: RegExp,
  options?: { caseSensitive?: boolean; maxMatches?: number },
): RuleMatch[] {
  const matches: RuleMatch[] = [];
  const lines = content.split("\n");
  const max = options?.maxMatches ?? 50;

  for (let i = 0; i < lines.length; i++) {
    const lineText = lines[i];
    const trimmed = lineText.trim();
    // Skip empty lines and single-line comment / docblock lines
    if (
      !trimmed ||
      trimmed.startsWith("//") ||
      trimmed.startsWith("#") ||
      trimmed.startsWith("*") ||
      trimmed.startsWith("/*")
    ) {
      continue;
    }

    const r = new RegExp(regex.source, regex.flags);
    const m = r.exec(lineText);
    if (m) {
      const col = m.index + 1;
      const snippet = trimmed;
      matches.push({
        line: i + 1,
        column: col,
        snippet,
        evidence: m[0],
      });

      if (matches.length >= max) break;
    }
  }

  return matches;
}

/**
 * Detect language from file path extension.
 */
export function detectLanguage(
  filePath: string,
): "typescript" | "javascript" | "python" | "go" | "unknown" {
  const lower = filePath.toLowerCase();
  if (lower.endsWith(".ts") || lower.endsWith(".tsx")) return "typescript";
  if (
    lower.endsWith(".js") ||
    lower.endsWith(".jsx") ||
    lower.endsWith(".mjs") ||
    lower.endsWith(".cjs")
  ) {
    return "javascript";
  }
  if (lower.endsWith(".py")) return "python";
  if (lower.endsWith(".go")) return "go";
  return "unknown";
}
