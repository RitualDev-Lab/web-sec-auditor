import * as fs from "node:fs/promises";
import * as path from "node:path";
import type {
  FindingSeverity,
  SastFinding,
  SastScanOptions,
  SastScanReport,
  SupportedLanguage,
} from "../types/index.js";
import { RuleRegistry } from "./registry.js";
import { detectLanguage } from "./utils.js";

const DEFAULT_EXCLUDE_DIRS = new Set([
  "node_modules",
  ".git",
  "dist",
  "build",
  "out",
  ".pnpm-store",
  ".next",
  ".turbo",
  "coverage",
  ".vscode",
  ".idea",
  "vendor",
]);

const SEVERITY_ORDER: Record<FindingSeverity, number> = {
  CRITICAL: 5,
  HIGH: 4,
  MEDIUM: 3,
  LOW: 2,
  INFO: 1,
};

export class SastScanner {
  private registry: RuleRegistry;

  constructor(registry: RuleRegistry = new RuleRegistry()) {
    this.registry = registry;
  }

  /**
   * Scan single file in-memory string content against registered rules.
   */
  public scanContent(content: string, filePath: string, options?: SastScanOptions): SastFinding[] {
    const lang = detectLanguage(filePath);
    if (lang === "unknown") return [];

    if (options?.languages && options.languages.length > 0) {
      if (!options.languages.includes("all") && !options.languages.includes(lang)) {
        return [];
      }
    }

    const rules = this.registry.getRulesForLanguage(lang, options?.threshold);
    const findings: SastFinding[] = [];

    for (const rule of rules) {
      const matches = rule.evaluate(content, filePath);
      for (const match of matches) {
        findings.push({
          id: `${rule.id}-${path.basename(filePath)}-L${match.line}`,
          ruleId: rule.id,
          category: rule.category,
          title: rule.name,
          severity: rule.severity,
          cwe: rule.cwe,
          owasp: rule.owasp,
          file: filePath,
          line: match.line,
          column: match.column,
          snippet: match.snippet,
          description: rule.description,
          remediation: rule.remediation,
        });
      }
    }

    return findings;
  }

  /**
   * Recursively walk a path (file or folder) and scan all supported code files.
   */
  public async scanPath(targetPath: string, options?: SastScanOptions): Promise<SastScanReport> {
    const startTime = Date.now();
    const resolvedPath = path.resolve(targetPath);
    const stat = await fs.stat(resolvedPath);

    const filesToScan: string[] = [];
    const maxSizeBytes = (options?.maxFileSizeKb ?? 1024) * 1024;
    const excludeDirs = new Set([...DEFAULT_EXCLUDE_DIRS, ...(options?.excludeDirs ?? [])]);

    if (stat.isFile()) {
      filesToScan.push(resolvedPath);
    } else if (stat.isDirectory()) {
      await this.collectFiles(resolvedPath, filesToScan, excludeDirs, maxSizeBytes);
    }

    const allFindings: SastFinding[] = [];

    for (const file of filesToScan) {
      try {
        const content = await fs.readFile(file, "utf-8");
        const fileFindings = this.scanContent(content, file, options);
        allFindings.push(...fileFindings);
      } catch {
        // Skip unreadable or binary files safely
      }
    }

    // Sort findings by severity descending, then by file and line
    allFindings.sort((a, b) => {
      const diff = SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity];
      if (diff !== 0) return diff;
      const fileDiff = a.file.localeCompare(b.file);
      if (fileDiff !== 0) return fileDiff;
      return a.line - b.line;
    });

    const summary = {
      critical: allFindings.filter((f) => f.severity === "CRITICAL").length,
      high: allFindings.filter((f) => f.severity === "HIGH").length,
      medium: allFindings.filter((f) => f.severity === "MEDIUM").length,
      low: allFindings.filter((f) => f.severity === "LOW").length,
      info: allFindings.filter((f) => f.severity === "INFO").length,
    };

    return {
      targetPath: resolvedPath,
      filesScanned: filesToScan.length,
      scanTimestamp: new Date().toISOString(),
      durationMs: Date.now() - startTime,
      summary,
      findings: allFindings,
    };
  }

  private async collectFiles(
    dir: string,
    filesList: string[],
    excludeDirs: Set<string>,
    maxSizeBytes: number,
  ): Promise<void> {
    let entries: import("node:fs").Dirent[] = [];
    try {
      entries = await fs.readdir(dir, { withFileTypes: true });
    } catch {
      return;
    }

    for (const entry of entries) {
      const fullPath = path.join(dir, entry.name);

      if (entry.isDirectory()) {
        if (!excludeDirs.has(entry.name)) {
          await this.collectFiles(fullPath, filesList, excludeDirs, maxSizeBytes);
        }
      } else if (entry.isFile()) {
        // Skip minified files
        if (entry.name.includes(".min.")) continue;

        // Skip non-code extensions quickly
        const lang = detectLanguage(fullPath);
        if (lang === "unknown") continue;

        try {
          const fileStat = await fs.stat(fullPath);
          if (fileStat.size <= maxSizeBytes) {
            filesList.push(fullPath);
          }
        } catch {
          // Skip if stat fails
        }
      }
    }
  }
}
