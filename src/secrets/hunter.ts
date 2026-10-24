import { execFile } from "node:child_process";
import * as fs from "node:fs/promises";
import * as path from "node:path";
import { promisify } from "node:util";
import type {
  FindingSeverity,
  SecretFinding,
  SecretScanOptions,
  SecretScanReport,
} from "../types/index.js";
import { calculateShannonEntropy } from "./entropy.js";
import { SECRET_PATTERNS } from "./patterns.js";

const execFileAsync = promisify(execFile);

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
  "vendor",
]);

const BINARY_EXTENSIONS = new Set([
  ".png",
  ".jpg",
  ".jpeg",
  ".gif",
  ".webp",
  ".svg",
  ".ico",
  ".pdf",
  ".zip",
  ".tar",
  ".gz",
  ".woff",
  ".woff2",
  ".ttf",
  ".eot",
  ".exe",
  ".dll",
  ".so",
  ".dylib",
  ".lock",
]);

const SEVERITY_ORDER: Record<FindingSeverity, number> = {
  CRITICAL: 5,
  HIGH: 4,
  MEDIUM: 3,
  LOW: 2,
  INFO: 1,
};

export class SecretHunter {
  /**
   * Scan single text content in-memory for exposed credentials and high-entropy secrets.
   */
  public scanContent(
    content: string,
    filePath: string,
    options?: SecretScanOptions,
  ): SecretFinding[] {
    const findings: SecretFinding[] = [];
    const lines = content.split("\n");

    for (let lineIdx = 0; lineIdx < lines.length; lineIdx++) {
      const lineText = lines[lineIdx];
      const trimmed = lineText.trim();
      if (!trimmed || trimmed.length > 1000) continue; // Skip empty or huge minified lines

      for (const pattern of SECRET_PATTERNS) {
        const regex = new RegExp(pattern.regex.source, pattern.regex.flags);
        let match: RegExpExecArray | null = regex.exec(lineText);

        while (match !== null) {
          const fullMatch = match[0];
          const targetSecret = match[1] || fullMatch;
          const entropy = calculateShannonEntropy(targetSecret);

          const minEnt = options?.minEntropy ?? pattern.minEntropy;
          const passesEntropy = minEnt === undefined || entropy >= minEnt;

          if (passesEntropy) {
            const masked = pattern.mask(fullMatch);
            const safeSnippet = trimmed.replace(fullMatch, masked);

            findings.push({
              id: `${pattern.id}-${path.basename(filePath)}-L${lineIdx + 1}`,
              patternId: pattern.id,
              title: pattern.name,
              severity: pattern.severity,
              file: filePath,
              line: lineIdx + 1,
              column: match.index + 1,
              maskedSecret: masked,
              entropy,
              snippet: safeSnippet,
              remediation:
                "Revoke and rotate this exposed credential immediately. Store secrets in environment variables or an enterprise secrets manager (e.g. AWS Secrets Manager, GCP Secret Manager, Vault).",
            });
          }

          if (!regex.global) break;
          match = regex.exec(lineText);
        }
      }
    }

    return findings;
  }

  /**
   * Recursively scan a file or folder for hardcoded secrets.
   */
  public async scanPath(
    targetPath: string,
    options?: SecretScanOptions,
  ): Promise<SecretScanReport> {
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

    const allFindings: SecretFinding[] = [];

    for (const file of filesToScan) {
      try {
        const content = await fs.readFile(file, "utf-8");
        const fileFindings = this.scanContent(content, file, options);
        allFindings.push(...fileFindings);
      } catch {
        // Skip binary or unreadable files safely
      }
    }

    allFindings.sort((a, b) => {
      const diff = SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity];
      if (diff !== 0) return diff;
      return a.file.localeCompare(b.file);
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

  /**
   * Scan git commit history diffs for previously committed or deleted secrets.
   */
  public async scanGitHistory(
    repoPath: string,
    options?: SecretScanOptions,
  ): Promise<SecretScanReport> {
    const startTime = Date.now();
    const resolvedPath = path.resolve(repoPath);
    const maxCommits = options?.maxCommits ?? 30;

    let gitOutput = "";
    try {
      const { stdout } = await execFileAsync("git", ["log", "-p", `--max-count=${maxCommits}`], {
        cwd: resolvedPath,
        maxBuffer: 10 * 1024 * 1024,
      });
      gitOutput = stdout;
    } catch {
      // Not a git repo or git not found
      return {
        targetPath: resolvedPath,
        filesScanned: 0,
        commitsScanned: 0,
        scanTimestamp: new Date().toISOString(),
        durationMs: Date.now() - startTime,
        summary: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
        findings: [],
      };
    }

    const lines = gitOutput.split("\n");
    let currentCommit = "";
    let currentAuthor = "";
    let currentFile = "unknown";
    let commitsCount = 0;
    const allFindings: SecretFinding[] = [];

    for (let idx = 0; idx < lines.length; idx++) {
      const line = lines[idx];

      if (line.startsWith("commit ")) {
        currentCommit = line.split(" ")[1] || "";
        commitsCount++;
        continue;
      }

      if (line.startsWith("Author: ")) {
        currentAuthor = line.replace("Author: ", "").trim();
        continue;
      }

      if (line.startsWith("diff --git a/")) {
        const parts = line.split(" ");
        if (parts[2]) {
          currentFile = parts[2].replace(/^a\//, "");
        }
        continue;
      }

      // Check added or modified lines in diff (+...)
      if (line.startsWith("+") && !line.startsWith("+++")) {
        const codeLine = line.slice(1); // Strip leading '+'
        const findings = this.scanContent(codeLine, currentFile, options);

        for (const f of findings) {
          allFindings.push({
            ...f,
            id: `${f.id}-git-${currentCommit.slice(0, 7)}`,
            line: idx + 1,
            commitHash: currentCommit,
            commitAuthor: currentAuthor,
          });
        }
      }
    }

    const summary = {
      critical: allFindings.filter((f) => f.severity === "CRITICAL").length,
      high: allFindings.filter((f) => f.severity === "HIGH").length,
      medium: allFindings.filter((f) => f.severity === "MEDIUM").length,
      low: allFindings.filter((f) => f.severity === "LOW").length,
      info: allFindings.filter((f) => f.severity === "INFO").length,
    };

    return {
      targetPath: resolvedPath,
      filesScanned: 0,
      commitsScanned: commitsCount,
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
        const ext = path.extname(entry.name).toLowerCase();
        if (BINARY_EXTENSIONS.has(ext)) continue;

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
