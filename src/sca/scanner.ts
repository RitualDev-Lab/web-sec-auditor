import * as path from "node:path";
import type { FindingSeverity, ScaFinding, ScaScanOptions, ScaScanReport } from "../types/index.js";
import { queryOsvBatch } from "./osv.js";
import { parsePackageJson } from "./parser.js";

const SEVERITY_ORDER: Record<FindingSeverity, number> = {
  CRITICAL: 5,
  HIGH: 4,
  MEDIUM: 3,
  LOW: 2,
  INFO: 1,
};

export class ScaScanner {
  private customFetch?: typeof fetch;

  constructor(options?: { customFetch?: typeof fetch }) {
    this.customFetch = options?.customFetch;
  }

  /**
   * Scan project manifest (package.json) for known vulnerabilities against OSV advisory database.
   */
  public async scanManifest(
    manifestPath: string,
    options?: ScaScanOptions,
  ): Promise<ScaScanReport> {
    const startTime = Date.now();
    const resolvedPath = path.resolve(manifestPath);

    const deps = await parsePackageJson(resolvedPath, {
      includeDev: options?.includeDev,
    });

    const rawFindings = await queryOsvBatch(deps, {
      timeoutMs: options?.timeoutMs,
      customFetch: this.customFetch,
    });

    let findings = rawFindings;
    if (options?.threshold) {
      const threshWeight = SEVERITY_ORDER[options.threshold];
      findings = findings.filter((f) => SEVERITY_ORDER[f.severity] >= threshWeight);
    }

    findings.sort((a, b) => {
      const diff = SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity];
      if (diff !== 0) return diff;
      return a.packageName.localeCompare(b.packageName);
    });

    const vulnerableSet = new Set(findings.map((f) => f.packageName));

    const summary = {
      critical: findings.filter((f) => f.severity === "CRITICAL").length,
      high: findings.filter((f) => f.severity === "HIGH").length,
      medium: findings.filter((f) => f.severity === "MEDIUM").length,
      low: findings.filter((f) => f.severity === "LOW").length,
      info: findings.filter((f) => f.severity === "INFO").length,
    };

    return {
      manifestPath: resolvedPath,
      ecosystem: "npm",
      totalDependencies: deps.length,
      vulnerableDependencies: vulnerableSet.size,
      scanTimestamp: new Date().toISOString(),
      durationMs: Date.now() - startTime,
      summary,
      findings,
    };
  }
}
