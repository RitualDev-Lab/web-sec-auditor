import * as fs from "node:fs/promises";
import * as path from "node:path";
import type { PackageDependency } from "../types/index.js";

/**
 * Normalizes semver prefixes (^, ~, >=, =, >, <, v) to a clean baseline version string for advisory lookup.
 * E.g., '^4.17.21' -> '4.17.21', '~1.2.3' -> '1.2.3'.
 */
export function normalizeVersion(rawVersion: string): string {
  if (!rawVersion) return "0.0.0";
  // Strip common npm specifiers, url tags, or ranges
  const cleaned = rawVersion
    .trim()
    .replace(/^[\^~>=<v]+/, "")
    .trim();
  // If it's a multi-range like "1.0.0 || 2.0.0" or ">= 1.0.0 < 2.0.0", take the first segment
  const firstSegment = cleaned.split(/[\s|]+/)[0] || "0.0.0";
  return firstSegment;
}

/**
 * Parses package.json and extracts dependencies for SCA scanning.
 */
export async function parsePackageJson(
  manifestPath: string,
  options?: { includeDev?: boolean },
): Promise<PackageDependency[]> {
  const resolvedPath = path.resolve(manifestPath);
  const targetFile = resolvedPath.endsWith("package.json")
    ? resolvedPath
    : path.join(resolvedPath, "package.json");

  const raw = await fs.readFile(targetFile, "utf-8");
  const pkg = JSON.parse(raw);

  const deps: PackageDependency[] = [];

  if (pkg.dependencies && typeof pkg.dependencies === "object") {
    for (const [name, ver] of Object.entries(pkg.dependencies)) {
      if (typeof ver === "string") {
        deps.push({
          name,
          version: normalizeVersion(ver),
          isDev: false,
        });
      }
    }
  }

  if (options?.includeDev && pkg.devDependencies && typeof pkg.devDependencies === "object") {
    for (const [name, ver] of Object.entries(pkg.devDependencies)) {
      if (typeof ver === "string") {
        deps.push({
          name,
          version: normalizeVersion(ver),
          isDev: true,
        });
      }
    }
  }

  return deps;
}
