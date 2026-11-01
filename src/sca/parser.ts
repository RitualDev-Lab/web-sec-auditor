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
          ecosystem: "npm",
        });
      }
    }
  }

  return deps.map((d) => ({ ...d, ecosystem: "npm" }));
}

/**
 * Parses Python requirements.txt file and extracts dependencies for SCA scanning.
 */
export async function parseRequirementsTxt(manifestPath: string): Promise<PackageDependency[]> {
  const resolvedPath = path.resolve(manifestPath);
  const targetFile = (await fs.stat(resolvedPath).catch(() => null))?.isDirectory()
    ? path.join(resolvedPath, "requirements.txt")
    : resolvedPath;

  const raw = await fs.readFile(targetFile, "utf-8");
  const lines = raw.split(/\r?\n/);
  const deps: PackageDependency[] = [];

  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#") || trimmed.startsWith("-")) continue;

    // Remove environment markers like ; python_version >= "3.8"
    const withoutMarker = trimmed.split(";")[0].trim();

    // Match package name and version operator
    const match = withoutMarker.match(
      /^([a-zA-Z0-9_\-\.]+)\s*(?:==|>=|<=|~=|!=|=)?\s*([0-9a-zA-Z\.\-]+)?/,
    );
    if (match) {
      const name = match[1];
      const version = match[2] ? normalizeVersion(match[2]) : "0.0.0";
      deps.push({
        name,
        version,
        isDev: false,
        ecosystem: "PyPI",
      });
    }
  }

  return deps;
}

/**
 * Parses Python poetry.lock file and extracts dependencies for SCA scanning.
 */
export async function parsePoetryLock(
  manifestPath: string,
  options?: { includeDev?: boolean },
): Promise<PackageDependency[]> {
  const resolvedPath = path.resolve(manifestPath);
  const targetFile = (await fs.stat(resolvedPath).catch(() => null))?.isDirectory()
    ? path.join(resolvedPath, "poetry.lock")
    : resolvedPath;

  const raw = await fs.readFile(targetFile, "utf-8");
  const blocks = raw.split("[[package]]");
  const deps: PackageDependency[] = [];

  for (let i = 1; i < blocks.length; i++) {
    const block = blocks[i];
    const nameMatch = block.match(/name\s*=\s*"([^"]+)"/);
    const versionMatch = block.match(/version\s*=\s*"([^"]+)"/);
    const categoryMatch = block.match(/category\s*=\s*"([^"]+)"/);

    if (nameMatch && versionMatch) {
      const isDev = categoryMatch ? categoryMatch[1].toLowerCase() === "dev" : false;
      if (isDev && !options?.includeDev) {
        continue;
      }
      deps.push({
        name: nameMatch[1],
        version: normalizeVersion(versionMatch[1]),
        isDev,
        ecosystem: "PyPI",
      });
    }
  }

  return deps;
}

/**
 * Parses Go go.sum lockfile and extracts module dependencies for SCA scanning.
 */
export async function parseGoSum(manifestPath: string): Promise<PackageDependency[]> {
  const resolvedPath = path.resolve(manifestPath);
  const targetFile = (await fs.stat(resolvedPath).catch(() => null))?.isDirectory()
    ? path.join(resolvedPath, "go.sum")
    : resolvedPath;

  const raw = await fs.readFile(targetFile, "utf-8");
  const lines = raw.split(/\r?\n/);
  const seen = new Set<string>();
  const deps: PackageDependency[] = [];

  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;

    // go.sum lines: <module> <version>[/go.mod] <hash>
    const parts = trimmed.split(/\s+/);
    if (parts.length < 2) continue;

    const moduleName = parts[0];
    const versionRaw = parts[1];

    // Skip the companion /go.mod hash lines
    if (versionRaw.endsWith("/go.mod")) continue;

    if (!seen.has(moduleName)) {
      seen.add(moduleName);
      // Clean Go version prefix if needed, or maintain semver
      const cleanedVer = versionRaw.startsWith("v") ? versionRaw.slice(1) : versionRaw;
      deps.push({
        name: moduleName,
        version: cleanedVer,
        isDev: false,
        ecosystem: "Go",
      });
    }
  }

  return deps;
}

export interface DetectedManifest {
  manifestPath: string;
  ecosystem: string;
  dependencies: PackageDependency[];
}

/**
 * Automatically detects the manifest format (package.json, requirements.txt, poetry.lock, go.sum)
 * and parses all dependencies with appropriate ecosystem metadata.
 */
export async function detectAndParseManifest(
  targetPath: string,
  options?: { includeDev?: boolean },
): Promise<DetectedManifest> {
  const resolved = path.resolve(targetPath);
  let stat: import("node:fs").Stats | null = null;
  try {
    stat = await fs.stat(resolved);
  } catch {
    throw new Error(`Manifest target path does not exist: ${resolved}`);
  }

  if (stat.isFile()) {
    const filename = path.basename(resolved).toLowerCase();
    if (filename === "package.json") {
      const deps = await parsePackageJson(resolved, options);
      return { manifestPath: resolved, ecosystem: "npm", dependencies: deps };
    }
    if (filename === "requirements.txt") {
      const deps = await parseRequirementsTxt(resolved);
      return { manifestPath: resolved, ecosystem: "PyPI", dependencies: deps };
    }
    if (filename === "poetry.lock") {
      const deps = await parsePoetryLock(resolved, options);
      return { manifestPath: resolved, ecosystem: "PyPI", dependencies: deps };
    }
    if (filename === "go.sum") {
      const deps = await parseGoSum(resolved);
      return { manifestPath: resolved, ecosystem: "Go", dependencies: deps };
    }
    // Default fallback to package.json parser
    const deps = await parsePackageJson(resolved, options);
    return { manifestPath: resolved, ecosystem: "npm", dependencies: deps };
  }

  // Target is a directory: probe known lockfiles in priority
  const candidates = [
    { file: "package.json", ecosystem: "npm", parser: (p: string) => parsePackageJson(p, options) },
    { file: "poetry.lock", ecosystem: "PyPI", parser: (p: string) => parsePoetryLock(p, options) },
    { file: "requirements.txt", ecosystem: "PyPI", parser: (p: string) => parseRequirementsTxt(p) },
    { file: "go.sum", ecosystem: "Go", parser: (p: string) => parseGoSum(p) },
  ];

  for (const c of candidates) {
    const candidatePath = path.join(resolved, c.file);
    try {
      await fs.access(candidatePath);
      const deps = await c.parser(candidatePath);
      return { manifestPath: candidatePath, ecosystem: c.ecosystem, dependencies: deps };
    } catch {
      // Continue to next candidate
    }
  }

  throw new Error(
    `No supported dependency manifest found in ${resolved} (expected package.json, requirements.txt, poetry.lock, or go.sum)`,
  );
}
