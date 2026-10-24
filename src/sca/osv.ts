import type { FindingSeverity, PackageDependency, ScaFinding } from "../types/index.js";

interface OsvEvent {
  introduced?: string;
  fixed?: string;
}

interface OsvRange {
  type: string;
  events?: OsvEvent[];
}

interface OsvAffected {
  package?: {
    name: string;
    ecosystem: string;
  };
  ranges?: OsvRange[];
}

interface OsvSeverity {
  type: string;
  score: string;
}

interface OsvVulnerability {
  id: string;
  summary?: string;
  details?: string;
  aliases?: string[];
  severity?: OsvSeverity[];
  affected?: OsvAffected[];
  references?: Array<{ type: string; url: string }>;
}

interface OsvBatchResponse {
  results?: Array<{
    vulns?: OsvVulnerability[];
  }>;
}

export function parseCvssSeverity(vuln: OsvVulnerability): {
  severity: FindingSeverity;
  score?: number;
} {
  const cvssEntry = vuln.severity?.find((s) => s.type === "CVSS_V3" || s.type === "CVSS_V2");

  if (cvssEntry?.score) {
    const vector = cvssEntry.score.toUpperCase();

    // Check high-impact CVSS v3 vectors
    if (vector.includes("/C:H/I:H/A:H") || vector.includes("/PR:N/UI:N/S:C")) {
      return { severity: "CRITICAL", score: 9.8 };
    }
    if (vector.includes("/C:H") || vector.includes("/I:H") || vector.includes("/A:H")) {
      return { severity: "HIGH", score: 7.5 };
    }
    if (vector.includes("/C:L") || vector.includes("/I:L")) {
      return { severity: "MEDIUM", score: 5.3 };
    }
  }

  // Fallback: If summary mentions critical words or prototype pollution / RCE
  const text = `${vuln.id} ${vuln.summary || ""} ${vuln.details || ""}`.toLowerCase();
  if (
    text.includes("remote code execution") ||
    text.includes("rce") ||
    text.includes("command injection") ||
    text.includes("sql injection")
  ) {
    return { severity: "CRITICAL", score: 9.0 };
  }
  if (
    text.includes("prototype pollution") ||
    text.includes("path traversal") ||
    text.includes("ssrf") ||
    text.includes("authentication bypass")
  ) {
    return { severity: "HIGH", score: 7.5 };
  }

  return { severity: "MEDIUM", score: 5.0 };
}

export function extractPatchedVersion(vuln: OsvVulnerability): string | undefined {
  if (!vuln.affected) return undefined;
  for (const aff of vuln.affected) {
    if (aff.ranges) {
      for (const r of aff.ranges) {
        if (r.events) {
          for (const ev of r.events) {
            if (ev.fixed) return ev.fixed;
          }
        }
      }
    }
  }
  return undefined;
}

/**
 * Queries the Open Source Vulnerability (OSV) API in batch mode for npm package dependencies.
 */
export async function queryOsvBatch(
  dependencies: PackageDependency[],
  options?: { timeoutMs?: number; customFetch?: typeof fetch },
): Promise<ScaFinding[]> {
  if (dependencies.length === 0) return [];

  const fetchFn = options?.customFetch || fetch;
  const timeoutMs = options?.timeoutMs ?? 10000;

  const queries = dependencies.map((dep) => ({
    package: {
      name: dep.name,
      ecosystem: "npm",
    },
    version: dep.version,
  }));

  const url = "https://api.osv.dev/v1/querybatch";
  let osvResponse: OsvBatchResponse;

  try {
    const res = await fetchFn(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ queries }),
      signal: AbortSignal.timeout(timeoutMs),
    });

    if (!res.ok) {
      throw new Error(`OSV API returned status ${res.status}`);
    }

    osvResponse = (await res.json()) as OsvBatchResponse;
  } catch (err) {
    // If offline or network timeout, fail gracefully with diagnostic message
    console.warn(`⚠️ OSV API request warning: ${(err as Error).message}`);
    return [];
  }

  const findings: ScaFinding[] = [];
  const results = osvResponse.results || [];

  for (let idx = 0; idx < results.length; idx++) {
    const dep = dependencies[idx];
    const item = results[idx];
    if (!item?.vulns || item.vulns.length === 0) continue;

    for (const vuln of item.vulns) {
      const { severity, score } = parseCvssSeverity(vuln);
      const patchedVersion = extractPatchedVersion(vuln);
      const advisoryRef =
        vuln.references?.find((r) => r.type === "ADVISORY" || r.type === "WEB")?.url ||
        `https://osv.dev/vulnerability/${vuln.id}`;

      findings.push({
        id: vuln.id,
        packageName: dep.name,
        currentVersion: dep.version,
        patchedVersion,
        severity,
        cvssScore: score,
        title: vuln.summary || `Vulnerability in ${dep.name}@${dep.version}`,
        description: vuln.details?.slice(0, 300) || vuln.summary || "No description provided.",
        advisoryUrl: advisoryRef,
        remediation: patchedVersion
          ? `Upgrade ${dep.name} to version >= ${patchedVersion}`
          : `Review security advisory and replace or patch ${dep.name}`,
      });
    }
  }

  return findings;
}
