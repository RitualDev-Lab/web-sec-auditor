import type { CorsAuditResult, SecurityFinding } from "../types/index.js";

export function evaluateCors(headers: Record<string, string | undefined>): {
  corsResult: CorsAuditResult;
  findings: SecurityFinding[];
} {
  const findings: SecurityFinding[] = [];
  const normalized: Record<string, string> = {};
  for (const [k, v] of Object.entries(headers)) {
    if (v !== undefined) {
      normalized[k.toLowerCase()] = v;
    }
  }

  const origin = normalized["access-control-allow-origin"];
  const credentialsHeader = normalized["access-control-allow-credentials"];
  const allowsCredentials = credentialsHeader?.toLowerCase() === "true";
  const methods = normalized["access-control-allow-methods"]?.split(",").map((m) => m.trim());
  const allowedHeaders = normalized["access-control-allow-headers"]
    ?.split(",")
    .map((h) => h.trim());

  const issues: string[] = [];
  let isWildcardWithCredentials = false;
  let status: "SAFE" | "WARN" | "CRITICAL" = "SAFE";

  if (origin) {
    // 1. Wildcard origin + credentials
    if (origin === "*" && allowsCredentials) {
      isWildcardWithCredentials = true;
      status = "CRITICAL";
      issues.push(
        "Wildcard origin '*' used together with 'Access-Control-Allow-Credentials: true'.",
      );
      findings.push({
        id: "SEC-CORS-WILDCARD-CREDENTIALS",
        category: "CORS",
        title: "Dangerous CORS Configuration: Wildcard Origin With Credentials",
        severity: "CRITICAL",
        scoreImpact: 35,
        cwe: "CWE-942",
        owasp: "A01:2021-Broken Access Control",
        description:
          "The endpoint allows any origin (*) while simultaneously allowing credentials (cookies, authorization headers). This allows arbitrary malicious websites to read authenticated responses on behalf of users.",
        evidence: "Access-Control-Allow-Origin: *\nAccess-Control-Allow-Credentials: true",
        remediation:
          "Specify an explicit allowlist of trusted origins instead of wildcard '*', or disallow credentials.",
        references: ["https://portswigger.net/web-security/cors"],
      });
    }

    // 2. 'null' origin allowed
    if (origin.toLowerCase() === "null") {
      status = status === "CRITICAL" ? "CRITICAL" : "WARN";
      issues.push("Origin 'null' allowed. Sandboxed iframes or data: URIs can access responses.");
      findings.push({
        id: "SEC-CORS-NULL-ORIGIN",
        category: "CORS",
        title: "Insecure CORS 'null' Origin Permitted",
        severity: "HIGH",
        scoreImpact: 20,
        cwe: "CWE-942",
        owasp: "A01:2021-Broken Access Control",
        description:
          "Allowing Origin 'null' enables attackers to use sandboxed iframes (<iframe sandbox='allow-scripts'>) to bypass origin restrictions and exfiltrate data.",
        evidence: "Access-Control-Allow-Origin: null",
        remediation:
          "Never permit 'null' as a valid CORS origin. Validate against strict hostnames (e.g. https://app.example.com).",
      });
    }

    // 3. Dangerous HTTP methods allowed in CORS
    if (
      methods &&
      (methods.includes("*") || methods.includes("PUT") || methods.includes("DELETE"))
    ) {
      if (origin === "*") {
        issues.push(`Overly permissive CORS methods permitted: ${methods.join(", ")}.`);
      }
    }
  }

  const corsResult: CorsAuditResult = {
    allowedOrigin: origin,
    allowsCredentials,
    allowedMethods: methods,
    allowedHeaders,
    isWildcardWithCredentials,
    issues,
    status,
  };

  return { corsResult, findings };
}
