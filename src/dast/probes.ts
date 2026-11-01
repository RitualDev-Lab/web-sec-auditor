import type { DastScanOptions, SecurityFinding } from "../types/index.js";

/**
 * Non-destructive active probe checking for CORS arbitrary origin reflection.
 * Sends a request with Origin: https://evil.com and checks if it is echoed back.
 */
export async function probeCorsReflection(
  targetUrl: string,
  options?: DastScanOptions & { customFetch?: typeof fetch },
): Promise<SecurityFinding[]> {
  const findings: SecurityFinding[] = [];
  const fetchFn = options?.customFetch || fetch;
  const timeoutMs = options?.timeoutMs ?? 5000;

  try {
    const res = await fetchFn(targetUrl, {
      method: "OPTIONS",
      headers: {
        Origin: "https://evil.com",
        "Access-Control-Request-Method": "POST",
        "User-Agent": options?.userAgent || "WebSecAuditor-ActiveProbe",
      },
      signal: AbortSignal.timeout(timeoutMs),
    });

    const allowOrigin = res.headers.get("access-control-allow-origin");
    const allowCreds = res.headers.get("access-control-allow-credentials") === "true";

    if (allowOrigin === "https://evil.com" || allowOrigin === "evil.com") {
      findings.push({
        id: "DAST-ACTIVE-CORS-REFLECT",
        category: "CORS",
        title: "Active CORS Reflection Vulnerability (Arbitrary Origin Allowed)",
        severity: allowCreds ? "CRITICAL" : "HIGH",
        scoreImpact: allowCreds ? -30 : -20,
        cwe: "CWE-942",
        owasp: "A05:2021-Security Misconfiguration",
        description: `Endpoint dynamically reflects untrusted arbitrary Origin (${allowOrigin})${
          allowCreds ? " with Access-Control-Allow-Credentials: true" : ""
        }. Attackers can execute cross-origin requests to read sensitive authenticated responses.`,
        evidence: `Origin: https://evil.com -> Access-Control-Allow-Origin: ${allowOrigin}, Allow-Credentials: ${allowCreds}`,
        remediation:
          "Enforce an explicit static allowlist of trusted origins. Never echo back arbitrary incoming request Origin headers.",
        references: ["https://portswigger.net/web-security/cors"],
      });
    }
  } catch {
    // Non-destructive probe failure tolerated
  }

  return findings;
}

/**
 * Non-destructive active probe testing for missing anti-CSRF protection on state-changing requests.
 */
export async function probeCsrfMutations(
  targetUrl: string,
  options?: DastScanOptions & { customFetch?: typeof fetch },
): Promise<SecurityFinding[]> {
  const findings: SecurityFinding[] = [];
  const fetchFn = options?.customFetch || fetch;
  const timeoutMs = options?.timeoutMs ?? 5000;

  try {
    const res = await fetchFn(targetUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": options?.userAgent || "WebSecAuditor-ActiveProbe",
      },
      body: "__probe_check=1",
      signal: AbortSignal.timeout(timeoutMs),
    });

    // Check if mutation was accepted without standard anti-CSRF tokens or SameSite cookie protection
    const status = res.status;
    const hasCsrfHeader =
      res.headers.has("x-csrf-token") ||
      res.headers.has("x-xsrf-token") ||
      res.headers.has("csrf-token");

    // If endpoint responds with 2xx status without any anti-CSRF challenge or header
    if (status >= 200 && status < 300 && !hasCsrfHeader) {
      findings.push({
        id: "DAST-ACTIVE-CSRF-MISSING",
        category: "AUTH",
        title: "Potential Missing Anti-CSRF Protection on State-Changing Endpoint",
        severity: "MEDIUM",
        scoreImpact: -15,
        cwe: "CWE-352",
        owasp: "A01:2021-Broken Access Control",
        description:
          "Endpoint accepted a mutation POST request without requiring CSRF token validation headers or SameSite cookie protections.",
        evidence: `HTTP ${status} response on unauthenticated POST probe without CSRF tokens.`,
        remediation:
          "Implement synchronized token pattern (e.g. csurf / double-submit cookie) or ensure SameSite=Lax/Strict is strictly enforced on session cookies.",
        references: [
          "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html",
        ],
      });
    }
  } catch {
    // Non-destructive probe failure tolerated
  }

  return findings;
}

/**
 * Non-destructive active probe checking for GraphQL introspection and schema exposure.
 */
export async function probeGraphqlIntrospection(
  targetUrl: string,
  options?: DastScanOptions & { customFetch?: typeof fetch },
): Promise<SecurityFinding[]> {
  const findings: SecurityFinding[] = [];
  const fetchFn = options?.customFetch || fetch;
  const timeoutMs = options?.timeoutMs ?? 5000;

  // Probe candidates: current URL if contains graphql, or /graphql /api/graphql
  let probeUrls = [targetUrl];
  if (!targetUrl.toLowerCase().includes("graphql")) {
    try {
      const parsed = new URL(targetUrl);
      probeUrls = [
        new URL("/graphql", parsed.origin).toString(),
        new URL("/api/graphql", parsed.origin).toString(),
      ];
    } catch {
      probeUrls = [targetUrl];
    }
  }

  const introspectionQuery = JSON.stringify({
    query: "query IntrospectionProbe { __schema { queryType { name } types { name } } }",
  });

  for (const url of probeUrls) {
    try {
      const res = await fetchFn(url, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Accept: "application/json",
          "User-Agent": options?.userAgent || "WebSecAuditor-ActiveProbe",
        },
        body: introspectionQuery,
        signal: AbortSignal.timeout(timeoutMs),
      });

      if (res.status === 200) {
        const body = (await res.json()) as {
          data?: { __schema?: { types?: Array<{ name: string }> } };
        };
        if (body?.data?.__schema?.types && body.data.__schema.types.length > 0) {
          findings.push({
            id: "DAST-ACTIVE-GRAPHQL-INTROSPECTION",
            category: "DISCLOSURE",
            title: "GraphQL Introspection & Full Schema Exposure Enabled in Production",
            severity: "MEDIUM",
            scoreImpact: -15,
            cwe: "CWE-200",
            owasp: "A05:2021-Security Misconfiguration",
            description: `GraphQL endpoint (${url}) returned full schema introspection data including ${body.data.__schema.types.length} internal types and query definitions. Attackers use introspection to map internal data models and hidden fields.`,
            evidence: `Introspection returned schema with ${body.data.__schema.types.length} types at ${url}`,
            remediation:
              "Disable GraphQL introspection query execution in production environments (e.g. introspection: false in Apollo Server / Yoga).",
            references: ["https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html"],
          });
          break; // Avoid duplicate reports
        }
      }
    } catch {
      // Non-destructive probe failure tolerated
    }
  }

  return findings;
}

/**
 * Runs enabled active DAST dynamic security probes.
 */
export async function runActiveProbes(
  targetUrl: string,
  options?: DastScanOptions & { customFetch?: typeof fetch },
): Promise<SecurityFinding[]> {
  const probeOpts = options?.activeProbeOptions ?? {
    testCorsReflection: true,
    testCsrfMutations: true,
    testGraphqlIntrospection: true,
  };

  const results: SecurityFinding[] = [];

  if (probeOpts.testCorsReflection !== false) {
    const corsFindings = await probeCorsReflection(targetUrl, options);
    results.push(...corsFindings);
  }

  if (probeOpts.testCsrfMutations !== false) {
    const csrfFindings = await probeCsrfMutations(targetUrl, options);
    results.push(...csrfFindings);
  }

  if (probeOpts.testGraphqlIntrospection !== false) {
    const gqlFindings = await probeGraphqlIntrospection(targetUrl, options);
    results.push(...gqlFindings);
  }

  return results;
}
