import type { HeaderAuditItem, SecurityFinding } from "../types/index.js";

export function evaluateSecurityHeaders(
  headers: Record<string, string | undefined>,
  isHttps: boolean,
): { headerItems: HeaderAuditItem[]; findings: SecurityFinding[] } {
  const headerItems: HeaderAuditItem[] = [];
  const findings: SecurityFinding[] = [];

  // Normalize all header keys to lowercase
  const normalized: Record<string, string> = {};
  for (const [k, v] of Object.entries(headers)) {
    if (v !== undefined) {
      normalized[k.toLowerCase()] = v;
    }
  }

  // 1. Content-Security-Policy (CSP)
  const csp = normalized["content-security-policy"];
  if (!csp) {
    headerItems.push({
      name: "Content-Security-Policy",
      present: false,
      status: "MISSING",
      issues: ["Content-Security-Policy header is missing."],
      recommendation:
        "Implement a strict Content-Security-Policy (e.g. \"default-src 'self'; script-src 'self' 'nonce-...' \") to prevent Cross-Site Scripting (XSS) and data injection.",
    });
    findings.push({
      id: "SEC-HDR-CSP-MISSING",
      category: "HEADERS",
      title: "Missing Content-Security-Policy (CSP)",
      severity: "HIGH",
      scoreImpact: 20,
      cwe: "CWE-693",
      owasp: "A05:2021-Security Misconfiguration",
      description:
        "The web application does not enforce a Content-Security-Policy header. Browsers will execute any resource without restricting script or style origins.",
      remediation:
        "Define a strict Content-Security-Policy header restricting script-src, object-src, and default-src to trusted origins with cryptographic nonces or hashes.",
      references: [
        "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",
        "https://owasp.org/www-community/attacks/xss/",
      ],
    });
  } else {
    const issues: string[] = [];
    if (csp.includes("'unsafe-inline'") && !csp.includes("'nonce-") && !csp.includes("'sha256-")) {
      issues.push("Allows 'unsafe-inline' scripts without nonce or hash protection.");
      findings.push({
        id: "SEC-HDR-CSP-UNSAFE-INLINE",
        category: "HEADERS",
        title: "Content-Security-Policy Allows 'unsafe-inline'",
        severity: "MEDIUM",
        scoreImpact: 10,
        cwe: "CWE-79",
        owasp: "A03:2021-Injection",
        description:
          "The CSP contains 'unsafe-inline' without nonces or hashes, significantly increasing vulnerability to Cross-Site Scripting (XSS).",
        evidence: `Content-Security-Policy: ${csp}`,
        remediation:
          "Remove 'unsafe-inline' and use cryptographic nonces ('nonce-...') or SHA-256 hashes for legitimate inline scripts.",
        references: ["https://web.dev/strict-csp/"],
      });
    }

    if (csp.includes("'unsafe-eval'")) {
      issues.push("Allows 'unsafe-eval' enabling dynamic code execution from strings.");
      findings.push({
        id: "SEC-HDR-CSP-UNSAFE-EVAL",
        category: "HEADERS",
        title: "Content-Security-Policy Allows 'unsafe-eval'",
        severity: "MEDIUM",
        scoreImpact: 10,
        cwe: "CWE-95",
        owasp: "A03:2021-Injection",
        description:
          "The CSP contains 'unsafe-eval', allowing eval(), Function(), and setTimeout(string) to execute arbitrary code.",
        evidence: `Content-Security-Policy: ${csp}`,
        remediation:
          "Refactor code to avoid eval() or code generation from strings and remove 'unsafe-eval' from CSP.",
      });
    }

    if (csp.includes("http://")) {
      issues.push("CSP permits unencrypted http:// resources.");
      findings.push({
        id: "SEC-HDR-CSP-INSECURE-HTTP",
        category: "HEADERS",
        title: "Content-Security-Policy Allows Insecure HTTP Resources",
        severity: "LOW",
        scoreImpact: 5,
        cwe: "CWE-319",
        description:
          "The CSP references plaintext http:// sources, exposing traffic to MitM tampering.",
        evidence: `Content-Security-Policy: ${csp}`,
        remediation:
          "Upgrade all source URLs in CSP to https:// or use 'upgrade-insecure-requests'.",
      });
    }

    headerItems.push({
      name: "Content-Security-Policy",
      present: true,
      value: csp,
      status: issues.length === 0 ? "OPTIMAL" : "SUBOPTIMAL",
      issues,
      recommendation:
        issues.length > 0 ? "Hardening CSP by removing unsafe keywords and wildcards." : undefined,
    });
  }

  // 2. Strict-Transport-Security (HSTS)
  const hsts = normalized["strict-transport-security"];
  if (isHttps) {
    if (!hsts) {
      headerItems.push({
        name: "Strict-Transport-Security",
        present: false,
        status: "MISSING",
        issues: ["Strict-Transport-Security (HSTS) header is missing on HTTPS origin."],
        recommendation:
          "Add Strict-Transport-Security: max-age=31536000; includeSubDomains; preload to enforce SSL/TLS.",
      });
      findings.push({
        id: "SEC-HDR-HSTS-MISSING",
        category: "HEADERS",
        title: "Missing Strict-Transport-Security (HSTS)",
        severity: "HIGH",
        scoreImpact: 15,
        cwe: "CWE-319",
        owasp: "A02:2021-Cryptographic Failures",
        description:
          "The web application serves HTTPS traffic but does not instruct browsers to remember HTTPS connection enforcement, leaving users vulnerable to SSL stripping MitM attacks.",
        remediation:
          "Configure your web server or edge proxy to send: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
        references: [
          "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html",
        ],
      });
    } else {
      const issues: string[] = [];
      const maxAgeMatch = hsts.match(/max-age=(\d+)/i);
      const maxAge = maxAgeMatch ? Number.parseInt(maxAgeMatch[1], 10) : 0;

      if (maxAge < 15552000) {
        // Less than 180 days
        issues.push(
          `HSTS max-age is short (${maxAge}s). Recommended is at least 31536000s (1 year).`,
        );
        findings.push({
          id: "SEC-HDR-HSTS-SHORT-MAXAGE",
          category: "HEADERS",
          title: "HSTS max-age Duration Too Short",
          severity: "LOW",
          scoreImpact: 5,
          cwe: "CWE-319",
          description: `Current HSTS max-age (${maxAge}s) is below the recommended 1-year threshold (31536000s).`,
          remediation: "Increase HSTS max-age to 31536000 (1 year) or greater.",
        });
      }

      if (!hsts.toLowerCase().includes("includesubdomains")) {
        issues.push("HSTS does not include 'includeSubDomains' directive.");
      }

      headerItems.push({
        name: "Strict-Transport-Security",
        present: true,
        value: hsts,
        status: issues.length === 0 ? "OPTIMAL" : "SUBOPTIMAL",
        issues,
      });
    }
  }

  // 3. X-Frame-Options
  const xfo = normalized["x-frame-options"];
  const cspHasFrameAncestors = csp?.includes("frame-ancestors");
  if (!xfo && !cspHasFrameAncestors) {
    headerItems.push({
      name: "X-Frame-Options",
      present: false,
      status: "MISSING",
      issues: ["X-Frame-Options header (or CSP frame-ancestors) is missing."],
      recommendation: "Add X-Frame-Options: DENY or SAMEORIGIN to prevent Clickjacking attacks.",
    });
    findings.push({
      id: "SEC-HDR-CLICKJACKING-RISK",
      category: "HEADERS",
      title: "Missing Clickjacking Protection (X-Frame-Options / frame-ancestors)",
      severity: "MEDIUM",
      scoreImpact: 10,
      cwe: "CWE-1021",
      owasp: "A05:2021-Security Misconfiguration",
      description:
        "The page can be embedded inside an <iframe> on external malicious websites, enabling UI redress and clickjacking attacks.",
      remediation:
        "Set 'X-Frame-Options: DENY' or 'Content-Security-Policy: frame-ancestors 'none';'.",
    });
  } else {
    headerItems.push({
      name: "X-Frame-Options",
      present: !!xfo,
      value: xfo || (cspHasFrameAncestors ? "Enforced via CSP frame-ancestors" : undefined),
      status: "OPTIMAL",
      issues: [],
    });
  }

  // 4. X-Content-Type-Options
  const xcto = normalized["x-content-type-options"];
  if (!xcto || !xcto.toLowerCase().includes("nosniff")) {
    headerItems.push({
      name: "X-Content-Type-Options",
      present: !!xcto,
      value: xcto,
      status: "MISSING",
      issues: ["X-Content-Type-Options header is missing or not set to 'nosniff'."],
      recommendation: "Set X-Content-Type-Options: nosniff to prevent MIME-sniffing attacks.",
    });
    findings.push({
      id: "SEC-HDR-XCTO-MISSING",
      category: "HEADERS",
      title: "Missing X-Content-Type-Options: nosniff",
      severity: "MEDIUM",
      scoreImpact: 10,
      cwe: "CWE-16",
      owasp: "A05:2021-Security Misconfiguration",
      description:
        "Without 'X-Content-Type-Options: nosniff', older browsers may attempt to sniff response content types, potentially executing user-uploaded files as scripts or HTML.",
      remediation: "Add header: X-Content-Type-Options: nosniff",
    });
  } else {
    headerItems.push({
      name: "X-Content-Type-Options",
      present: true,
      value: xcto,
      status: "OPTIMAL",
      issues: [],
    });
  }

  // 5. Referrer-Policy
  const referrerPolicy = normalized["referrer-policy"];
  if (!referrerPolicy) {
    headerItems.push({
      name: "Referrer-Policy",
      present: false,
      status: "MISSING",
      issues: ["Referrer-Policy header is missing."],
      recommendation:
        "Set Referrer-Policy: strict-origin-when-cross-origin to prevent leaking query params and path tokens.",
    });
    findings.push({
      id: "SEC-HDR-REFERRER-MISSING",
      category: "HEADERS",
      title: "Missing Referrer-Policy Header",
      severity: "LOW",
      scoreImpact: 5,
      cwe: "CWE-200",
      description:
        "When Referrer-Policy is missing, browsers may leak full URLs (including sensitive query parameters or session IDs) to third-party domains.",
      remediation: "Add header: Referrer-Policy: strict-origin-when-cross-origin",
    });
  } else {
    headerItems.push({
      name: "Referrer-Policy",
      present: true,
      value: referrerPolicy,
      status: "OPTIMAL",
      issues: [],
    });
  }

  // 6. Permissions-Policy
  const permissionsPolicy = normalized["permissions-policy"];
  if (!permissionsPolicy) {
    headerItems.push({
      name: "Permissions-Policy",
      present: false,
      status: "MISSING",
      issues: ["Permissions-Policy header is missing."],
      recommendation:
        "Set Permissions-Policy: camera=(), microphone=(), geolocation=() to restrict unnecessary browser capabilities.",
    });
  } else {
    headerItems.push({
      name: "Permissions-Policy",
      present: true,
      value: permissionsPolicy,
      status: "OPTIMAL",
      issues: [],
    });
  }

  // 7. Information Disclosure Headers (Server, X-Powered-By)
  const serverHeader = normalized.server;
  if (serverHeader && (/\d+\.\d+/.test(serverHeader) || serverHeader.length > 15)) {
    findings.push({
      id: "SEC-HDR-INFO-DISCLOSURE-SERVER",
      category: "DISCLOSURE",
      title: "Server Technology & Version Fingerprint Disclosed",
      severity: "LOW",
      scoreImpact: 5,
      cwe: "CWE-200",
      owasp: "A05:2021-Security Misconfiguration",
      description:
        "The Server header discloses precise backend server technology and version numbers, aiding attackers in searching for known CVEs.",
      evidence: `Server: ${serverHeader}`,
      remediation:
        "Suppress or sanitize the Server response header in your web server configuration.",
    });
  }

  const poweredBy = normalized["x-powered-by"];
  if (poweredBy) {
    findings.push({
      id: "SEC-HDR-INFO-DISCLOSURE-POWERED-BY",
      category: "DISCLOSURE",
      title: "X-Powered-By Technology Stack Disclosed",
      severity: "LOW",
      scoreImpact: 5,
      cwe: "CWE-200",
      description:
        "The X-Powered-By header advertises underlying application frameworks (e.g. Express, PHP, ASP.NET).",
      evidence: `X-Powered-By: ${poweredBy}`,
      remediation: "Remove the X-Powered-By header (e.g. in Express: app.disable('x-powered-by')).",
    });
  }

  return { headerItems, findings };
}
