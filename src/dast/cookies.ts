import type { CookieAuditItem, SecurityFinding } from "../types/index.js";

const SENSITIVE_COOKIE_NAMES = [
  "session",
  "sess",
  "sid",
  "token",
  "auth",
  "jwt",
  "id",
  "user",
  "remember",
  "csrf",
  "xsrf",
];

export function evaluateCookies(
  rawCookies: string[] | string | undefined,
  isHttps: boolean,
): { cookieItems: CookieAuditItem[]; findings: SecurityFinding[] } {
  const cookieItems: CookieAuditItem[] = [];
  const findings: SecurityFinding[] = [];

  if (!rawCookies) {
    return { cookieItems, findings };
  }

  const cookieStrings = Array.isArray(rawCookies) ? rawCookies : [rawCookies];

  for (const raw of cookieStrings) {
    if (!raw.trim()) continue;

    const parts = raw.split(";").map((p) => p.trim());
    const [nameVal, ...attributes] = parts;
    const eqIdx = nameVal.indexOf("=");
    const name = eqIdx !== -1 ? nameVal.substring(0, eqIdx).trim() : nameVal.trim();
    const value = eqIdx !== -1 ? nameVal.substring(eqIdx + 1).trim() : "";

    const lowerAttrs = attributes.map((a) => a.toLowerCase());
    const secure = lowerAttrs.includes("secure");
    const httpOnly = lowerAttrs.includes("httponly");

    let sameSite: string | undefined;
    for (const attr of attributes) {
      if (attr.toLowerCase().startsWith("samesite=")) {
        sameSite = attr.substring(9).trim();
      }
    }

    const issues: string[] = [];
    const isSensitive = SENSITIVE_COOKIE_NAMES.some((k) => name.toLowerCase().includes(k));

    // 1. Secure Flag check
    if (isHttps && !secure) {
      issues.push("Cookie missing 'Secure' flag on HTTPS origin.");
      findings.push({
        id: `SEC-CK-NO-SECURE-${name.toUpperCase()}`,
        category: "COOKIES",
        title: `Cookie '${name}' Missing Secure Flag`,
        severity: isSensitive ? "HIGH" : "MEDIUM",
        scoreImpact: isSensitive ? 15 : 8,
        cwe: "CWE-614",
        owasp: "A05:2021-Security Misconfiguration",
        description: `Cookie '${name}' is transmitted without the Secure flag, allowing plaintext transmission if the user triggers an unencrypted HTTP request.`,
        evidence: `Set-Cookie: ${raw}`,
        remediation: `Add the 'Secure' directive to the Set-Cookie header for '${name}'.`,
      });
    }

    // 2. HttpOnly Flag check
    if (!httpOnly) {
      issues.push("Cookie missing 'HttpOnly' flag (accessible via JavaScript document.cookie).");
      if (isSensitive) {
        findings.push({
          id: `SEC-CK-NO-HTTPONLY-${name.toUpperCase()}`,
          category: "COOKIES",
          title: `Sensitive Cookie '${name}' Missing HttpOnly Flag`,
          severity: "HIGH",
          scoreImpact: 15,
          cwe: "CWE-1004",
          owasp: "A07:2021-Identification and Authentication Failures",
          description: `Sensitive authentication or session cookie '${name}' lacks the HttpOnly attribute, allowing client-side scripts to read it via document.cookie if an XSS vulnerability occurs.`,
          evidence: `Set-Cookie: ${raw}`,
          remediation: `Set 'HttpOnly' on '${name}' to prevent client-side JavaScript access.`,
        });
      }
    }

    // 3. SameSite Flag check
    if (!sameSite) {
      issues.push("Cookie missing 'SameSite' attribute (vulnerable to CSRF).");
      findings.push({
        id: `SEC-CK-NO-SAMESITE-${name.toUpperCase()}`,
        category: "COOKIES",
        title: `Cookie '${name}' Missing SameSite Attribute`,
        severity: isSensitive ? "MEDIUM" : "LOW",
        scoreImpact: isSensitive ? 10 : 5,
        cwe: "CWE-1275",
        owasp: "A01:2021-Broken Access Control",
        description: `Cookie '${name}' does not specify SameSite=Lax or SameSite=Strict, increasing risk of Cross-Site Request Forgery (CSRF).`,
        evidence: `Set-Cookie: ${raw}`,
        remediation: `Specify 'SameSite=Lax' (or 'SameSite=Strict') on the Set-Cookie header for '${name}'.`,
      });
    } else if (sameSite.toLowerCase() === "none" && !secure) {
      issues.push("SameSite=None requires Secure attribute.");
      findings.push({
        id: `SEC-CK-NONE-WITHOUT-SECURE-${name.toUpperCase()}`,
        category: "COOKIES",
        title: `Cookie '${name}' Uses SameSite=None Without Secure`,
        severity: "HIGH",
        scoreImpact: 15,
        cwe: "CWE-614",
        description:
          "Modern browsers reject SameSite=None cookies unless accompanied by the Secure directive.",
        evidence: `Set-Cookie: ${raw}`,
        remediation: `Add the 'Secure' attribute to cookie '${name}'.`,
      });
    }

    cookieItems.push({
      name,
      value,
      secure,
      httpOnly,
      sameSite,
      raw,
      issues,
    });
  }

  return { cookieItems, findings };
}
