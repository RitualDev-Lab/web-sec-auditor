import type { SastRule } from "../../types/index.js";
import { findMatchesInContent } from "../utils.js";

export const ssrfMisconfigRules: SastRule[] = [
  {
    id: "SEC-SSRF-UNVALIDATED",
    name: "Server-Side Request Forgery (SSRF) via Untrusted URL Fetch",
    category: "INJECTION",
    severity: "HIGH",
    cwe: "CWE-918",
    owasp: "A10:2021-Server-Side Request Forgery",
    description:
      "A server-side HTTP request is initiated using an unvalidated user-supplied URL parameter. An attacker can probe internal services (127.0.0.1, RFC 1918) or cloud instance metadata (169.254.169.254).",
    remediation:
      "Enforce an allowlist of trusted destination hostnames and explicitly block private IP addresses, loopback addresses, and cloud metadata endpoints.",
    languages: ["typescript", "javascript", "python", "go"],
    evaluate(content: string) {
      // Matches: fetch(req.query.url), axios.get(req.body.url), requests.get(request.args.get('url'))
      const regex =
        /(?:fetch|axios\.(?:get|post|request)|http\.(?:get|request)|requests\.(?:get|post))\s*\(\s*(?:req\.(?:query|body|params)\.[a-zA-Z0-9_]*url|request\.(?:args|form|GET|POST)\[)/i;
      return findMatchesInContent(content, regex);
    },
  },
  {
    id: "SEC-CONF-DISABLE-TLS",
    name: "SSL / TLS Certificate Validation Disabled",
    category: "AUTH",
    severity: "CRITICAL",
    cwe: "CWE-295",
    owasp: "A02:2021-Cryptographic Failures",
    description:
      "TLS certificate verification is disabled via rejectUnauthorized: false, NODE_TLS_REJECT_UNAUTHORIZED = '0', or verify=False. This leaves all outbound HTTPS connections vulnerable to man-in-the-middle decryption.",
    remediation:
      "Never disable TLS verification in production. Import proper internal CA root certificates if testing against internal endpoints.",
    languages: ["typescript", "javascript", "python", "go"],
    evaluate(content: string) {
      // Matches: rejectUnauthorized: false, NODE_TLS_REJECT_UNAUTHORIZED = '0', verify=False, InsecureSkipVerify: true
      const regex =
        /(?:rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]0['"]|verify\s*=\s*False|InsecureSkipVerify\s*:\s*true)/i;
      return findMatchesInContent(content, regex);
    },
  },
  {
    id: "SEC-CONF-DEBUG",
    name: "Production Debug Mode Enabled",
    category: "DISCLOSURE",
    severity: "MEDIUM",
    cwe: "CWE-489",
    owasp: "A05:2021-Security Misconfiguration",
    description:
      "Debug flags are set to true in source code. In production, this can leak detailed stack traces, internal paths, and environment state to attackers.",
    remediation:
      "Ensure debug mode is conditionally driven by environment variables and strictly disabled in production (e.g. DEBUG = process.env.NODE_ENV !== 'production').",
    languages: ["typescript", "javascript", "python"],
    evaluate(content: string) {
      // Matches: DEBUG = True, debug: true, debug=True, app.run(debug=True)
      const regex =
        /(?:DEBUG\s*=\s*True|\bdebug\s*[:=]\s*(?:true|True)|app\.run\([^)]*debug\s*=\s*True)/i;
      return findMatchesInContent(content, regex);
    },
  },
];
