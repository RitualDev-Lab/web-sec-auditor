import type { SastRule } from "../../types/index.js";
import { findMatchesInContent } from "../utils.js";

export const authAccessRules: SastRule[] = [
  {
    id: "SEC-AUTH-STORAGE",
    name: "Sensitive Auth Token in Web Storage (localStorage/sessionStorage)",
    category: "AUTH",
    severity: "HIGH",
    cwe: "CWE-922",
    owasp: "A07:2021-Identification and Authentication Failures",
    description:
      "Storing session tokens, JWTs, or passwords in browser localStorage or sessionStorage makes them accessible to any script executing on the page (XSS credential exfiltration).",
    remediation:
      "Store authentication tokens in HttpOnly, Secure, SameSite=Lax/Strict cookies so client-side JavaScript cannot read them.",
    languages: ["typescript", "javascript"],
    evaluate(content: string) {
      // Matches: localStorage.setItem('token', ...), sessionStorage.setItem('jwt', ...), etc.
      const regex =
        /(?:localStorage|sessionStorage)\.setItem\s*\(\s*["'][^"']*(?:token|jwt|auth|session|secret|credential|password)[^"']*["']/i;
      return findMatchesInContent(content, regex);
    },
  },
  {
    id: "SEC-AUTH-PASSWORD-LOG",
    name: "Sensitive Password or Credential in Log Output",
    category: "AUTH",
    severity: "MEDIUM",
    cwe: "CWE-532",
    owasp: "A09:2021-Security Logging and Monitoring Failures",
    description:
      "Sensitive variables (password, secret, api_key) or raw request bodies are printed directly to logs, risking credential exposure in logging aggregators.",
    remediation:
      "Redact passwords, credentials, and Authorization headers before writing request objects or credentials to logger streams.",
    languages: ["typescript", "javascript", "python", "go"],
    evaluate(content: string) {
      // Matches: console.log(..., password), logger.info(password), print(password)
      const regex =
        /(?:console\.(?:log|info|warn|error)|logger\.(?:info|debug|warn|error)|print)\s*\([^)]*(?:password|user\.password|req\.body\.password|secretKey|apiKey)/i;
      return findMatchesInContent(content, regex);
    },
  },
];
