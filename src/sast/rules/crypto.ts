import type { SastRule } from "../../types/index.js";
import { findMatchesInContent } from "../utils.js";

export const cryptoRules: SastRule[] = [
  {
    id: "SEC-CRYP-WEAK-HASH",
    name: "Broken Cryptographic Hash (MD5 / SHA-1)",
    category: "AUTH",
    severity: "HIGH",
    cwe: "CWE-328",
    owasp: "A02:2021-Cryptographic Failures",
    description:
      "Use of cryptographically broken hash functions (MD5 or SHA-1) was detected. These algorithms are vulnerable to collision and preimage attacks.",
    remediation:
      "Use modern secure hash algorithms such as SHA-256, SHA-512, or specialized password hashing algorithms (bcrypt, Argon2, scrypt).",
    languages: ["typescript", "javascript", "python", "go"],
    evaluate(content: string) {
      // Matches: createHash('md5'), createHash('sha1'), hashlib.md5(), md5.New()
      const regex =
        /(?:createHash\s*\(\s*["'](?:md5|sha1)["']|hashlib\.(?:md5|sha1)\s*\(|md5\.New\s*\(|sha1\.New\s*\()/i;
      return findMatchesInContent(content, regex);
    },
  },
  {
    id: "SEC-CRYP-JWT-NONE",
    name: "JWT Insecure 'none' Algorithm Allowed",
    category: "AUTH",
    severity: "CRITICAL",
    cwe: "CWE-327",
    owasp: "A02:2021-Cryptographic Failures",
    description:
      "JWT verification allows the 'none' algorithm, permitting an attacker to forge arbitrary claims with no signature.",
    remediation:
      "Explicitly enforce approved signature algorithms when verifying JWTs: jwt.verify(token, secret, { algorithms: ['HS256'] }).",
    languages: ["typescript", "javascript", "python"],
    evaluate(content: string) {
      // Matches: algorithms: ['none'], "none" in algorithms
      const regex = /(?:algorithms\s*:\s*\[[^\]]*["']none["']|algorithm\s*=\s*["']none["'])/i;
      return findMatchesInContent(content, regex);
    },
  },
  {
    id: "SEC-CRYP-INSECURE-RANDOM",
    name: "Insecure Pseudorandom Number Generator in Security Context",
    category: "AUTH",
    severity: "MEDIUM",
    cwe: "CWE-338",
    owasp: "A02:2021-Cryptographic Failures",
    description:
      "Math.random() is not cryptographically secure and predictable. It must not be used for session IDs, tokens, reset links, or password generation.",
    remediation:
      "Use crypto.randomBytes() or crypto.getRandomValues() for generating security-sensitive random values.",
    languages: ["typescript", "javascript", "python"],
    evaluate(content: string) {
      // Matches: (token|secret|session|code|csrf|key)\s*=\s*.*Math\.random\(\)
      const regex =
        /(?:token|secret|session|code|csrf|key|auth|nonce|salt)\s*[:=]\s*[^;\n]*Math\.random\s*\(\)/i;
      return findMatchesInContent(content, regex);
    },
  },
  {
    id: "SEC-CRYP-FALLBACK-SECRET",
    name: "Hardcoded Cryptographic Fallback Secret",
    category: "AUTH",
    severity: "HIGH",
    cwe: "CWE-798",
    owasp: "A07:2021-Identification and Authentication Failures",
    description:
      "A hardcoded fallback default secret was detected in environment variable assignment. If the env var is missing in production, this default secret will be used.",
    remediation:
      "Throw a startup configuration error if the secret environment variable is missing in production, rather than providing a default fallback string.",
    languages: ["typescript", "javascript", "python"],
    evaluate(content: string) {
      // Matches: process.env.JWT_SECRET || "secret"
      const regex =
        /(?:JWT_SECRET|SECRET_KEY|SESSION_SECRET|API_SECRET)\s*(?:\|\||\?\?)\s*["'][^"']+["']/i;
      return findMatchesInContent(content, regex);
    },
  },
];
