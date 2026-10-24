import type { SecretPattern } from "../types/index.js";
import { maskSecret } from "./entropy.js";

export const SECRET_PATTERNS: SecretPattern[] = [
  {
    id: "SEC-TOK-AWS-KEY",
    name: "AWS Access Key ID",
    category: "SECRETS",
    severity: "CRITICAL",
    description:
      "Plaintext AWS Access Key ID detected. If paired with a secret key, attackers can provision cloud resources or exfiltrate private data.",
    regex: /\b(AKIA[0-9A-Z]{16})\b/g,
    minEntropy: 2.8,
    mask: (m) => maskSecret(m, 4, 2),
  },
  {
    id: "SEC-TOK-GCP-API",
    name: "Google Cloud / Firebase API Key",
    category: "SECRETS",
    severity: "CRITICAL",
    description:
      "Plaintext Google Cloud / Firebase API Key exposed. May allow unauthorized access to GCP resources, Maps, or Firebase database nodes.",
    regex: /\b(AIza[0-9A-Za-z_\-]{30,40})\b/g,
    minEntropy: 3.5,
    mask: (m) => maskSecret(m, 4, 3),
  },
  {
    id: "SEC-TOK-OPENAI",
    name: "OpenAI API Secret Key",
    category: "SECRETS",
    severity: "CRITICAL",
    description:
      "OpenAI API key detected. Exposed keys allow unauthorized LLM inference billing and organization data access.",
    regex: /\b(sk-(?:proj-)?[a-zA-Z0-9_-]{20,})\b/g,
    minEntropy: 3.5,
    mask: (m) => maskSecret(m, 7, 3),
  },
  {
    id: "SEC-TOK-ANTHROPIC",
    name: "Anthropic Claude API Key",
    category: "SECRETS",
    severity: "CRITICAL",
    description:
      "Anthropic Claude API key detected. Can be abused for unauthorized API consumption and prompt exfiltration.",
    regex: /\b(sk-ant-(?:api03-)?[a-zA-Z0-9_-]{30,})\b/g,
    minEntropy: 3.5,
    mask: (m) => maskSecret(m, 10, 3),
  },
  {
    id: "SEC-TOK-STRIPE",
    name: "Stripe Live Secret Key",
    category: "SECRETS",
    severity: "CRITICAL",
    description:
      "Live Stripe secret key detected. Allows attackers to issue refunds, charge customer cards, and access transaction records.",
    regex: /\b([sr]k_live_[0-9a-zA-Z]{24,})\b/g,
    minEntropy: 3.2,
    mask: (m) => maskSecret(m, 8, 2),
  },
  {
    id: "SEC-TOK-GITHUB",
    name: "GitHub Personal Access Token",
    category: "SECRETS",
    severity: "CRITICAL",
    description:
      "GitHub Personal Access Token detected. Allows attackers to clone private repositories or push malicious code.",
    regex: /\b(ghp_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z_]{60,85})\b/g,
    minEntropy: 3.5,
    mask: (m) => maskSecret(m, 4, 3),
  },
  {
    id: "SEC-TOK-SLACK",
    name: "Slack Bot Token or Webhook URL",
    category: "SECRETS",
    severity: "HIGH",
    description:
      "Slack token or incoming webhook URL detected. Attackers can spam internal channels or intercept team messages.",
    regex:
      /\b(xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}|https:\/\/hooks\.slack\.com\/services\/T[a-zA-Z0-9_]+\/B[a-zA-Z0-9_]+\/[a-zA-Z0-9_]+)\b/g,
    mask: (m) => maskSecret(m, 8, 3),
  },
  {
    id: "SEC-TOK-PRIVATE-KEY",
    name: "Unencrypted Asymmetric Private Key",
    category: "SECRETS",
    severity: "CRITICAL",
    description:
      "Unencrypted private key detected (RSA, EC, OpenSSH, DSA). Attackers can decrypt TLS traffic or impersonate servers over SSH.",
    regex: /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/g,
    mask: () => "-----BEGIN [REDACTED] PRIVATE KEY-----",
  },
  {
    id: "SEC-TOK-DB-URI",
    name: "Database Connection URI with Embedded Credentials",
    category: "SECRETS",
    severity: "HIGH",
    description:
      "Database connection string with plaintext password detected. Attackers can connect directly to production databases.",
    regex: /(?:postgres|postgresql|mysql|mongodb(?:\+srv)?):\/\/[^:\s]+:([^@\s]+)@[^/\s]+/gi,
    mask: (m) => {
      return m.replace(/(:)([^@\s]+)(@)/, (_, p1, p2, p3) => `${p1}${maskSecret(p2, 1, 1)}${p3}`);
    },
  },
  {
    id: "SEC-TOK-GENERIC-ENTROPY",
    name: "High-Entropy Secret Variable Assignment",
    category: "SECRETS",
    severity: "HIGH",
    description:
      "High-entropy random string assigned to sensitive variable (secret, api_key, password, token). Likely an exposed credential.",
    regex:
      /(?:[a-zA-Z0-9_]*(?:api_?key|secret|password|token|credential))\s*[:=]\s*["']([a-zA-Z0-9_\-=/+]{16,})["']/gi,
    minEntropy: 3.6,
    mask: (m) => {
      return m.replace(
        /(["'])([^"']+)(["'])/,
        (_, q1, val, q2) => `${q1}${maskSecret(val, 3, 2)}${q2}`,
      );
    },
  },
];
