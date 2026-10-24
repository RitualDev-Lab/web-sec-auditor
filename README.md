<div align="center">

# 🛡️ WebSecAuditor (`web-sec-auditor`)

**Enterprise-Grade AI Web Cybersecurity & Vulnerability Auditor for Web Applications, APIs, and Repositories**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.8%2B-blue)](https://www.typescriptlang.org/)
[![Node.js](https://img.shields.io/badge/Node.js-%3E%3D22.0-green.svg)](https://nodejs.org/)
[![Biome](https://img.shields.io/badge/Code%20Style-Biome-60a5fa.svg)](https://biomejs.dev)
[![OWASP Top 10](https://img.shields.io/badge/OWASP-Top%2010%20Compliant-red.svg)](https://owasp.org/www-project-top-ten/)
[![CVSS v3.1](https://img.shields.io/badge/CVSS-v3.1%20Scored-orange.svg)](https://www.first.org/cvss/v3.1/specification-document)

*Detect vulnerabilities, security header weaknesses, cookie misconfigurations, code injection, exposed API keys, CVSS v3.1 risks, and automatically generate defensive code patches.*

</div>

---

## ⚡ The Problem: Web Application Security Blindspots

Modern web applications and APIs are frequently deployed with critical security misconfigurations and vulnerabilities:
1. **Unpatched Vulnerabilities**: Identifying a vulnerability is only half the battle; developers need immediate, safe, contextual code fixes (parameterized queries, isolated exec, path confinement).
2. **Missing Risk Metrics & Compliance Signals**: Engineering teams struggle to prioritize alerts without standard CVSS v3.1 mathematical scoring and compliance mappings (PCI-DSS v4.0, SOC 2, CWE Top 25).
3. **Exposed Secrets & API Keys**: Cloud credentials (AWS, GCP), LLM API keys (OpenAI, Anthropic), payment tokens (Stripe), database connection strings with passwords, and private keys hardcoded in repositories or commit histories.
4. **Vulnerable Dependencies (SCA)**: Unpatched third-party npm packages harboring high-severity remote code execution or prototype pollution vulnerabilities.
5. **Source Code Flaws (SAST)**: Raw query concatenations (SQLi), command injection, path traversals, DOM-XSS, and dynamic code evaluation.
6. **Transport & Header Blindspots (DAST)**: Missing `Content-Security-Policy`, insecure cookies without `Secure`/`HttpOnly`/`SameSite`, dangerous wildcard CORS with credentials, and plaintext HTTP fallbacks.

**`web-sec-auditor` provides a unified DAST + SAST + Secret Hunter + SCA + Auto-Patch cybersecurity engine evaluating live endpoints and source code against OWASP Top 10, CWE Top 25, and enterprise compliance standards.**

---

## 🚀 Key Capabilities

### 🛠️ Automated Code Patching & Git Diffs (Phase 4: Auto-Patch Engine)
- 📝 **Unified Git Diff Generation**:
  - Automatically calculates standard unified git diffs for identified vulnerabilities.
- 💡 **Contextual Defensive Code Transformations**:
  - **SQL Injection**: Transforms string query concatenation into parameterized queries (`$1, $2` or `?`) with bind variables.
  - **Command Injection**: Converts shell-interpolated `child_process.exec()` into safe `child_process.execFile()` with an arguments array.
  - **Path Traversal**: Confinies file reads using `path.basename()` and `path.resolve()`.
  - **DOM-XSS**: Replaces `.innerHTML = ...` with `.textContent = ...`.
  - **Insecure TLS**: Enforces `rejectUnauthorized: true`.
  - **Secret Fallbacks**: Replaces hardcoded fallback strings with explicit environment validation checks.
- ⚡ **Direct File Patching**:
  - Apply patches directly with `web-sec-auditor patch <file> --line <num> --rule <ruleId>` or preview with `--dry-run`.

### 📊 CVSS v3.1 Scoring & Compliance Mapping (Phase 4)
- 📐 **Official FIRST CVSS v3.1 Mathematical Engine**:
  - Calculates Base Score (0.0 to 10.0), Exploitability Subscore, Impact Subscore, and standard vector strings (e.g. `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`).
- 📜 **Enterprise Compliance Tagging**:
  - **OWASP Top 10 (2021)**: Tagged across all categories (`A01` to `A10`).
  - **PCI-DSS v4.0**: Mapped to Requirements `6.2.4` (injection controls), `6.4.3` (client-side script management), `8.3.1` (strong auth), `4.1.2` (TLS encryption).
  - **SOC 2 Type II**: Mapped to Trust Services Criteria `CC6.1` (access control), `CC6.6` (perimeter defenses), `CC7.1` (vulnerability management).
  - **CWE Top 25 (2023/2024)**: Surfaces official ranks (e.g. `CWE-89` #3, `CWE-79` #2, `CWE-78` #5, `CWE-22` #8, `CWE-798` #18).

### 🔑 High-Entropy Secret Hunter (Phase 3: Secrets & Token Detection)
- 📊 **Shannon Entropy Scoring**:
  - Calculates information density \( H(S) \) to eliminate false alarms while flagging true random secrets.
  - Automatic credential redaction (`AKIA**************LE`) in all terminal snippets and JSON reports.
- ☁️ **Cloud, AI & SaaS Credentials**:
  - AWS, Google Cloud, OpenAI, Anthropic Claude, Stripe, GitHub, Slack webhooks, database connection URIs, and unencrypted private keys.
- 📜 **Git Commit History Scanning**:
  - Analyzes commit diffs (`git log -p`) to identify credentials committed and subsequently deleted in earlier commits.

### 📦 Software Composition Analysis (Phase 3: SCA Dependency Auditor)
- 🌐 **Live OSV Database Integration**:
  - Batch queries the Open Source Vulnerability (OSV) API (`https://api.osv.dev/v1/querybatch`) for npm dependencies.
  - Maps CVSS v3 vectors to standard severity tiers and extracts exact patched upgrade targets.

### 🔍 Static Application Security Testing (Phase 2: AST SAST Engine)
- 💉 **Injection Flaws (OWASP A03 / CWE-89, CWE-78, CWE-22, CWE-79, CWE-95)**:
  - SQL/NoSQL Injection, Command Injection, Path Traversal, DOM-Based XSS, and Dynamic Code Execution (`eval`).
- 🔐 **Cryptographic Failures (OWASP A02 / CWE-327, CWE-328, CWE-338, CWE-798)**:
  - Broken Hash Functions (MD5, SHA-1), JWT Signature Bypass (`none` algorithm), Insecure Randomness, Fallback Secrets.

### 🌐 Live Dynamic Testing (Phase 1: DAST & Transport Security)
- **HTTP Security Header Probe**: CSP (`unsafe-inline`, `unsafe-eval`), HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy.
- **Cookie Hygiene**: `Secure`, `HttpOnly`, `SameSite` attribute enforcement.
- **CORS Misconfiguration**: Wildcard origins with credentials, `Origin: null` bypasses.
- **Transport & TLS**: Certificate validity, expiration tracking, HTTPS redirect validation.
- **Deterministic Scoring**: 0–100 health score with letter grade badges (`A+` to `F`).

---

## 📦 Installation & CLI Usage

### 1. Global / One-Off CLI Execution
```bash
# Audit a local codebase or repository (SAST) with auto-patch diffs
npx @ritualdev-lab/web-sec-auditor scan-code ./src --threshold HIGH --diff

# Apply an automated remediation patch to a vulnerable line
npx @ritualdev-lab/web-sec-auditor patch ./src/user.ts --line 42 --rule SEC-INJ-SQLI

# Preview a patch in dry-run mode
npx @ritualdev-lab/web-sec-auditor patch ./src/user.ts --line 42 --rule SEC-INJ-SQLI --dry-run

# Hunt for leaked credentials and high-entropy secrets
npx @ritualdev-lab/web-sec-auditor scan-secrets . --git-history

# Audit package.json dependencies for known CVEs via OSV
npx @ritualdev-lab/web-sec-auditor scan-deps . --dev

# Audit a live web application or API endpoint (DAST)
npx @ritualdev-lab/web-sec-auditor scan-url https://example.com
```

### 2. Local Installation
```bash
pnpm add @ritualdev-lab/web-sec-auditor
# or
npm install @ritualdev-lab/web-sec-auditor
```

---

## 💻 Programmatic Node.js SDK

### Auto-Patching & Unified Diffs
```typescript
import { PatchEngine } from "@ritualdev-lab/web-sec-auditor";

const engine = new PatchEngine();
const content = `const q = "SELECT * FROM users WHERE email = '" + req.body.email;`;

const recipe = engine.generatePatch("src/user.ts", content, 1, "SEC-INJ-SQLI");
if (recipe) {
  console.log(recipe.diff); // Unified git diff
  console.log(recipe.explanation);
  
  // Apply patch to disk
  await engine.applyPatch(recipe);
}
```

### CVSS v3.1 Scoring & Compliance Lookup
```typescript
import { calculateCvssV31, getComplianceMapping } from "@ritualdev-lab/web-sec-auditor";

// Compute CVSS v3.1 Base Score
const cvss = calculateCvssV31({
  attackVector: "NETWORK",
  attackComplexity: "LOW",
  privilegesRequired: "NONE",
  userInteraction: "NONE",
  scope: "UNCHANGED",
  confidentiality: "HIGH",
  integrity: "HIGH",
  availability: "HIGH",
});

console.log(`CVSS Score: ${cvss.baseScore} (${cvss.vectorString})`); // 9.8 (CRITICAL)

// Lookup enterprise compliance mapping
const compliance = getComplianceMapping("CWE-89");
console.log(`CWE Top 25 Rank: #${compliance?.cweTop25Rank}`); // #3
console.log(`PCI-DSS: ${compliance?.pciDssV4.join(", ")}`);
console.log(`SOC 2: ${compliance?.soc2.join(", ")}`);
```

---

## 🗺️ Project Roadmap & Enterprise Evolution

- [x] **Phase 1: Live DAST Probe, Transport Security & Network Hygiene**
  - High-performance HTTP header evaluator (CSP, HSTS, XFO, XCTO, Referrer, Permissions-Policy)
  - Cookie security hygiene inspector (`Secure`, `HttpOnly`, `SameSite`)
  - CORS policy & dangerous credential reflection analyzer
  - SSL/TLS certificate inspector & validity checker
  - Security scoring engine (0–100) with letter grading (`A+` to `F`)
  - CLI binary: `web-sec-auditor scan-url <url>`
- [x] **Phase 2: High-Performance SAST Engine & OWASP Top 10 Ruleset**
  - Multi-language SAST visitor (TypeScript, JavaScript, Python, Go)
  - Injection rules (SQLi, OS Command, Path Traversal, DOM-XSS, Eval)
  - Cryptographic weakness rules (Weak hash, JWT Alg None, Insecure Random, Fallback Secret)
  - Authentication hygiene (Web storage tokens, password logging)
  - SSRF & security misconfigurations (Unvalidated requests, TLS disabled, Debug mode)
  - CLI binary: `web-sec-auditor scan-code <path>`
- [x] **Phase 3: High-Entropy Secret Hunter & SCA Dependency Auditor**
  - Shannon entropy secret scanner for AWS, GCP, OpenAI, Anthropic, Stripe, GitHub, and private keys
  - Automatic secret masking in reports (`AKIA**************LE`)
  - Git history scanner (`git log -p`) to detect previously committed/deleted credentials
  - Software Composition Analysis (SCA) querying OSV database for known CVEs/GHSAs
  - CLI binaries: `web-sec-auditor scan-secrets <path>`, `web-sec-auditor scan-deps <path>`
- [x] **Phase 4: AI Exploit Verification, CVSS v3.1 Scoring & Auto-Patch Engine**
  - Deterministic CVSS v3.1 base score, exploitability, impact, and vector calculations
  - Compliance mapping database (OWASP Top 10, PCI-DSS v4.0, SOC 2 Type II, CWE Top 25)
  - Automated code remediation engine generating unified `git diff` recipes
  - CLI binary: `web-sec-auditor patch <file> --line <num> --rule <ruleId>`
- [ ] **Phase 5: Enterprise Reporting, SARIF v2.1.0, MCP Protocol & CI/CD Action**
  - OASIS SARIF v2.1.0 generator for GitHub Advanced Security and GitLab dashboards
  - Standalone interactive HTML executive reporting dashboard
  - Universal MCP Server for Cursor, Claude Desktop, Antigravity, and Windsurf
  - GitHub Action with custom severity break-build thresholds (`--fail-on high`)

---

## 📄 License
MIT © [RitualDev Lab](https://github.com/RitualDev-Lab)
