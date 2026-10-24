<div align="center">

# 🛡️ WebSecAuditor (`web-sec-auditor`)

**Enterprise-Grade AI Web Cybersecurity & Vulnerability Auditor for Web Applications, APIs, and Repositories**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.8%2B-blue)](https://www.typescriptlang.org/)
[![Node.js](https://img.shields.io/badge/Node.js-%3E%3D22.0-green.svg)](https://nodejs.org/)
[![Biome](https://img.shields.io/badge/Code%20Style-Biome-60a5fa.svg)](https://biomejs.dev)
[![OWASP Top 10](https://img.shields.io/badge/OWASP-Top%2010%20Compliant-red.svg)](https://owasp.org/www-project-top-ten/)

*Detect vulnerabilities, security header weaknesses, cookie misconfigurations, code injection, exposed API keys, and third-party CVE dependencies before attackers do.*

</div>

---

## ⚡ The Problem: Web Application Security Blindspots

Modern web applications and APIs are frequently deployed with critical security misconfigurations and vulnerabilities:
1. **Exposed Secrets & API Keys**: Cloud credentials (AWS, GCP), LLM API keys (OpenAI, Anthropic), payment tokens (Stripe), database connection strings with passwords, and private keys hardcoded in repositories or commit histories.
2. **Vulnerable Dependencies (SCA)**: Unpatched third-party npm packages harboring high-severity remote code execution, prototype pollution, or denial-of-service vulnerabilities (GHSA / CVE).
3. **Source Code Vulnerabilities (SAST)**: Raw query concatenations (SQLi), command injection (`child_process.exec`), path traversals, DOM-XSS, and dynamic code evaluation (`eval`).
4. **Cryptographic Failures**: Deprecated hash functions (MD5, SHA-1), JWTs allowing `none` algorithm verification, and insecure pseudo-random generation.
5. **Transport & Header Blindspots (DAST)**: Missing `Content-Security-Policy`, insecure cookies without `Secure`/`HttpOnly`/`SameSite`, dangerous wildcard CORS with credentials, and plaintext HTTP fallbacks.

**`web-sec-auditor` provides a unified DAST + SAST + Secret Hunter + SCA cybersecurity engine evaluating live endpoints and source code against OWASP Top 10, CWE Top 25, and enterprise compliance standards.**

---

## 🚀 Key Capabilities

### 🔑 High-Entropy Secret Hunter (Phase 3: Secrets & Token Detection)
- 📊 **Shannon Entropy Scoring**:
  - Calculates information density \( H(S) \) to eliminate false alarms while flagging true random secrets.
  - Automatic credential redaction (`AKIA**************LE`) in all terminal snippets and JSON reports to prevent secondary credential leakage.
- ☁️ **Cloud & SaaS Credentials**:
  - **AWS**: Access Key IDs (`AKIA...`).
  - **Google Cloud / Firebase**: API keys (`AIza...`).
  - **AI / LLM Platforms**: OpenAI (`sk-...`), Anthropic Claude (`sk-ant-...`).
  - **Payment & VCS**: Stripe Live Secret Keys (`sk_live_...`), GitHub Personal Access Tokens (`ghp_...`, `github_pat_...`).
  - **Team Webhooks**: Slack bot tokens and incoming webhook URLs.
  - **Cryptography**: Unencrypted RSA, OpenSSH, EC, and DSA private keys.
  - **Database URIs**: Direct connection strings with embedded plaintext passwords (`postgres://user:pass@host/db`).
  - **Generic High-Entropy Secrets**: Variable assignments matching secret keywords with entropy \( \ge 3.6 \).
- 📜 **Git Commit History Scanning**:
  - Analyzes commit diffs (`git log -p`) to identify credentials committed and subsequently deleted in earlier commits.

### 📦 Software Composition Analysis (Phase 3: SCA Dependency Auditor)
- 🌐 **Live OSV Database Integration**:
  - Batch queries the Open Source Vulnerability (OSV) API (`https://api.osv.dev/v1/querybatch`) for npm dependencies.
- 🛡️ **Actionable Remediation Roadmaps**:
  - Maps CVSS v3 vectors to standard severity tiers (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`).
  - Extracts exact patched upgrade targets (e.g. `>= 4.17.21`) and links directly to official GHSA and CVE advisories.

### 🔍 Static Application Security Testing (Phase 2: AST SAST Engine)
- 💉 **Injection Flaws (OWASP A03 / CWE-89, CWE-78, CWE-22, CWE-79, CWE-95)**:
  - **SQL / NoSQL Injection**: Flags unparameterized query concatenations and template literals.
  - **OS Command Injection**: Detects `child_process.exec`, `execSync`, `os.system`, and `subprocess.Popen(..., shell=True)`.
  - **Path Traversal**: Flags untrusted user input concatenated into filesystem calls (`fs.readFile`, `open`).
  - **DOM-Based XSS**: Catches unsanitized assignments to `innerHTML`, `outerHTML`, and `document.write`.
  - **Dynamic Code Execution**: Flags `eval()` and dynamic `new Function()` execution.
- 🔐 **Cryptographic Failures (OWASP A02 / CWE-327, CWE-328, CWE-338, CWE-798)**:
  - **Broken Hash Functions**: Catches collision-vulnerable algorithms (MD5, SHA-1).
  - **JWT Signature Bypass**: Intercepts insecure token verification allowing the `'none'` algorithm.
  - **Insecure Randomness**: Detects `Math.random()` or `random.random()` used in security-sensitive token contexts.
  - **Fallback Secrets**: Flags hardcoded fallback strings in secret environment assignments.

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
# Hunt for leaked credentials and high-entropy secrets in working directory
npx @ritualdev-lab/web-sec-auditor scan-secrets .

# Deep scan git commit diff history for previously committed secrets
npx @ritualdev-lab/web-sec-auditor scan-secrets . --git-history

# Audit package.json dependencies for known CVEs via OSV
npx @ritualdev-lab/web-sec-auditor scan-deps . --dev

# Audit a local codebase or repository (SAST)
npx @ritualdev-lab/web-sec-auditor scan-code ./src --threshold HIGH

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

### Secret Hunter: Leaked Credential Discovery
```typescript
import { SecretHunter } from "@ritualdev-lab/web-sec-auditor";

const hunter = new SecretHunter();

// Scan files or entire repository
const report = await hunter.scanPath("./src", {
  minEntropy: 3.5,
});

console.log(`Exposed Secrets: ${report.findings.length}`);
for (const f of report.findings) {
  console.log(`[${f.severity}] ${f.title}`);
  console.log(`  Redacted: ${f.maskedSecret} (Entropy: ${f.entropy})`);
  console.log(`  Remediation: ${f.remediation}`);
}
```

### SCA: Dependency Vulnerability Audit
```typescript
import { ScaScanner } from "@ritualdev-lab/web-sec-auditor";

const sca = new ScaScanner();

// Scan package.json against OSV advisory database
const report = await sca.scanManifest("package.json", {
  includeDev: true,
  threshold: "HIGH",
});

console.log(`Vulnerable Packages: ${report.vulnerableDependencies}`);
for (const vuln of report.findings) {
  console.log(`[${vuln.severity}] ${vuln.title} (${vuln.id})`);
  console.log(`  Package: ${vuln.packageName}@${vuln.currentVersion}`);
  console.log(`  Remediation: ${vuln.remediation}`);
}
```

### SAST & DAST Scanning
```typescript
import { DastScanner, SastScanner } from "@ritualdev-lab/web-sec-auditor";

// DAST live endpoint audit
const dast = new DastScanner();
const dastReport = await dast.scanUrl("https://my-saas-app.com");

// SAST source code audit
const sast = new SastScanner();
const sastReport = await sast.scanPath("./src");
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
- [ ] **Phase 4: AI Exploit Verification, CVSS v3.1 Scoring & Auto-Patch Engine**
  - Contextual AI exploit proof-of-concept (PoC) generator
  - Automated code remediation recipes with unified `git diff` output
  - CVSS v3.1 vector calculations and compliance tagging (PCI-DSS, SOC 2)
- [ ] **Phase 5: Enterprise Reporting, SARIF v2.1.0, MCP Protocol & CI/CD Action**
  - OASIS SARIF v2.1.0 generator for GitHub Advanced Security and GitLab dashboards
  - Standalone interactive HTML executive reporting dashboard
  - Universal MCP Server for Cursor, Claude Desktop, Antigravity, and Windsurf
  - GitHub Action with custom severity break-build thresholds (`--fail-on high`)

---

## 📄 License
MIT © [RitualDev Lab](https://github.com/RitualDev-Lab)
