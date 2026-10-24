<div align="center">

# 🛡️ WebSecAuditor (`web-sec-auditor`)

**Enterprise-Grade AI Web Cybersecurity & Vulnerability Auditor for Web Applications, APIs, and Repositories**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.8%2B-blue)](https://www.typescriptlang.org/)
[![Node.js](https://img.shields.io/badge/Node.js-%3E%3D22.0-green.svg)](https://nodejs.org/)
[![Biome](https://img.shields.io/badge/Code%20Style-Biome-60a5fa.svg)](https://biomejs.dev)
[![OWASP Top 10](https://img.shields.io/badge/OWASP-Top%2010%20Compliant-red.svg)](https://owasp.org/www-project-top-ten/)

*Detect vulnerabilities, security header weaknesses, cookie misconfigurations, dangerous CORS policies, code injection, broken crypto, and transport gaps before attackers do.*

</div>

---

## ⚡ The Problem: Web Application Security Blindspots

Modern web applications and APIs are frequently deployed with critical security misconfigurations and vulnerabilities:
1. **Source Code Vulnerabilities**: Raw string concatenations in database queries (SQLi), unsanitized inputs passed to child process execution (Command Injection), path traversals, and dynamic code evaluation (`eval`).
2. **Cryptographic Failures**: Deprecated hash functions (MD5, SHA-1), JWTs allowing `none` algorithm verification, insecure pseudo-random generation for security tokens, and hardcoded fallback secrets.
3. **Missing or Broken Headers**: Sites lacking `Content-Security-Policy` (CSP) or `Strict-Transport-Security` (HSTS) leave users vulnerable to Cross-Site Scripting (XSS) and SSL-stripping man-in-the-middle attacks.
4. **Insecure Cookies & Storage**: Auth and session tokens set without `Secure`, `HttpOnly`, or `SameSite` flags or stored in browser `localStorage`.
5. **Dangerous CORS Policies**: Overly permissive wildcard origins (`*`) paired with credentials (`Access-Control-Allow-Credentials: true`).
6. **Transport & Information Leaks**: Plaintext HTTP fallback, expiring TLS certificates, and detailed server version disclosure headers (`Server: Apache/2.4.41`, `X-Powered-By: Express`).

**`web-sec-auditor` provides a unified DAST + SAST cybersecurity engine evaluating live endpoints and source code against OWASP Top 10, CWE Top 25, and enterprise compliance standards.**

---

## 🚀 Key Capabilities

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
- 🛡️ **Auth & Access Control (OWASP A07 / CWE-922, CWE-532)**:
  - **Token Storage Hygiene**: Flags storing JWTs or session secrets in `localStorage` or `sessionStorage`.
  - **Credential Leak in Logs**: Flags printing passwords, secret keys, or raw auth bodies to logger streams.
- 🌐 **SSRF & Security Misconfiguration (OWASP A05, A10 / CWE-918, CWE-295, CWE-489)**:
  - **SSRF**: Flags direct unvalidated outbound HTTP calls using request parameters.
  - **TLS Disabled**: Flags `rejectUnauthorized: false` or `NODE_TLS_REJECT_UNAUTHORIZED='0'`.
  - **Debug Flags**: Catches production debug modes left enabled in code.

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
# Audit a local codebase or repository (SAST)
npx @ritualdev-lab/web-sec-auditor scan-code ./src

# Filter findings by minimum severity threshold
npx @ritualdev-lab/web-sec-auditor scan-code . --threshold HIGH

# Output JSON for CI/CD pipelines
npx @ritualdev-lab/web-sec-auditor scan-code . --format json

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

### SAST: Static Codebase Analysis
```typescript
import { SastScanner } from "@ritualdev-lab/web-sec-auditor";

const scanner = new SastScanner();

// Scan an entire repository or directory
const report = await scanner.scanPath("./src", {
  threshold: "HIGH",
  languages: ["typescript", "javascript", "python", "go"],
});

console.log(`Files Scanned: ${report.filesScanned} in ${report.durationMs}ms`);
console.log(`Critical Issues: ${report.summary.critical}`);

for (const finding of report.findings) {
  console.log(`[${finding.severity}] ${finding.title}`);
  console.log(`  File: ${finding.file}:${finding.line}:${finding.column}`);
  console.log(`  Remediation: ${finding.remediation}`);
}
```

### DAST: Live Endpoint Analysis
```typescript
import { DastScanner } from "@ritualdev-lab/web-sec-auditor";

const scanner = new DastScanner({
  timeoutMs: 8000,
  checkTlsCert: true,
});

const report = await scanner.scanUrl("https://my-saas-app.com");

console.log(`Security Grade: ${report.grade} (Score: ${report.score}/100)`);
console.log(`Total Findings: ${report.findings.length}`);
```

---

## 🛡️ Example SAST Terminal Output

```text
🛡️  WebSecAuditor - Static Application Security Testing (SAST) Report
─────────────────────────────────────────────────────────────
Target Path:    /home/dev/my-project/src
Files Scanned:  42
Scan Duration:  48ms
Scan Timestamp: 2026-10-24T04:00:00.000Z

SUMMARY:
  ⛔ Critical: 1
  🔴 High:     2
  🟠 Medium:   1
  🟡 Low:      0
  ℹ️  Info:     0
─────────────────────────────────────────────────────────────

🚨 Detected 4 Security Issue(s):

  1. [⛔ CRITICAL] SQL / NoSQL Query String Interpolation (SEC-INJ-SQLI)
     Location:    controllers/users.ts:24:18
     Category:    INJECTION | CWE-89 | A03:2021-Injection
     Snippet:     const q = "SELECT * FROM users WHERE email = '" + req.body.email + "'";
     Description: Raw string interpolation or concatenation was detected inside a database query call.
     Remediation: 💡 Use parameterized queries or ORM query builder methods.

  2. [🔴 HIGH] Hardcoded Cryptographic Fallback Secret (SEC-CRYP-FALLBACK-SECRET)
     Location:    config/jwt.ts:8:32
     Category:    AUTH | CWE-798 | A07:2021-Identification and Authentication Failures
     Snippet:     const secret = process.env.JWT_SECRET || "dev_secret_key_123";
     Description: A hardcoded fallback default secret was detected in environment variable assignment.
     Remediation: 💡 Throw a startup configuration error if the secret environment variable is missing.
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
  - Severity-based threshold filtering (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`)
  - CLI binary: `web-sec-auditor scan-code <path>`
- [ ] **Phase 3: High-Entropy Secret Hunter & SCA Dependency Auditor**
  - Shannon entropy secret scanner for AWS, OpenAI, Gemini, Stripe, and private keys
  - Git history scanner to detect credentials in earlier commits
  - Software Composition Analysis (SCA) auditing `package.json` and lockfiles against OSV CVE database
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
