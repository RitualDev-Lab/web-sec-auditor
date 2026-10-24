<div align="center">

# 🛡️ WebSecAuditor (`web-sec-auditor`)

**Enterprise-Grade AI Web Cybersecurity & Vulnerability Auditor for Web Applications, APIs, and Repositories**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.8%2B-blue)](https://www.typescriptlang.org/)
[![Node.js](https://img.shields.io/badge/Node.js-%3E%3D22.0-green.svg)](https://nodejs.org/)
[![Biome](https://img.shields.io/badge/Code%20Style-Biome-60a5fa.svg)](https://biomejs.dev)
[![OWASP Top 10](https://img.shields.io/badge/OWASP-Top%2010%20Compliant-red.svg)](https://owasp.org/www-project-top-ten/)

*Detect vulnerabilities, security header weaknesses, cookie misconfigurations, dangerous CORS policies, and transport gaps before attackers do.*

</div>

---

## ⚡ The Problem: Web Application Security Blindspots

Modern web applications and APIs are frequently deployed with critical security misconfigurations:
1. **Missing or Broken Headers**: Sites lacking `Content-Security-Policy` (CSP) or `Strict-Transport-Security` (HSTS) leave users vulnerable to Cross-Site Scripting (XSS) and SSL-stripping man-in-the-middle attacks.
2. **Insecure Cookies**: Auth and session tokens set without `Secure`, `HttpOnly`, or `SameSite` flags expose sessions to client-side script theft and CSRF.
3. **Dangerous CORS Policies**: Overly permissive wildcard origins (`*`) paired with credentials (`Access-Control-Allow-Credentials: true`) allow arbitrary external websites to make authenticated API requests.
4. **Transport & Information Leaks**: Plaintext HTTP fallback, expiring TLS certificates, and detailed server version disclosure headers (`Server: Apache/2.4.41`, `X-Powered-By: Express`) hand attackers actionable exploit intelligence.

**`web-sec-auditor` evaluates your web applications against modern cybersecurity specifications, assigns a deterministic letter grade (`A+` to `F`), and provides exact, framework-specific remediation code.**

---

## 🚀 Key Capabilities (Phase 1: DAST & Transport Security)

- 🌐 **Live HTTP Security Header Probe**:
  - Full evaluation of `Content-Security-Policy` (detecting `unsafe-inline`, `unsafe-eval`, wildcard sources, and insecure `http://` references).
  - Strict enforcement of `Strict-Transport-Security` (HSTS `max-age`, `includeSubDomains`, `preload`).
  - Clickjacking protection via `X-Frame-Options` and CSP `frame-ancestors`.
  - MIME-sniffing prevention via `X-Content-Type-Options: nosniff`.
  - Privacy preservation via `Referrer-Policy` and `Permissions-Policy`.
- 🍪 **Cookie Flag & Hygiene Auditor**:
  - Automatically identifies sensitive session and auth cookies (`session`, `jwt`, `token`, `auth`, `sid`).
  - Verifies `Secure`, `HttpOnly`, and `SameSite` (`Lax`/`Strict`) directives.
- 🔓 **CORS Misconfiguration Detection**:
  - Detects high-risk combinations (`Access-Control-Allow-Origin: *` with credentials).
  - Catches insecure `Origin: null` bypass vulnerabilities.
- 🔒 **SSL/TLS & Certificate Inspector**:
  - Inspects peer certificate validity, trusted CA issuer, and days remaining until expiration.
  - Flags plaintext HTTP usage and verifies HTTPS redirect enforcement.
- 🎛️ **Deterministic Security Scoring**:
  - 0–100 numerical health score and industry standard letter grade (`A+`, `A`, `B`, `C`, `D`, `F`).
  - Severity-capped risk thresholds: critical vulnerabilities cap maximum score at `F` (≤39).

---

## 📦 Installation & CLI Usage

### 1. Global / One-Off CLI Execution
```bash
# Run audit against any public or local URL
npx @ritualdev-lab/web-sec-auditor scan-url https://example.com

# Output structured JSON for automation and CI pipelines
npx @ritualdev-lab/web-sec-auditor scan-url https://api.example.com --format json
```

### 2. Local Installation
```bash
pnpm add @ritualdev-lab/web-sec-auditor
# or
npm install @ritualdev-lab/web-sec-auditor
```

---

## 💻 Programmatic Node.js SDK

You can embed `DastScanner` directly into your automated test suites, CI checks, or background health workers:

```typescript
import { DastScanner } from "@ritualdev-lab/web-sec-auditor";

const scanner = new DastScanner({
  timeoutMs: 8000,
  checkTlsCert: true,
});

const report = await scanner.scanUrl("https://my-saas-app.com");

console.log(`Security Grade: ${report.grade} (Score: ${report.score}/100)`);
console.log(`Total Findings: ${report.findings.length}`);

for (const finding of report.findings) {
  console.log(`[${finding.severity}] ${finding.title}`);
  console.log(`  Remediation: ${finding.remediation}`);
}
```

---

## 🛡️ Example Terminal Output

```text
🛡️  WebSecAuditor - Live DAST & Security Header Report
─────────────────────────────────────────────────────────────
Target:       https://example.com
Final URL:    https://example.com/
Status Code:  200
Latency:      142ms
Scan Time:    2026-10-24T03:50:00.000Z

OVERALL GRADE: 🟡 B [MODERATE HARDENING NEEDED] (Score: 78/100)
Summary:       0 Critical | 1 High | 1 Medium | 1 Low
─────────────────────────────────────────────────────────────

📋 HTTP Security Headers:
  ❌ Content-Security-Policy      [MISSING]
     • Issue: Content-Security-Policy header is missing.
     💡 Fix: Implement a strict Content-Security-Policy.
  ✅ Strict-Transport-Security   [OPTIMAL]
  ✅ X-Frame-Options              [OPTIMAL]
  ✅ X-Content-Type-Options       [OPTIMAL]
  ⚠️ Referrer-Policy              [MISSING]

🍪 Cookie Security Flags:
  ✅ Cookie 'session_id': Secure=true, HttpOnly=true, SameSite=Lax

🌐 CORS Configuration:
  Allowed Origin:      https://app.example.com
  Allows Credentials:  YES
  CORS Status:         SAFE

🔒 Transport & TLS Posture:
  HTTPS:               YES
  Certificate Valid:   YES
  Certificate Issuer:  Let's Encrypt
  Days to Expiration:  64 days

🚨 Identified Vulnerabilities & Remediation Roadmaps:

  1. 🔴 [HIGH] Missing Content-Security-Policy (CSP)
     ID:          SEC-HDR-CSP-MISSING (CWE-693)
     Description: The web application does not enforce a Content-Security-Policy header.
     Remediation: Define a strict Content-Security-Policy header restricting script-src, object-src, and default-src.
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
- [ ] **Phase 2: High-Performance SAST Engine & OWASP Top 10 Ruleset**
  - AST syntax visitor for TypeScript, JavaScript, Python, and Go
  - Injection detection (SQLi, NoSQLi, OS Command, Path Traversal, DOM-XSS)
  - Broken Access Control & IDOR / BOLA route parameter validator
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
