---
name: web-sec-auditor
title: WebSecAuditor
tagline: Static AST cybersecurity, dependency vulnerability & API security auditor for AI agents
description: Automated static AST vulnerability scanner and security auditor designed for AI coding agents. Inspects repositories, scans for OWASP Top 10 vulnerabilities, detects hardcoded secrets, audits third-party package dependencies, and exports SARIF & HTML compliance reports directly inside your IDE.
category: Security
use_cases:
  - Static Code Analysis (SAST)
  - Dependency Vulnerability Scanning
  - OWASP Top 10 Compliance
  - Secret & Credential Detection
  - Automated SARIF & HTML Reporting
getting_started:
  - "Audit repository for security vulnerabilities: audit_code path: './src'"
  - "Scan dependency lockfile for CVEs: audit_dependencies manifestPath: './package.json'"
  - "Hunt for leaked credentials: hunt_secrets path: '.'"
  - "Audit live web application: audit_url url: 'https://example.com'"
  - "Tool: audit_code: Analyzes source code AST for OWASP injection patterns and vulnerabilities"
  - "Tool: audit_dependencies: Cross-references dependencies against OSV and GitHub Advisory database"
  - "Tool: hunt_secrets: Scans files and git history for high-entropy API tokens and private keys"
  - "Tool: audit_url: DAST audit of HTTP headers, TLS, cookies, and CORS policies with SSRF protection"
  - "Tool: generate_patch: Generates read-only defensive remediation diff preview for detected flaws"
tags:
  - security
  - vulnerability-scanner
  - sast
  - dast
  - owasp
  - sarif
  - audit
  - mcp
  - ai-agents
  - cursor
documentation_url: https://ritualdev.in/web-sec-auditor
repository: https://github.com/RitualDev-Lab/web-sec-auditor
homepage: https://ritualdev.in/web-sec-auditor
npm: "@ritualdev-lab/web-sec-auditor"
transport: stdio
command: npx
args: ["-y", "@ritualdev-lab/web-sec-auditor", "mcp"]
pricing:
  type: freemium
  license: MIT
environment_variables:
  - name: WEBHOOK_SECRET
    description: HMAC secret key used to verify incoming GitHub webhook signatures for the PR bot listener.
    required: false
    docs_url: https://ritualdev.in/web-sec-auditor#webhook-secret
  - name: GITHUB_TOKEN
    description: Optional GitHub personal access token used by the bot and pr-scan commands to read PR diffs.
    required: false
    docs_url: https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens
---

# WebSecAuditor MCP Server

**WebSecAuditor** brings real-time static AST cybersecurity audits, dependency vulnerability checks, and OWASP compliance reporting into your AI coding assistant (Claude Desktop, Cursor, Antigravity, Windsurf).

## Setup Requirements

**Zero required configuration.** WebSecAuditor runs 100% locally on your machine with zero required cloud tokens.

## Quick Installation

```json
{
  "mcpServers": {
    "web-sec-auditor": {
      "command": "npx",
      "args": ["-y", "@ritualdev-lab/web-sec-auditor", "mcp"]
    }
  }
}
```

## Exposed MCP Tools

1. `audit_code`: Static AST analysis across JavaScript, TypeScript, and Python codebases flagging OWASP injection patterns (SQLi, Command Injection, SSRF, Path Traversal).
2. `audit_dependencies`: Cross-references lockfiles (`package.json`, `package-lock.json`, `pnpm-lock.yaml`) against OSV vulnerability databases.
3. `hunt_secrets`: Scans repository files and commit history for exposed high-entropy secrets and API tokens.
4. `audit_url`: Validates HTTP security headers (CSP, HSTS, CORS), cookies, and transport posture for live web applications with built-in SSRF defense.
5. `generate_patch`: Generates a read-only defensive remediation patch and unified git diff preview for user review.
