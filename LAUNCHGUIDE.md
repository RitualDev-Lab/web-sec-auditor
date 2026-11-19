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
  - "Audit repository for security vulnerabilities: audit_repo path: './src'"
  - "Scan dependency lockfile for CVEs: audit_dependencies path: './package.json'"
  - "Tool: audit_repo: Analyzes source code AST for OWASP injection patterns and exposed secrets"
  - "Tool: audit_dependencies: Cross-references dependencies against OSV and GitHub Advisory database"
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
args: ["-y", "@ritualdev-lab/web-sec-auditor"]
pricing:
  type: freemium
  license: MIT
environment_variables: []
---

# WebSecAuditor MCP Server

**WebSecAuditor** brings real-time static AST cybersecurity audits, dependency vulnerability checks, and OWASP compliance reporting into your AI coding assistant (Claude Desktop, Cursor, Windsurf).

## Setup Requirements

**None.** WebSecAuditor operates entirely locally on your workspace with zero required cloud tokens.

## Quick Installation

```json
{
  "mcpServers": {
    "web-sec-auditor": {
      "command": "npx",
      "args": ["-y", "@ritualdev-lab/web-sec-auditor"]
    }
  }
}
```

## Exposed Tools

1. `audit_repo`: Static AST analysis across JavaScript, TypeScript, and Python codebases flagging OWASP injection patterns.
2. `audit_dependencies`: Cross-references lockfiles (`package-lock.json`, `pnpm-lock.yaml`) against OSV vulnerability databases.
3. `audit_headers`: Validates HTTP security headers (CSP, HSTS, CORS) for live web applications.
4. `generate_report`: Produces standard SARIF and HTML audit ledgers for compliance review.
