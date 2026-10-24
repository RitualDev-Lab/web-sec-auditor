#!/usr/bin/env node
import { DastScanner } from "./dast/index.js";
import type { DastScanReport, SecurityGrade } from "./types/index.js";

const VERSION = "0.1.0";

const HELP_TEXT = `
  🛡️  WebSecAuditor - Enterprise AI Web Cybersecurity Auditor v${VERSION}
  ─────────────────────────────────────────────────────────────
  Multi-vector security auditor detecting vulnerabilities, misconfigurations,
  and transport weaknesses across web applications and APIs.

  USAGE:
    web-sec-auditor [command] [options]

  COMMANDS:
    scan-url <url>   Audit a live web application or API endpoint (DAST & Headers)
    status           Display auditor capabilities and supported security checks
    help             Display this help message

  OPTIONS:
    --format <text|json>  Output format (default: text)
    --timeout <ms>        Request timeout in milliseconds (default: 10000)
    --no-cert             Skip raw TLS peer certificate handshake inspection
    --version, -v         Display version
    --help, -h            Display help

  EXAMPLES:
    web-sec-auditor scan-url https://example.com
    web-sec-auditor scan-url https://api.example.com --format json
`;

function getGradeBadge(grade: SecurityGrade): string {
  switch (grade) {
    case "A+":
      return "🟢 A+ [EXCELLENT POSTURE]";
    case "A":
      return "🟢 A [STRONG POSTURE]";
    case "B":
      return "🟡 B [MODERATE HARDENING NEEDED]";
    case "C":
      return "🟠 C [SIGNIFICANT GAPS]";
    case "D":
      return "🔴 D [HIGH RISK]";
    case "F":
      return "⛔ F [CRITICAL VULNERABILITIES]";
  }
}

function renderTextReport(report: DastScanReport): string {
  const lines: string[] = [];

  lines.push(`
🛡️  WebSecAuditor - Live DAST & Security Header Report
─────────────────────────────────────────────────────────────
Target:       ${report.targetUrl}
Final URL:    ${report.finalUrl}
Status Code:  ${report.statusCode}
Latency:      ${report.responseTimeMs}ms
Scan Time:    ${report.scanTimestamp}

OVERALL GRADE: ${getGradeBadge(report.grade)} (Score: ${report.score}/100)
Summary:       ${report.summary.critical} Critical | ${report.summary.high} High | ${report.summary.medium} Medium | ${report.summary.low} Low
─────────────────────────────────────────────────────────────
`);

  lines.push("📋 HTTP Security Headers:");
  for (const h of report.headers) {
    const icon = h.status === "OPTIMAL" ? "✅" : h.status === "SUBOPTIMAL" ? "⚠️" : "❌";
    lines.push(`  ${icon} ${h.name.padEnd(28)} [${h.status}]`);
    if (h.issues.length > 0) {
      for (const iss of h.issues) {
        lines.push(`     • Issue: ${iss}`);
      }
    }
    if (h.recommendation) {
      lines.push(`     💡 Fix: ${h.recommendation}`);
    }
  }

  lines.push("\n🍪 Cookie Security Flags:");
  if (report.cookies.length === 0) {
    lines.push("  ℹ️  No Set-Cookie headers observed in response.");
  } else {
    for (const ck of report.cookies) {
      const statusIcon = ck.issues.length === 0 ? "✅" : "⚠️";
      lines.push(
        `  ${statusIcon} Cookie '${ck.name}': Secure=${ck.secure}, HttpOnly=${ck.httpOnly}, SameSite=${ck.sameSite || "MISSING"}`,
      );
      for (const iss of ck.issues) {
        lines.push(`     • ${iss}`);
      }
    }
  }

  lines.push("\n🌐 CORS Configuration:");
  lines.push(`  Allowed Origin:      ${report.cors.allowedOrigin || "None declared"}`);
  lines.push(`  Allows Credentials:  ${report.cors.allowsCredentials ? "YES" : "NO"}`);
  lines.push(`  CORS Status:         ${report.cors.status}`);
  for (const iss of report.cors.issues) {
    lines.push(`  • ${iss}`);
  }

  lines.push("\n🔒 Transport & TLS Posture:");
  lines.push(`  HTTPS:               ${report.tls.isHttps ? "YES" : "NO"}`);
  if (report.tls.certificateValid !== undefined) {
    lines.push(`  Certificate Valid:   ${report.tls.certificateValid ? "YES" : "NO"}`);
  }
  if (report.tls.issuer) {
    lines.push(`  Certificate Issuer:  ${report.tls.issuer}`);
  }
  if (report.tls.daysRemaining !== undefined) {
    lines.push(`  Days to Expiration:  ${report.tls.daysRemaining} days`);
  }
  for (const iss of report.tls.issues) {
    lines.push(`  • ${iss}`);
  }

  if (report.findings.length > 0) {
    lines.push("\n🚨 Identified Vulnerabilities & Remediation Roadmaps:");
    report.findings.forEach((f, idx) => {
      const sevIcon =
        f.severity === "CRITICAL"
          ? "⛔ [CRITICAL]"
          : f.severity === "HIGH"
            ? "🔴 [HIGH]"
            : f.severity === "MEDIUM"
              ? "🟠 [MEDIUM]"
              : "🟡 [LOW]";
      lines.push(`\n  ${idx + 1}. ${sevIcon} ${f.title}`);
      lines.push(`     ID:          ${f.id} ${f.cwe ? `(${f.cwe})` : ""}`);
      lines.push(`     Description: ${f.description}`);
      if (f.evidence) {
        lines.push(`     Evidence:    ${f.evidence.replace(/\n/g, " ")}`);
      }
      lines.push(`     Remediation: ${f.remediation}`);
    });
  } else {
    lines.push("\n🎉 No security vulnerabilities or misconfigurations detected!");
  }

  return lines.join("\n");
}

async function main() {
  const args = process.argv.slice(2);
  const command = args[0] || "help";

  if (args.includes("--help") || args.includes("-h") || command === "help") {
    console.log(HELP_TEXT);
    process.exit(0);
  }

  if (args.includes("--version") || args.includes("-v") || command === "version") {
    console.log(`web-sec-auditor v${VERSION}`);
    process.exit(0);
  }

  switch (command) {
    case "scan-url": {
      const targetUrl = args[1];
      if (!targetUrl) {
        console.error("❌ Error: Target URL is required.\nUsage: web-sec-auditor scan-url <url>");
        process.exit(1);
      }

      const formatIdx = args.indexOf("--format");
      const format = formatIdx !== -1 && args[formatIdx + 1] ? args[formatIdx + 1] : "text";

      const timeoutIdx = args.indexOf("--timeout");
      const timeoutMs =
        timeoutIdx !== -1 && args[timeoutIdx + 1]
          ? Number.parseInt(args[timeoutIdx + 1], 10)
          : 10000;

      const checkTlsCert = !args.includes("--no-cert");

      const scanner = new DastScanner({ timeoutMs, checkTlsCert });
      try {
        const report = await scanner.scanUrl(targetUrl);
        if (format === "json") {
          console.log(JSON.stringify(report, null, 2));
        } else {
          console.log(renderTextReport(report));
        }
      } catch (err) {
        console.error(`❌ Scan failed for ${targetUrl}: ${(err as Error).message}`);
        process.exit(1);
      }
      break;
    }

    case "status": {
      console.log(`
🛡️  WebSecAuditor - Engine Capabilities
────────────────────────────────────────
Version:       v${VERSION}
Engines:
  [Phase 1] DAST & Live Header Probe     - ACTIVE
  [Phase 1] Cookie & CORS Auditor        - ACTIVE
  [Phase 1] TLS & Transport Inspector    - ACTIVE
  [Phase 2] AST-Level SAST Engine        - PLANNED
  [Phase 3] High-Entropy Secret Hunter   - PLANNED
  [Phase 4] AI Exploit PoC & Auto-Patch  - PLANNED
  [Phase 5] SARIF v2.1.0 & MCP Server    - PLANNED
`);
      break;
    }

    default:
      console.error(`Unknown command '${command}'. Run 'web-sec-auditor --help' for usage.`);
      process.exit(1);
  }
}

main().catch((err) => {
  console.error("❌ Fatal Error in WebSecAuditor CLI:", err);
  process.exit(1);
});
