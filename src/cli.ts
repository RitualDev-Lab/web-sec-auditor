#!/usr/bin/env node
import { DastScanner } from "./dast/index.js";
import { SastScanner } from "./sast/index.js";
import { ScaScanner } from "./sca/index.js";
import { SecretHunter } from "./secrets/index.js";
import type {
  DastScanReport,
  FindingSeverity,
  SastScanReport,
  ScaScanReport,
  SecretScanReport,
  SecurityGrade,
  SupportedLanguage,
} from "./types/index.js";

const VERSION = "0.3.0";

const HELP_TEXT = `
  🛡️  WebSecAuditor - Enterprise AI Web Cybersecurity Auditor v${VERSION}
  ─────────────────────────────────────────────────────────────
  Multi-vector security auditor detecting vulnerabilities, misconfigurations,
  credential leaks, and third-party dependency CVEs across web stacks.

  USAGE:
    web-sec-auditor [command] [options]

  COMMANDS:
    scan-url <url>        Audit a live web application or API endpoint (DAST & Headers)
    scan-code <path>      Audit local source code or repository (SAST & OWASP Top 10)
    scan-secrets <path>   Hunt for leaked API keys and high-entropy credentials
    scan-deps <path>      Audit third-party dependencies for known CVEs (SCA via OSV)
    status                Display auditor capabilities and supported security checks
    help                  Display this help message

  OPTIONS:
    --format <text|json>        Output format (default: text)
    --threshold <level>         Minimum severity (CRITICAL, HIGH, MEDIUM, LOW, INFO)
    --timeout <ms>              Request timeout in milliseconds (default: 10000)
    --languages <lang1,lang2>   Filter languages for SAST (ts, js, py, go)
    --min-entropy <float>       Minimum Shannon entropy threshold for secret hunter (default: 3.5)
    --git-history               Scan git commit diff history for deleted/historical secrets
    --dev                       Include devDependencies in SCA dependency scan
    --no-cert                   Skip raw TLS peer certificate handshake inspection
    --version, -v               Display version
    --help, -h                  Display help

  EXAMPLES:
    web-sec-auditor scan-url https://example.com
    web-sec-auditor scan-code ./src --threshold HIGH
    web-sec-auditor scan-secrets . --git-history
    web-sec-auditor scan-deps . --dev
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

function renderSastTextReport(report: SastScanReport): string {
  const lines: string[] = [];

  lines.push(`
🛡️  WebSecAuditor - Static Application Security Testing (SAST) Report
─────────────────────────────────────────────────────────────
Target Path:    ${report.targetPath}
Files Scanned:  ${report.filesScanned}
Scan Duration:  ${report.durationMs}ms
Scan Timestamp: ${report.scanTimestamp}

SUMMARY:
  ⛔ Critical: ${report.summary.critical}
  🔴 High:     ${report.summary.high}
  🟠 Medium:   ${report.summary.medium}
  🟡 Low:      ${report.summary.low}
  ℹ️  Info:     ${report.summary.info}
─────────────────────────────────────────────────────────────
`);

  if (report.findings.length === 0) {
    lines.push("🎉 Clean scan! No security vulnerabilities identified in codebase.");
    return lines.join("\n");
  }

  lines.push(`🚨 Detected ${report.findings.length} Security Issue(s):\n`);

  report.findings.forEach((f, idx) => {
    const sevBadge =
      f.severity === "CRITICAL"
        ? "⛔ CRITICAL"
        : f.severity === "HIGH"
          ? "🔴 HIGH"
          : f.severity === "MEDIUM"
            ? "🟠 MEDIUM"
            : "🟡 LOW";

    lines.push(`  ${idx + 1}. [${sevBadge}] ${f.title} (${f.ruleId})`);
    lines.push(`     Location:    ${f.file}:${f.line}:${f.column}`);
    lines.push(`     Category:    ${f.category} | ${f.cwe} | ${f.owasp}`);
    lines.push(`     Snippet:     ${f.snippet}`);
    lines.push(`     Description: ${f.description}`);
    lines.push(`     Remediation: 💡 ${f.remediation}\n`);
  });

  return lines.join("\n");
}

function renderSecretsTextReport(report: SecretScanReport): string {
  const lines: string[] = [];

  lines.push(`
🛡️  WebSecAuditor - High-Entropy Secret Hunter Report
─────────────────────────────────────────────────────────────
Target Path:     ${report.targetPath}
${report.commitsScanned ? `Commits Scanned: ${report.commitsScanned}` : `Files Scanned:   ${report.filesScanned}`}
Scan Duration:   ${report.durationMs}ms
Scan Timestamp:  ${report.scanTimestamp}

SUMMARY:
  ⛔ Critical: ${report.summary.critical}
  🔴 High:     ${report.summary.high}
  🟠 Medium:   ${report.summary.medium}
  🟡 Low:      ${report.summary.low}
─────────────────────────────────────────────────────────────
`);

  if (report.findings.length === 0) {
    lines.push("🎉 Clean scan! No hardcoded secrets or credentials detected.");
    return lines.join("\n");
  }

  lines.push(`🚨 Found ${report.findings.length} Exposed Secret(s):\n`);

  report.findings.forEach((f, idx) => {
    const sevBadge = f.severity === "CRITICAL" ? "⛔ CRITICAL" : "🔴 HIGH";
    lines.push(`  ${idx + 1}. [${sevBadge}] ${f.title} (${f.patternId})`);
    lines.push(`     Location:    ${f.file}:${f.line}:${f.column}`);
    if (f.commitHash) {
      lines.push(
        `     Commit:      ${f.commitHash.slice(0, 10)} by ${f.commitAuthor || "Unknown"}`,
      );
    }
    lines.push(`     Redacted:    ${f.maskedSecret} (Entropy: ${f.entropy})`);
    lines.push(`     Snippet:     ${f.snippet}`);
    lines.push(`     Remediation: 💡 ${f.remediation}\n`);
  });

  return lines.join("\n");
}

function renderScaTextReport(report: ScaScanReport): string {
  const lines: string[] = [];

  lines.push(`
🛡️  WebSecAuditor - Software Composition Analysis (SCA) Report
─────────────────────────────────────────────────────────────
Manifest:        ${report.manifestPath}
Ecosystem:       ${report.ecosystem}
Total Packages:  ${report.totalDependencies}
Vulnerable Pkgs: ${report.vulnerableDependencies}
Scan Duration:   ${report.durationMs}ms
Scan Timestamp:  ${report.scanTimestamp}

SUMMARY:
  ⛔ Critical: ${report.summary.critical}
  🔴 High:     ${report.summary.high}
  🟠 Medium:   ${report.summary.medium}
  🟡 Low:      ${report.summary.low}
─────────────────────────────────────────────────────────────
`);

  if (report.findings.length === 0) {
    lines.push("🎉 Clean scan! No known CVEs or security advisories reported in dependencies.");
    return lines.join("\n");
  }

  lines.push(`🚨 Detected ${report.findings.length} Dependency Vulnerability Advisory(s):\n`);

  report.findings.forEach((f, idx) => {
    const sevBadge =
      f.severity === "CRITICAL"
        ? "⛔ CRITICAL"
        : f.severity === "HIGH"
          ? "🔴 HIGH"
          : f.severity === "MEDIUM"
            ? "🟠 MEDIUM"
            : "🟡 LOW";

    lines.push(`  ${idx + 1}. [${sevBadge}] ${f.title} (${f.id})`);
    lines.push(`     Package:     ${f.packageName}@${f.currentVersion}`);
    if (f.cvssScore) {
      lines.push(`     CVSS Score:  ${f.cvssScore}`);
    }
    if (f.patchedVersion) {
      lines.push(`     Safe Version: >= ${f.patchedVersion}`);
    }
    if (f.advisoryUrl) {
      lines.push(`     Advisory:    ${f.advisoryUrl}`);
    }
    lines.push(`     Remediation: 💡 ${f.remediation}\n`);
  });

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

    case "scan-code": {
      const targetPath = args[1] || ".";

      const formatIdx = args.indexOf("--format");
      const format = formatIdx !== -1 && args[formatIdx + 1] ? args[formatIdx + 1] : "text";

      const threshIdx = args.indexOf("--threshold");
      const threshold = (
        threshIdx !== -1 && args[threshIdx + 1] ? args[threshIdx + 1].toUpperCase() : undefined
      ) as FindingSeverity | undefined;

      const langIdx = args.indexOf("--languages");
      const languages =
        langIdx !== -1 && args[langIdx + 1]
          ? (args[langIdx + 1].split(",") as SupportedLanguage[])
          : undefined;

      const scanner = new SastScanner();
      try {
        const report = await scanner.scanPath(targetPath, {
          threshold,
          languages,
        });

        if (format === "json") {
          console.log(JSON.stringify(report, null, 2));
        } else {
          console.log(renderSastTextReport(report));
        }
      } catch (err) {
        console.error(`❌ SAST scan failed for path '${targetPath}': ${(err as Error).message}`);
        process.exit(1);
      }
      break;
    }

    case "scan-secrets": {
      const targetPath = args[1] || ".";

      const formatIdx = args.indexOf("--format");
      const format = formatIdx !== -1 && args[formatIdx + 1] ? args[formatIdx + 1] : "text";

      const entropyIdx = args.indexOf("--min-entropy");
      const minEntropy =
        entropyIdx !== -1 && args[entropyIdx + 1]
          ? Number.parseFloat(args[entropyIdx + 1])
          : undefined;

      const scanGitHistory = args.includes("--git-history");

      const hunter = new SecretHunter();
      try {
        const report = scanGitHistory
          ? await hunter.scanGitHistory(targetPath, { minEntropy })
          : await hunter.scanPath(targetPath, { minEntropy });

        if (format === "json") {
          console.log(JSON.stringify(report, null, 2));
        } else {
          console.log(renderSecretsTextReport(report));
        }
      } catch (err) {
        console.error(`❌ Secret hunt failed for '${targetPath}': ${(err as Error).message}`);
        process.exit(1);
      }
      break;
    }

    case "scan-deps": {
      const targetPath = args[1] || ".";

      const formatIdx = args.indexOf("--format");
      const format = formatIdx !== -1 && args[formatIdx + 1] ? args[formatIdx + 1] : "text";

      const threshIdx = args.indexOf("--threshold");
      const threshold = (
        threshIdx !== -1 && args[threshIdx + 1] ? args[threshIdx + 1].toUpperCase() : undefined
      ) as FindingSeverity | undefined;

      const includeDev = args.includes("--dev");

      const scanner = new ScaScanner();
      try {
        const report = await scanner.scanManifest(targetPath, {
          includeDev,
          threshold,
        });

        if (format === "json") {
          console.log(JSON.stringify(report, null, 2));
        } else {
          console.log(renderScaTextReport(report));
        }
      } catch (err) {
        console.error(`❌ Dependency scan failed for '${targetPath}': ${(err as Error).message}`);
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
  [Phase 2] AST-Level SAST Engine        - ACTIVE
  [Phase 2] OWASP Top 10 Rules Registry  - ACTIVE (SQLi, CMD, XSS, SSRF, Crypto, Auth)
  [Phase 3] High-Entropy Secret Hunter   - ACTIVE (AWS, GCP, OpenAI, Claude, Stripe, GitHub, Private Keys)
  [Phase 3] SCA Dependency Auditor (OSV) - ACTIVE (CVE & GHSA Security Advisories)
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
