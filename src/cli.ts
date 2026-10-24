#!/usr/bin/env node
import * as fs from "node:fs/promises";
import * as path from "node:path";
import {
  BotServer,
  type BotSeverityGate,
  GitHubClient,
  PrDiffScanner,
  PrPatcher,
} from "./bot/index.js";
import { DastScanner } from "./dast/index.js";
import { startMcpServer } from "./mcp/index.js";
import { PatchEngine } from "./patch/index.js";
import { generateHtmlReport, generateSarifReport } from "./reporting/index.js";
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

const VERSION = "1.1.0";

const HELP_TEXT = `
  🛡️  WebSecAuditor - Enterprise AI Web Cybersecurity Auditor v${VERSION}
  ─────────────────────────────────────────────────────────────
  Multi-vector security auditor detecting vulnerabilities, misconfigurations,
  credential leaks, CVSS v3.1 risks, and compliance gaps across web stacks.

  USAGE:
    web-sec-auditor [command] [options]

  COMMANDS:
    audit [target]        Run unified multi-vector audit (DAST if URL, or SAST+Secrets+SCA)
    scan-url <url>        Audit a live web application or API endpoint (DAST & Headers)
    scan-code <path>      Audit local source code or repository (SAST & OWASP Top 10)
    scan-secrets <path>   Hunt for leaked API keys and high-entropy credentials
    scan-deps <path>      Audit third-party dependencies for known CVEs (SCA via OSV)
    patch <file>          Apply an automated remediation patch to a vulnerable line
    bot                   Start GitHub App webhook listener server for automated PR audits
    pr-scan               Audit a Pull Request diff directly (for GitHub Actions / CI)
    mcp                   Start Model Context Protocol (MCP) server over stdio
    status                Display auditor capabilities and supported security checks
    help                  Display this help message

  OPTIONS:
    --format <text|json>        Output format (default: text)
    --sarif <file.sarif>        Export standardized OASIS SARIF v2.1.0 log
    --html <file.html>          Export self-contained interactive HTML executive dashboard
    --fail-on <level>           CI/CD break-build gate (CRITICAL, HIGH, MEDIUM, LOW)
    --threshold <level>         Minimum severity threshold (CRITICAL, HIGH, MEDIUM, LOW, INFO)
    --timeout <ms>              Request timeout in milliseconds (default: 10000)
    --languages <lang1,lang2>   Filter languages for SAST (ts, js, py, go)
    --min-entropy <float>       Minimum Shannon entropy threshold for secret hunter (default: 3.5)
    --git-history               Scan git commit diff history for deleted/historical secrets
    --dev                       Include devDependencies in SCA dependency scan
    --diff                      Display unified git diff auto-patch recipes in scan reports
    --line <number>             Target line number for patch command
    --rule <ruleId>             Rule ID for patch command (e.g. SEC-INJ-SQLI)
    --dry-run                   Preview patch unified diff without modifying file on disk
    --port <number>             Port for bot webhook listener (default: 3000)
    --secret <secret>           Webhook HMAC secret (or env WEBHOOK_SECRET)
    --token <token>             GitHub Token (or env GITHUB_TOKEN)
    --app-id <id>               GitHub App ID (or env GITHUB_APP_ID)
    --private-key <pem>         GitHub App Private Key PEM string or path
    --pr <number>               Pull request number for pr-scan command
    --owner <owner>             Repository owner for pr-scan command
    --repo <repo>               Repository name for pr-scan command
    --auto-patch                Automatically open remediation PR for critical findings
    --no-cert                   Skip raw TLS peer certificate handshake inspection
    --version, -v               Display version
    --help, -h                  Display help

  EXAMPLES:
    web-sec-auditor audit . --sarif report.sarif --html report.html --fail-on HIGH
    web-sec-auditor bot --port 3000 --auto-patch
    web-sec-auditor pr-scan --owner acme --repo backend --pr 42 --fail-on HIGH
    web-sec-auditor scan-url https://example.com
    web-sec-auditor scan-code ./src --threshold HIGH --diff
    web-sec-auditor scan-secrets . --git-history
    web-sec-auditor scan-deps . --dev
    web-sec-auditor patch ./src/user.ts --line 42 --rule SEC-INJ-SQLI
    web-sec-auditor mcp
`;

const SEVERITY_RANKS: Record<FindingSeverity, number> = {
  CRITICAL: 4,
  HIGH: 3,
  MEDIUM: 2,
  LOW: 1,
  INFO: 0,
};

function checkFailOn(findings: Array<{ severity: FindingSeverity }>, failOnLevel?: string): void {
  if (!failOnLevel) return;
  const targetRank = SEVERITY_RANKS[failOnLevel.toUpperCase() as FindingSeverity];
  if (targetRank === undefined) return;

  const failingIssues = findings.filter((f) => SEVERITY_RANKS[f.severity] >= targetRank);
  if (failingIssues.length > 0) {
    console.error(
      `\n🚨 CI/CD Gate Broken: Found ${failingIssues.length} issue(s) matching or exceeding threshold '${failOnLevel.toUpperCase()}'.`,
    );
    process.exit(1);
  }
}

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

function renderSastTextReport(report: SastScanReport, showDiff = false): string {
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
    if (f.cvssScore) {
      lines.push(`     CVSS v3.1:   Score ${f.cvssScore} (${f.cvssVector})`);
    }
    if (f.compliance) {
      const parts: string[] = [];
      if (f.compliance.cweTop25Rank) parts.push(`CWE Top 25 (#${f.compliance.cweTop25Rank})`);
      if (f.compliance.pciDss?.length) parts.push(`PCI-DSS: ${f.compliance.pciDss[0]}`);
      if (f.compliance.soc2?.length) parts.push(`SOC 2: ${f.compliance.soc2[0]}`);
      lines.push(`     Compliance:  ${parts.join(" | ")}`);
    }
    lines.push(`     Snippet:     ${f.snippet}`);
    lines.push(`     Description: ${f.description}`);
    lines.push(`     Remediation: 💡 ${f.remediation}`);

    if (showDiff && f.patch?.diff) {
      lines.push("\n     📝 Auto-Patch Preview (Unified Diff):");
      for (const dLine of f.patch.diff.split("\n")) {
        lines.push(`        ${dLine}`);
      }
    }
    lines.push("");
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

  // Handle MCP server start
  if (command === "mcp") {
    await startMcpServer();
    return;
  }

  const sarifIdx = args.indexOf("--sarif");
  const sarifPath = sarifIdx !== -1 ? args[sarifIdx + 1] : undefined;

  const htmlIdx = args.indexOf("--html");
  const htmlPath = htmlIdx !== -1 ? args[htmlIdx + 1] : undefined;

  const failOnIdx = args.indexOf("--fail-on");
  const failOnLevel = failOnIdx !== -1 ? args[failOnIdx + 1] : undefined;

  switch (command) {
    case "audit": {
      const target = args[1] || ".";
      const isUrl = target.startsWith("http://") || target.startsWith("https://");

      console.log(`\n🛡️  Starting Unified Security Audit on '${target}'...`);

      let dastReport: DastScanReport | undefined;
      let sastReport: SastScanReport | undefined;
      let secretReport: SecretScanReport | undefined;
      let scaReport: ScaScanReport | undefined;

      if (isUrl) {
        const dast = new DastScanner();
        dastReport = await dast.scanUrl(target);
        console.log(renderTextReport(dastReport));
      } else {
        // 1. SAST scan
        const sast = new SastScanner();
        sastReport = await sast.scanPath(target);
        console.log(renderSastTextReport(sastReport, args.includes("--diff")));

        // 2. Secret scan
        const hunter = new SecretHunter();
        secretReport = await hunter.scanPath(target);
        console.log(renderSecretsTextReport(secretReport));

        // 3. SCA scan (if package.json exists)
        try {
          const pkgPath = path.resolve(target, "package.json");
          await fs.stat(pkgPath);
          const sca = new ScaScanner();
          scaReport = await sca.scanManifest(pkgPath, {
            includeDev: args.includes("--dev"),
          });
          console.log(renderScaTextReport(scaReport));
        } catch {
          // No package.json in target directory
        }
      }

      // Export SARIF if requested
      if (sarifPath) {
        const sarifLog = generateSarifReport({
          dastReport,
          sastReport,
          secretReport,
          scaReport,
        });
        await fs.writeFile(path.resolve(sarifPath), JSON.stringify(sarifLog, null, 2), "utf-8");
        console.log(`📄 Standardized SARIF v2.1.0 report saved to '${sarifPath}'`);
      }

      // Export HTML if requested
      if (htmlPath) {
        const htmlDoc = generateHtmlReport({
          dastReport,
          sastReport,
          secretReport,
          scaReport,
        });
        await fs.writeFile(path.resolve(htmlPath), htmlDoc, "utf-8");
        console.log(`📊 Executive HTML dashboard saved to '${htmlPath}'`);
      }

      // Evaluate CI/CD fail-on gate
      const allFindings = [
        ...(dastReport?.findings || []),
        ...(sastReport?.findings || []),
        ...(secretReport?.findings || []),
        ...(scaReport?.findings || []),
      ];
      checkFailOn(allFindings, failOnLevel);
      break;
    }

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

        if (sarifPath) {
          const sarifLog = generateSarifReport({ dastReport: report });
          await fs.writeFile(path.resolve(sarifPath), JSON.stringify(sarifLog, null, 2), "utf-8");
          console.log(`📄 SARIF report saved to '${sarifPath}'`);
        }

        checkFailOn(report.findings, failOnLevel);
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

      const showDiff = args.includes("--diff");

      const scanner = new SastScanner();
      try {
        const report = await scanner.scanPath(targetPath, {
          threshold,
          languages,
        });

        if (format === "json") {
          console.log(JSON.stringify(report, null, 2));
        } else {
          console.log(renderSastTextReport(report, showDiff));
        }

        if (sarifPath) {
          const sarifLog = generateSarifReport({ sastReport: report });
          await fs.writeFile(path.resolve(sarifPath), JSON.stringify(sarifLog, null, 2), "utf-8");
          console.log(`📄 SARIF report saved to '${sarifPath}'`);
        }

        checkFailOn(report.findings, failOnLevel);
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

        if (sarifPath) {
          const sarifLog = generateSarifReport({ secretReport: report });
          await fs.writeFile(path.resolve(sarifPath), JSON.stringify(sarifLog, null, 2), "utf-8");
          console.log(`📄 SARIF report saved to '${sarifPath}'`);
        }

        checkFailOn(report.findings, failOnLevel);
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

        if (sarifPath) {
          const sarifLog = generateSarifReport({ scaReport: report });
          await fs.writeFile(path.resolve(sarifPath), JSON.stringify(sarifLog, null, 2), "utf-8");
          console.log(`📄 SARIF report saved to '${sarifPath}'`);
        }

        checkFailOn(report.findings, failOnLevel);
      } catch (err) {
        console.error(`❌ Dependency scan failed for '${targetPath}': ${(err as Error).message}`);
        process.exit(1);
      }
      break;
    }

    case "patch": {
      const targetFile = args[1];
      if (!targetFile) {
        console.error(
          "❌ Error: Target file path is required.\nUsage: web-sec-auditor patch <file> --line <number> --rule <ruleId>",
        );
        process.exit(1);
      }

      const lineIdx = args.indexOf("--line");
      const lineNumber =
        lineIdx !== -1 && args[lineIdx + 1] ? Number.parseInt(args[lineIdx + 1], 10) : undefined;

      const ruleIdx = args.indexOf("--rule");
      const ruleId = ruleIdx !== -1 ? args[ruleIdx + 1] : undefined;

      if (!lineNumber || !ruleId) {
        console.error("❌ Error: Both --line <number> and --rule <ruleId> are required.");
        process.exit(1);
      }

      const dryRun = args.includes("--dry-run");

      try {
        const resolved = path.resolve(targetFile);
        const content = await fs.readFile(resolved, "utf-8");
        const patchEngine = new PatchEngine();
        const recipe = patchEngine.generatePatch(resolved, content, lineNumber, ruleId);

        if (!recipe) {
          console.log(
            `ℹ️  No automatic remediation recipe available for rule '${ruleId}' at line ${lineNumber}.`,
          );
          process.exit(0);
        }

        console.log(`
🛠️  Auto-Patch Generated for ${targetFile}:${lineNumber} (${ruleId}):
─────────────────────────────────────────────────────────────
${recipe.diff}
─────────────────────────────────────────────────────────────
💡 Explanation: ${recipe.explanation}
`);

        if (!dryRun) {
          await patchEngine.applyPatch(recipe);
          console.log(`✅ Patch applied successfully to ${targetFile}!`);
        } else {
          console.log("ℹ️  Dry-run mode: file was not modified.");
        }
      } catch (err) {
        console.error(`❌ Patch application failed: ${(err as Error).message}`);
        process.exit(1);
      }
      break;
    }

    case "bot": {
      const portIdx = args.indexOf("--port");
      const port =
        portIdx !== -1
          ? Number.parseInt(args[portIdx + 1], 10)
          : Number.parseInt(process.env.PORT || "3000", 10);

      const secretIdx = args.indexOf("--secret");
      const webhookSecret = secretIdx !== -1 ? args[secretIdx + 1] : process.env.WEBHOOK_SECRET;

      const tokenIdx = args.indexOf("--token");
      const githubToken = tokenIdx !== -1 ? args[tokenIdx + 1] : process.env.GITHUB_TOKEN;

      const appIdIdx = args.indexOf("--app-id");
      const appId = appIdIdx !== -1 ? args[appIdIdx + 1] : process.env.GITHUB_APP_ID;

      const privKeyIdx = args.indexOf("--private-key");
      let privateKey =
        privKeyIdx !== -1 ? args[privKeyIdx + 1] : process.env.GITHUB_APP_PRIVATE_KEY;

      if (
        privateKey &&
        !privateKey.includes("BEGIN RSA PRIVATE KEY") &&
        !privateKey.includes("BEGIN PRIVATE KEY")
      ) {
        try {
          privateKey = await fs.readFile(path.resolve(privateKey), "utf-8");
        } catch {
          // Keep raw value
        }
      }

      const autoPatch =
        args.includes("--auto-patch") || process.env.AUTO_PATCH_ON_CRITICAL === "true";

      const server = new BotServer({
        port,
        webhookSecret,
        githubToken,
        appId,
        privateKey,
        autoPatchOnCritical: autoPatch,
        failOnSeverity: (failOnLevel?.toUpperCase() as BotSeverityGate) || "HIGH",
      });

      const actualPort = await server.listen(port);
      console.log(`
🛡️  WebSecAuditor GitHub App Bot & Automated PR Scanner
─────────────────────────────────────────────────────────────
Status:          LISTENING on port ${actualPort}
Webhook URL:     http://localhost:${actualPort}/webhook
Health Check:    http://localhost:${actualPort}/health
Severity Gate:   ${failOnLevel ? failOnLevel.toUpperCase() : "HIGH"}
Auto-Patch PR:   ${autoPatch ? "ENABLED (1-Click fix PRs enabled)" : "DISABLED"}
HMAC Auth:       ${webhookSecret ? "ENABLED" : "DISABLED (Secret missing)"}
─────────────────────────────────────────────────────────────
Waiting for pull_request and issue_comment webhook events...
`);
      break;
    }

    case "pr-scan": {
      const prIdx = args.indexOf("--pr");
      const prNumber = prIdx !== -1 ? Number.parseInt(args[prIdx + 1], 10) : undefined;

      const ownerIdx = args.indexOf("--owner");
      const owner = ownerIdx !== -1 ? args[ownerIdx + 1] : undefined;

      const repoIdx = args.indexOf("--repo");
      const repo = repoIdx !== -1 ? args[repoIdx + 1] : undefined;

      const tokenIdx = args.indexOf("--token");
      const token = tokenIdx !== -1 ? args[tokenIdx + 1] : process.env.GITHUB_TOKEN;

      const diffIdx = args.indexOf("--diff-file");
      const diffFile = diffIdx !== -1 ? args[diffIdx + 1] : undefined;

      if (!diffFile && (!prNumber || !owner || !repo)) {
        console.error(
          "❌ pr-scan requires either --diff-file <path> OR (--owner <o> --repo <r> --pr <num>)",
        );
        process.exit(1);
      }

      const autoPatch = args.includes("--auto-patch");
      const failGate = (failOnLevel?.toUpperCase() as BotSeverityGate) || "HIGH";

      let diffText = "";
      const scanFiles: Array<{ path: string; content: string }> = [];

      if (diffFile) {
        diffText = await fs.readFile(path.resolve(diffFile), "utf-8");
      } else if (owner && repo && prNumber && token) {
        const client = new GitHubClient({ githubToken: token });
        diffText = await client.getPullRequestDiff(owner, repo, prNumber);
      }

      const { parseUnifiedDiff } = await import("./bot/diff.js");
      const parsed = parseUnifiedDiff(diffText);
      for (const f of parsed) {
        if (f.status === "deleted") continue;
        const filePath = f.newPath || f.oldPath;
        try {
          const content = await fs.readFile(path.resolve(filePath), "utf-8");
          scanFiles.push({ path: filePath, content });
        } catch {
          // File not present in local workspace
        }
      }

      const scanner = new PrDiffScanner();
      const summary = await scanner.scanDiff(scanFiles, diffText, {
        owner,
        repo,
        prNumber,
        failOnSeverity: failGate,
      });

      console.log(scanner.generateMarkdownReview(summary));

      if (autoPatch && summary.patchableCount > 0) {
        console.log(`\n⚡ Applying ${summary.patchableCount} automated security patches...`);
        const patcher = new PrPatcher();
        const { patchedFilesMap, recipesApplied } = patcher.generatePatchedFiles(
          scanFiles,
          summary.findings,
        );
        for (const [fp, content] of patchedFilesMap.entries()) {
          await fs.writeFile(path.resolve(fp), content, "utf-8");
          console.log(`  ✅ Patched: ${fp}`);
        }
        console.log(`✨ Successfully remediated ${recipesApplied} vulnerabilities on disk!`);
      }

      if (!summary.passedGate) {
        console.error(
          `\n🚨 PR Security Gate Broken: Issues found matching or exceeding ${summary.failOnLevel}`,
        );
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
  [Phase 4] CVSS v3.1 Scoring Engine     - ACTIVE (Base Score, Impact, Exploitability, Vectors)
  [Phase 4] Compliance Mapping Engine    - ACTIVE (OWASP, PCI-DSS v4.0, SOC 2, CWE Top 25)
  [Phase 4] Automated Code Patch Engine  - ACTIVE (Unified Git Diff & Direct Remediation)
  [Phase 5] OASIS SARIF v2.1.0 Exporter  - ACTIVE (GitHub Advanced Security & GitLab)
  [Phase 5] Executive HTML Dashboard     - ACTIVE (Self-Contained Interactive Dashboard)
  [Phase 5] Universal MCP Server         - ACTIVE (Cursor, Claude Desktop, Antigravity)
  [Phase 5] CI/CD Break-Build Gate       - ACTIVE (--fail-on critical|high|medium|low)
  [Enterprise] GitHub App Webhook Bot    - ACTIVE (Automated PR Scanning & Checks API)
  [Enterprise] 1-Click Auto-Patch Engine - ACTIVE (Auto-Branching & Fix Pull Requests)
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
