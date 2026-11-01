/**
 * Official WebSecAuditor GitHub Action Runner
 *
 * Turnkey CI/CD security gate:
 * 1. Audits repository with multi-vector SAST, Inter-File Taint Flow, and Secret Hunter.
 * 2. Generates and exports OASIS SARIF v2.1.0 report.
 * 3. Uploads SARIF directly to the GitHub Security / Code Scanning tab.
 * 4. Posts rich executive summary comments on Pull Requests.
 * 5. Generates inline code review diffs with 1-click GitHub ```suggestion patches.
 */

import * as fs from "node:fs/promises";
import * as path from "node:path";
import * as zlib from "node:zlib";
import { GitHubClient } from "./bot/client.js";
import { generateSarifReport } from "./reporting/sarif.js";
import { SastScanner } from "./sast/engine.js";
import { ScaScanner } from "./sca/scanner.js";
import { SecretHunter } from "./secrets/hunter.js";
import type {
  FindingSeverity,
  GitHubActionOptions,
  SastFinding,
  ScaFinding,
  SecretFinding,
} from "./types/index.js";

const SEVERITY_LEVELS: Record<FindingSeverity, number> = {
  CRITICAL: 5,
  HIGH: 4,
  MEDIUM: 3,
  LOW: 2,
  INFO: 1,
};

export interface ActionRunResult {
  passed: boolean;
  totalFindings: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  sarifPath: string;
  prCommentPosted: boolean;
  inlineReviewSubmitted: boolean;
  sarifUploaded: boolean;
}

export class GitHubActionRunner {
  private options: GitHubActionOptions;

  constructor(options: GitHubActionOptions = {}) {
    this.options = {
      githubToken:
        process.env.INPUT_GITHUB_TOKEN || process.env.GITHUB_TOKEN || options.githubToken,
      targetDir:
        process.env.INPUT_TARGET_DIR || process.env.GITHUB_WORKSPACE || options.targetDir || ".",
      failOn: (process.env.INPUT_FAIL_ON as FindingSeverity) || options.failOn || "HIGH",
      sarifFile: process.env.INPUT_SARIF_FILE || options.sarifFile || "results.sarif",
      commentPr: process.env.INPUT_COMMENT_PR !== "false" && (options.commentPr ?? true),
      inlineReview: process.env.INPUT_INLINE_REVIEW !== "false" && (options.inlineReview ?? true),
      uploadSarif: process.env.INPUT_UPLOAD_SARIF !== "false" && (options.uploadSarif ?? true),
      verifySecrets:
        process.env.INPUT_VERIFY_SECRETS === "true" || (options.verifySecrets ?? false),
    };
  }

  /**
   * Main entrypoint executed when running as a GitHub Action step.
   */
  public async run(): Promise<ActionRunResult> {
    const targetDir = path.resolve(this.options.targetDir || ".");
    console.log(
      `\n🛡️ [WebSecAuditor Action] Running multi-vector cybersecurity audit against: ${targetDir}`,
    );

    // 1. Run SAST Scanner (including inter-file taint analysis)
    const sastScanner = new SastScanner();
    const sastReport = await sastScanner.scanPath(targetDir);
    console.log(
      `   • SAST: Scanned ${sastReport.filesScanned} files, discovered ${sastReport.findings.length} findings`,
    );

    // 2. Run Secret Hunter
    const secretHunter = new SecretHunter();
    const secretReport = await secretHunter.scanPath(targetDir, {
      verifySecrets: this.options.verifySecrets,
    });
    console.log(`   • Secrets: Discovered ${secretReport.findings.length} credential exposures`);

    // 3. Run SCA Scanner if package.json or lockfile exists
    const scaFindings: ScaFinding[] = [];
    try {
      const packageJsonPath = path.join(targetDir, "package.json");
      const stat = await fs.stat(packageJsonPath);
      if (stat.isFile()) {
        const scaScanner = new ScaScanner();
        const scaReport = await scaScanner.scanManifest(packageJsonPath);
        scaFindings.push(...scaReport.findings);
        console.log(
          `   • SCA: Audited dependencies, discovered ${scaReport.findings.length} vulnerabilities`,
        );
      }
    } catch {
      // Manifest not present, skip SCA
    }

    // Combine findings
    const allSastAndTaint = sastReport.findings;
    const allSecrets = secretReport.findings;

    const criticalCount =
      allSastAndTaint.filter((f) => f.severity === "CRITICAL").length +
      allSecrets.filter((f) => f.severity === "CRITICAL").length +
      scaFindings.filter((f) => f.severity === "CRITICAL").length;

    const highCount =
      allSastAndTaint.filter((f) => f.severity === "HIGH").length +
      allSecrets.filter((f) => f.severity === "HIGH").length +
      scaFindings.filter((f) => f.severity === "HIGH").length;

    const mediumCount =
      allSastAndTaint.filter((f) => f.severity === "MEDIUM").length +
      allSecrets.filter((f) => f.severity === "MEDIUM").length +
      scaFindings.filter((f) => f.severity === "MEDIUM").length;

    const lowCount =
      allSastAndTaint.filter((f) => f.severity === "LOW").length +
      allSecrets.filter((f) => f.severity === "LOW").length +
      scaFindings.filter((f) => f.severity === "LOW").length;

    const totalFindings = criticalCount + highCount + mediumCount + lowCount;

    // 4. Export SARIF v2.1.0 Report
    const sarifPath = path.resolve(this.options.sarifFile || "results.sarif");
    const sarifLog = generateSarifReport({
      sastReport,
      secretReport,
      scaReport:
        scaFindings.length > 0
          ? {
              manifestPath: "package.json",
              ecosystem: "npm",
              totalDependencies: scaFindings.length,
              vulnerableDependencies: scaFindings.length,
              scanTimestamp: new Date().toISOString(),
              durationMs: 0,
              summary: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
              findings: scaFindings,
            }
          : undefined,
    });
    const sarifJson = JSON.stringify(sarifLog, null, 2);
    await fs.writeFile(sarifPath, sarifJson, "utf-8");
    console.log(`✅ [WebSecAuditor Action] Exported SARIF v2.1.0 report: ${sarifPath}`);

    // Check pass/fail condition
    const failThreshold = SEVERITY_LEVELS[this.options.failOn || "HIGH"] || 4;
    let passed = true;
    if (failThreshold <= 5 && criticalCount > 0) passed = false;
    if (failThreshold <= 4 && highCount > 0) passed = false;
    if (failThreshold <= 3 && mediumCount > 0) passed = false;

    // 5. Detect GitHub Action Pull Request Context
    let prCommentPosted = false;
    let inlineReviewSubmitted = false;
    let sarifUploaded = false;

    const eventPath = process.env.GITHUB_EVENT_PATH;
    const repoSlug = process.env.GITHUB_REPOSITORY; // "owner/repo"

    let prNumber: number | undefined;
    let headSha: string | undefined;

    if (eventPath) {
      try {
        const eventData = JSON.parse(await fs.readFile(eventPath, "utf-8"));
        prNumber = eventData.pull_request?.number;
        headSha = eventData.pull_request?.head?.sha || process.env.GITHUB_SHA;
      } catch {
        // Not a PR event or failed to parse
      }
    }

    if (repoSlug && this.options.githubToken) {
      const [owner, repo] = repoSlug.split("/");
      const client = new GitHubClient({ githubToken: this.options.githubToken });

      // A. Post PR Summary Comment
      if (prNumber && this.options.commentPr) {
        try {
          const commentBody = this.formatPrComment(
            passed,
            allSastAndTaint,
            allSecrets,
            scaFindings,
            { criticalCount, highCount, mediumCount, lowCount },
          );
          await client.postIssueComment(owner, repo, prNumber, commentBody);
          prCommentPosted = true;
          console.log(
            `💬 [WebSecAuditor Action] Posted security summary comment to PR #${prNumber}`,
          );
        } catch (err: unknown) {
          console.warn(
            `⚠️ Could not post PR comment: ${err instanceof Error ? err.message : String(err)}`,
          );
        }
      }

      // B. Create PR Review with Inline ```suggestion Diffs
      if (prNumber && this.options.inlineReview && allSastAndTaint.length > 0) {
        try {
          const reviewComments: Array<{ path: string; line: number; body: string }> = [];

          for (const finding of allSastAndTaint) {
            const relFile = path.relative(targetDir, finding.file).replace(/\\/g, "/");

            let commentBody =
              `### 🛡️ WebSecAuditor: ${finding.title} (${finding.severity})\n` +
              `**CWE:** ${finding.cwe || "N/A"} | **OWASP:** ${finding.owasp || "N/A"}\n\n` +
              `${finding.description}\n\n`;

            if (finding.patch?.diff) {
              commentBody += `#### 🛠️ Automated 1-Click Defensive Patch:\n\`\`\`suggestion\n${finding.patch.diff}\n\`\`\`\n`;
            } else {
              commentBody += `**Remediation:** ${finding.remediation}\n`;
            }

            reviewComments.push({
              path: relFile,
              line: finding.line,
              body: commentBody,
            });
          }

          if (reviewComments.length > 0) {
            await client.createPrReview(owner, repo, prNumber, {
              commit_id: headSha,
              body: `### 🛡️ WebSecAuditor Security Review\nIdentified **${reviewComments.length}** code review suggestions on modified files.`,
              event: passed ? "COMMENT" : "REQUEST_CHANGES",
              comments: reviewComments.slice(0, 25), // GitHub API limit
            });
            inlineReviewSubmitted = true;
            console.log(
              `📝 [WebSecAuditor Action] Submitted inline review with ${reviewComments.length} patch suggestions.`,
            );
          }
        } catch (err: unknown) {
          console.warn(
            `⚠️ Could not post inline review: ${err instanceof Error ? err.message : String(err)}`,
          );
        }
      }

      // C. Direct SARIF Upload to GitHub Advanced Security Code Scanning
      if (this.options.uploadSarif && headSha) {
        try {
          sarifUploaded = await this.uploadSarifToGitHub(
            owner,
            repo,
            headSha,
            sarifJson,
            this.options.githubToken,
          );
          if (sarifUploaded) {
            console.log(
              `🔒 [WebSecAuditor Action] Uploaded SARIF report to GitHub Security / Code Scanning tab.`,
            );
          }
        } catch (err: unknown) {
          console.warn(
            `⚠️ Could not upload SARIF directly via API: ${err instanceof Error ? err.message : String(err)}`,
          );
        }
      }
    }

    return {
      passed,
      totalFindings,
      criticalCount,
      highCount,
      mediumCount,
      lowCount,
      sarifPath,
      prCommentPosted,
      inlineReviewSubmitted,
      sarifUploaded,
    };
  }

  /**
   * Directly uploads compressed SARIF payload to GitHub Code Scanning API.
   */
  private async uploadSarifToGitHub(
    owner: string,
    repo: string,
    commitSha: string,
    sarifContent: string,
    token: string,
  ): Promise<boolean> {
    const gzipped = zlib.gzipSync(Buffer.from(sarifContent, "utf-8")).toString("base64");
    const ref = process.env.GITHUB_REF || "refs/heads/main";

    const res = await fetch(`https://api.github.com/repos/${owner}/${repo}/code-scanning/sarifs`, {
      method: "POST",
      headers: {
        Accept: "application/vnd.github.v3+json",
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
        "User-Agent": "WebSecAuditor-Action/1.0",
      },
      body: JSON.stringify({
        commit_sha: commitSha,
        ref,
        sarif: gzipped,
      }),
    });

    return res.ok || res.status === 202;
  }

  /**
   * Formats the executive markdown comment posted on Pull Requests.
   */
  public formatPrComment(
    passed: boolean,
    sastFindings: SastFinding[],
    secretFindings: SecretFinding[],
    scaFindings: ScaFinding[],
    counts: { criticalCount: number; highCount: number; mediumCount: number; lowCount: number },
  ): string {
    const statusHeader = passed
      ? "## 🛡️ WebSecAuditor Gate: ✅ PASSED"
      : "## 🛡️ WebSecAuditor Gate: ❌ ACTION REQUIRED";

    return `${statusHeader}

| Critical | High | Medium | Low | Total Vulnerabilities |
| :---: | :---: | :---: | :---: | :---: |
| **${counts.criticalCount}** | **${counts.highCount}** | **${counts.mediumCount}** | **${counts.lowCount}** | **${counts.criticalCount + counts.highCount + counts.mediumCount + counts.lowCount}** |

${
  sastFindings.length > 0
    ? `### 🔍 Code Analysis & Taint Flow Findings (${sastFindings.length})
| Severity | Finding | Location | CWE |
| :--- | :--- | :--- | :--- |
${sastFindings
  .slice(0, 10)
  .map(
    (f) =>
      `| \`${f.severity}\` | **${f.title}** | \`${path.basename(f.file)}:${f.line}\` | \`${f.cwe || "N/A"}\` |`,
  )
  .join("\n")}
`
    : ""
}
${
  secretFindings.length > 0
    ? `### 🔑 Secret & API Credential Exposures (${secretFindings.length})
| Severity | Credential Type | Location | Status |
| :--- | :--- | :--- | :--- |
${secretFindings
  .slice(0, 5)
  .map(
    (s) =>
      `| \`${s.severity}\` | **${s.title}** | \`${path.basename(s.file)}:${s.line}\` | \`${s.verification?.status || "DETECTED"}\` |`,
  )
  .join("\n")}
`
    : ""
}
${
  scaFindings.length > 0
    ? `### 📦 Software Supply Chain (SCA) Advisories (${scaFindings.length})
| Package | Version | Advisory | Severity |
| :--- | :--- | :--- | :--- |
${scaFindings
  .slice(0, 5)
  .map(
    (a) =>
      `| \`${a.packageName}\` | \`${a.currentVersion}\` | [${a.title}](${a.advisoryUrl || "#"}) | \`${a.severity}\` |`,
  )
  .join("\n")}
`
    : ""
}

---
*Report generated automatically by [WebSecAuditor](https://github.com/RitualDev-Lab/web-sec-auditor). View detailed diagnostics in the **Security** tab.*
`;
  }
}
