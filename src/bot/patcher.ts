import * as fs from "node:fs/promises";
import * as path from "node:path";
import { PatchEngine } from "../patch/index.js";
import type { SastFinding } from "../types/index.js";
import type { GitHubClient } from "./client.js";
import type { DiffScanFile } from "./scanner.js";
import type { AnyAuditFinding, PatchPrResult, PrScanSummary } from "./types.js";

export class PrPatcher {
  private patchEngine: PatchEngine;

  constructor() {
    this.patchEngine = new PatchEngine();
  }

  /**
   * Applies auto-patch recipes in-memory to all vulnerable files.
   * Returns a map of filePath -> patchedContent, and combined unified diff.
   */
  public generatePatchedFiles(
    files: DiffScanFile[],
    findings: AnyAuditFinding[],
  ): {
    patchedFilesMap: Map<string, string>;
    combinedDiff: string;
    recipesApplied: number;
  } {
    const patchedFilesMap = new Map<string, string>();
    const diffSnippets: string[] = [];
    let recipesApplied = 0;

    // Group findings by file
    const fileFindings = new Map<string, SastFinding[]>();
    for (const f of findings) {
      if (f.findingType === "SAST") {
        const sast = f as SastFinding;
        const list = fileFindings.get(sast.file) ?? [];
        list.push(sast);
        fileFindings.set(sast.file, list);
      }
    }

    for (const [filePath, sastList] of fileFindings.entries()) {
      const targetFile = files.find(
        (fl) => fl.path.replace(/\\/g, "/") === filePath.replace(/\\/g, "/"),
      );
      if (!targetFile) continue;

      let currentContent = targetFile.content;

      // Sort findings in descending line order so line shifts do not break lower lines
      const sortedFindings = [...sastList].sort((a, b) => b.line - a.line);

      for (const f of sortedFindings) {
        const recipe = this.patchEngine.generatePatch(filePath, currentContent, f.line, f.ruleId);

        if (recipe) {
          currentContent = recipe.patchedContent;
          diffSnippets.push(recipe.diff);
          recipesApplied++;
        }
      }

      if (currentContent !== targetFile.content) {
        patchedFilesMap.set(filePath, currentContent);
      }
    }

    return {
      patchedFilesMap,
      combinedDiff: diffSnippets.join("\n\n"),
      recipesApplied,
    };
  }

  /**
   * Automatically creates a fix branch and opens a Pull Request on GitHub.
   */
  public async createFixPullRequest(
    client: GitHubClient,
    owner: string,
    repo: string,
    prNumber: number,
    files: DiffScanFile[],
    summary: PrScanSummary,
    installationId?: number,
  ): Promise<PatchPrResult> {
    try {
      // 1. Compute patched contents
      const { patchedFilesMap, combinedDiff, recipesApplied } = this.generatePatchedFiles(
        files,
        summary.findings,
      );

      if (patchedFilesMap.size === 0 || recipesApplied === 0) {
        return {
          success: false,
          branchName: "",
          filesPatched: [],
          unifiedDiff: "",
          error: "No automatically patchable vulnerabilities found in PR diff.",
        };
      }

      // 2. Fetch original PR details
      const prDetails = await client.getPullRequest(owner, repo, prNumber, installationId);
      const headSha = prDetails.head.sha;
      const headRef = prDetails.head.ref; // target branch to merge fix into

      // 3. Create unique patch branch
      const timestamp = Math.floor(Date.now() / 1000);
      const patchBranch = `web-sec-auditor/fix-pr-${prNumber}-${timestamp}`;

      await client.createBranch(owner, repo, patchBranch, headSha, installationId);

      // 4. Commit each patched file to the new branch
      const filesPatchedList: string[] = [];
      for (const [filePath, patchedContent] of patchedFilesMap.entries()) {
        let existingSha: string | undefined;
        try {
          const existingFile = await client.getFileContent(
            owner,
            repo,
            filePath,
            patchBranch,
            installationId,
          );
          existingSha = existingFile.sha;
        } catch {
          // File might not have existing sha on remote lookup
        }

        await client.putFileContent(
          owner,
          repo,
          filePath,
          patchedContent,
          `fix(security): auto-remediate vulnerabilities in ${filePath} via WebSecAuditor`,
          patchBranch,
          existingSha,
          installationId,
        );
        filesPatchedList.push(filePath);
      }

      // 5. Open fix Pull Request targeting original PR head branch
      const prBody = [
        "## 🛡️ WebSecAuditor Automated Security Remediation",
        "",
        `This automated pull request remediates **${recipesApplied} security vulnerability findings** identified in PR #${prNumber}.`,
        "",
        "### 📝 Modified Files:",
        filesPatchedList.map((f) => `- \`${f}\``).join("\n"),
        "",
        "### 🔍 Unified Git Diff Preview:",
        "```diff",
        combinedDiff,
        "```",
        "",
        "---",
        "*Generated by [WebSecAuditor](https://github.com/RitualDev-Lab/web-sec-auditor) • RitualDev Lab Enterprise DevSecOps*",
      ].join("\n");

      const createdPr = await client.openPullRequest(
        owner,
        repo,
        `fix(security): automated security patches for #${prNumber}`,
        patchBranch,
        headRef,
        prBody,
        installationId,
      );

      // 6. Post confirmation comment to the original PR
      const commentMsg = [
        "### 🚀 WebSecAuditor Auto-Patch Generated",
        "",
        `✅ Successfully generated defensive security fixes for **${recipesApplied} finding(s)**!`,
        "",
        `🔗 **Pull Request Created**: [#${createdPr.number}](${createdPr.html_url})`,
        `🌿 **Branch**: \`${patchBranch}\``,
        "",
        "Review and merge the patch PR into your branch to clear all blocking security gates.",
      ].join("\n");

      await client.postIssueComment(owner, repo, prNumber, commentMsg, installationId);

      return {
        success: true,
        branchName: patchBranch,
        commitSha: headSha,
        patchPrNumber: createdPr.number,
        patchPrUrl: createdPr.html_url,
        filesPatched: filesPatchedList,
        unifiedDiff: combinedDiff,
      };
    } catch (err: unknown) {
      return {
        success: false,
        branchName: "",
        filesPatched: [],
        unifiedDiff: "",
        error: err instanceof Error ? err.message : String(err),
      };
    }
  }
}
