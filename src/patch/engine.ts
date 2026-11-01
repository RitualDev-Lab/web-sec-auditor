import { exec } from "node:child_process";
import * as fs from "node:fs/promises";
import * as path from "node:path";
import type { PatchVerificationOptions, PatchVerificationResult } from "../types/index.js";
import { generateRemediation } from "./templates.js";

export interface AutoPatchRecipe {
  file: string;
  line: number;
  ruleId: string;
  originalCode: string;
  patchedCode: string;
  explanation: string;
  diff: string;
  patchedContent: string;
}

/**
 * Creates a standard unified git diff string.
 */
export function generateUnifiedDiff(
  filePath: string,
  originalLine: string,
  patchedLine: string,
  lineNumber: number,
): string {
  const normPath = filePath.replace(/\\/g, "/");
  return [
    `--- a/${normPath}`,
    `+++ b/${normPath}`,
    `@@ -${lineNumber},1 +${lineNumber},1 @@`,
    `-${originalLine}`,
    `+${patchedLine}`,
  ].join("\n");
}

export class PatchEngine {
  /**
   * Generates an automated remediation patch recipe and unified git diff for a finding.
   */
  public generatePatch(
    filePath: string,
    fileContent: string,
    lineNumber: number,
    ruleId: string,
  ): AutoPatchRecipe | undefined {
    const lines = fileContent.split("\n");
    const targetIdx = lineNumber - 1;

    if (targetIdx < 0 || targetIdx >= lines.length) {
      return undefined;
    }

    const originalLine = lines[targetIdx];
    const remediation = generateRemediation(originalLine, ruleId);

    if (!remediation) {
      return undefined;
    }

    // Preserve original line indentation
    const indentMatch = originalLine.match(/^(\s*)/);
    const indent = indentMatch ? indentMatch[1] : "";
    const patchedLine = `${indent}${remediation.replacementText}`;

    const newLines = [...lines];
    newLines[targetIdx] = patchedLine;
    const patchedContent = newLines.join("\n");

    const diff = generateUnifiedDiff(filePath, originalLine, patchedLine, lineNumber);

    return {
      file: filePath,
      line: lineNumber,
      ruleId,
      originalCode: originalLine.trim(),
      patchedCode: patchedLine.trim(),
      explanation: remediation.explanation,
      diff,
      patchedContent,
    };
  }

  /**
   * Applies an automated patch recipe directly to the target file on disk.
   */
  public async applyPatch(recipe: AutoPatchRecipe): Promise<void> {
    const resolved = path.resolve(recipe.file);
    await fs.writeFile(resolved, recipe.patchedContent, "utf-8");
  }

  /**
   * Dry-run verifies an automated patch recipe by temporarily writing it to disk,
   * executing the repository's test runner (npm test / pytest / go test) in an isolated
   * subprocess, and cleanly reverting the file back to its original state.
   */
  public async verifyPatchWithTests(
    recipe: AutoPatchRecipe,
    options?: PatchVerificationOptions,
  ): Promise<PatchVerificationResult> {
    const startTime = Date.now();
    const resolvedFile = path.resolve(recipe.file);
    const repoDir = options?.repoDir ? path.resolve(options.repoDir) : path.dirname(resolvedFile);
    const testCommand = options?.testCommand || (await this.detectTestCommand(repoDir));
    const timeoutMs = options?.timeoutMs ?? 30000;

    let originalContent: string;
    try {
      originalContent = await fs.readFile(resolvedFile, "utf-8");
    } catch (readErr) {
      return {
        passed: false,
        testCommand,
        exitCode: 1,
        stdout: "",
        stderr: `Failed to read file ${resolvedFile}: ${(readErr as Error).message}`,
        durationMs: Date.now() - startTime,
        revertedCleanly: true,
        error: (readErr as Error).message,
      };
    }

    let revertedCleanly = false;
    let stdout = "";
    let stderr = "";
    let exitCode: number | null = 0;
    let errorMsg: string | undefined;

    try {
      // 1. Temporarily write the patched content to disk
      await fs.writeFile(resolvedFile, recipe.patchedContent, "utf-8");

      // 2. Execute test command in isolated subprocess
      const result = await new Promise<{
        stdout: string;
        stderr: string;
        exitCode: number | null;
      }>((resolve) => {
        exec(
          testCommand,
          {
            cwd: repoDir,
            timeout: timeoutMs,
            env: { ...process.env, ...options?.env },
          },
          (err, out, errOut) => {
            if (err) {
              resolve({
                stdout: out ? String(out) : "",
                stderr: errOut ? String(errOut) : err.message,
                exitCode: typeof err.code === "number" ? err.code : 1,
              });
            } else {
              resolve({
                stdout: out ? String(out) : "",
                stderr: errOut ? String(errOut) : "",
                exitCode: 0,
              });
            }
          },
        );
      });

      stdout = result.stdout;
      stderr = result.stderr;
      exitCode = result.exitCode;
    } catch (execErr) {
      exitCode = 1;
      errorMsg = (execErr as Error).message;
      stderr += `\nSubprocess execution failed: ${errorMsg}`;
    } finally {
      // 3. Guaranteed clean reversion back to original content
      try {
        await fs.writeFile(resolvedFile, originalContent, "utf-8");
        revertedCleanly = true;
      } catch (revertErr) {
        revertedCleanly = false;
        stderr += `\nFailed to revert ${resolvedFile}: ${(revertErr as Error).message}`;
      }
    }

    return {
      passed: exitCode === 0,
      testCommand,
      exitCode,
      stdout,
      stderr,
      durationMs: Date.now() - startTime,
      revertedCleanly,
      error: errorMsg,
    };
  }

  private async detectTestCommand(repoDir: string): Promise<string> {
    const isWin = process.platform === "win32";
    const npmCmd = isWin ? "npm.cmd" : "npm";

    try {
      const pkgPath = path.join(repoDir, "package.json");
      await fs.access(pkgPath);
      return `${npmCmd} test`;
    } catch {}

    try {
      const pyCandidates = ["requirements.txt", "pyproject.toml", "pytest.ini", "setup.py"];
      for (const f of pyCandidates) {
        try {
          await fs.access(path.join(repoDir, f));
          return "pytest";
        } catch {}
      }
    } catch {}

    try {
      const goPath = path.join(repoDir, "go.mod");
      await fs.access(goPath);
      return "go test ./...";
    } catch {}

    return `${npmCmd} test`;
  }
}
