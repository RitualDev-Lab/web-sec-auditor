import * as fs from "node:fs/promises";
import * as path from "node:path";
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
}
