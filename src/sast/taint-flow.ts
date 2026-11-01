/**
 * Inter-File AST Taint Flow Analyzer
 *
 * Performs cross-module static data flow analysis, tracking untrusted HTTP route
 * inputs (req.params, req.query, req.body) across import/export boundaries down
 * to critical sinks (SQL queries, shell executions, SSRF, path traversal).
 */

import * as path from "node:path";
import type { TaintFlowFinding, TaintFlowTraceStep } from "../types/index.js";

export interface TaintSource {
  file: string;
  line: number;
  variable: string;
  expression: string;
}

export interface ExportedFunction {
  file: string;
  name: string;
  params: string[];
  body: string;
  startLine: number;
}

export interface ImportRef {
  symbol: string;
  moduleSpecifier: string;
  resolvedFile?: string;
  line: number;
}

export class InterFileTaintAnalyzer {
  /**
   * Analyzes an in-memory dictionary of files (filePath -> content) or a project structure
   * to discover cross-file taint flows from sources to sinks.
   */
  public analyzeProject(files: Map<string, string>): TaintFlowFinding[] {
    const findings: TaintFlowFinding[] = [];

    // 1. Index all exported functions across all files
    const exportMap = new Map<string, ExportedFunction[]>(); // normalizedFilePath -> functions
    for (const [filePath, content] of files.entries()) {
      const normPath = this.normalizePath(filePath);
      exportMap.set(normPath, this.extractExportedFunctions(content, normPath));
    }

    // 2. Index all imports across all files
    const importMap = new Map<string, ImportRef[]>(); // normPath -> imports
    for (const [filePath, content] of files.entries()) {
      const normPath = this.normalizePath(filePath);
      importMap.set(normPath, this.extractImports(content, normPath, files));
    }

    // 3. For each file, discover taint sources and trace calls across modules
    for (const [filePath, content] of files.entries()) {
      const normPath = this.normalizePath(filePath);
      const sources = this.extractTaintSources(content, normPath);
      const imports = importMap.get(normPath) || [];

      for (const source of sources) {
        // Look for calls to imported functions passing the tainted variable
        for (const imp of imports) {
          if (!imp.resolvedFile) continue;

          const callMatch = this.findFunctionCallPassingVariable(
            content,
            imp.symbol,
            source.variable,
          );
          if (!callMatch) continue;

          // Target function in imported file
          const targetFunctions = exportMap.get(imp.resolvedFile) || [];
          const targetFn = targetFunctions.find((f) => f.name === imp.symbol);
          if (!targetFn) continue;

          const taintedParamName = targetFn.params[callMatch.argIndex];
          if (!taintedParamName) continue;

          // Check for sinks in the target function body
          const targetContent = files.get(imp.resolvedFile) || targetFn.body;
          const sinkMatches = this.findSinksInFunction(
            targetFn,
            taintedParamName,
            imp.resolvedFile,
            targetContent,
          );

          for (const sink of sinkMatches) {
            const trace: TaintFlowTraceStep[] = [
              {
                file: source.file,
                line: source.line,
                symbol: source.variable,
                expression: source.expression,
                type: "SOURCE",
              },
              {
                file: source.file,
                line: callMatch.line,
                symbol: imp.symbol,
                expression: callMatch.expression,
                type: "PROPAGATION",
              },
              {
                file: sink.file,
                line: sink.line,
                symbol: taintedParamName,
                expression: sink.expression,
                type: "SINK",
              },
            ];

            findings.push({
              id: `${sink.ruleId}-${path.basename(source.file)}-to-${path.basename(sink.file)}-L${sink.line}`,
              ruleId: sink.ruleId,
              category: "INJECTION",
              title: sink.title,
              severity: "CRITICAL",
              cwe: sink.cwe,
              owasp: "A03:2021-Injection",
              file: sink.file,
              line: sink.line,
              column: 1,
              snippet: sink.expression,
              description: `Inter-file taint flow detected: Untrusted input '${source.variable}' from ${path.basename(source.file)}:${source.line} propagates into '${taintedParamName}' of ${targetFn.name}() in ${path.basename(sink.file)}:${sink.line} without sanitization.`,
              remediation: sink.remediation,
              cvssScore: 9.8,
              cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
              confidence: "HIGH",
              confidenceScore: 0.98,
              sourceFile: source.file,
              sourceLine: source.line,
              sourceExpression: source.expression,
              sinkFile: sink.file,
              sinkLine: sink.line,
              sinkExpression: sink.expression,
              taintTrace: trace,
            });
          }
        }
      }
    }

    return findings;
  }

  /**
   * Normalizes file paths for consistent map lookup across operating systems.
   */
  private normalizePath(p: string): string {
    return p.replace(/\\/g, "/");
  }

  /**
   * Discovers untrusted input taint sources (Express/Koa/Fastify/Next.js/Flask/FastAPI/Go).
   */
  public extractTaintSources(content: string, filePath: string): TaintSource[] {
    const sources: TaintSource[] = [];
    const lines = content.split("\n");

    // Patterns for HTTP input extraction
    // e.g.: const id = req.params.id; or const { userId } = req.query; or request.args.get('id')
    const sourcePatterns = [
      /(?:const|let|var)\s+([a-zA-Z0-9_]+)\s*=\s*(?:req|request|ctx)\.(?:params|query|body)(?:\.([a-zA-Z0-9_]+)|\[["']([a-zA-Z0-9_]+)["']\])/,
      /(?:const|let|var)\s*\{\s*([a-zA-Z0-9_,\s]+)\s*\}\s*=\s*(?:req|request|ctx)\.(?:params|query|body)/,
      /(?:const|let|var)\s+([a-zA-Z0-9_]+)\s*=\s*(?:req|request)\.(?:params|query|body)\b/,
      /([a-zA-Z0-9_]+)\s*=\s*request\.(?:args|form|values|json)(?:\[|\.get\()/i, // Python
    ];

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const trimmed = line.trim();
      if (trimmed.startsWith("//") || trimmed.startsWith("#")) continue;

      // Destructured: const { id, name } = req.params;
      const destrMatch = line.match(
        /(?:const|let|var)\s*\{\s*([a-zA-Z0-9_,\s]+)\s*\}\s*=\s*(?:req|request|ctx)\.(?:params|query|body)/,
      );
      if (destrMatch) {
        const vars = destrMatch[1]
          .split(",")
          .map((v) => v.trim())
          .filter(Boolean);
        for (const v of vars) {
          sources.push({
            file: filePath,
            line: i + 1,
            variable: v,
            expression: trimmed,
          });
        }
        continue;
      }

      // Direct assignment: const id = req.params.id;
      for (const pattern of sourcePatterns) {
        const match = line.match(pattern);
        if (match && match[1]) {
          sources.push({
            file: filePath,
            line: i + 1,
            variable: match[1].trim(),
            expression: trimmed,
          });
          break;
        }
      }
    }

    return sources;
  }

  /**
   * Extracts exported functions and their parameter lists from a file.
   */
  public extractExportedFunctions(content: string, filePath: string): ExportedFunction[] {
    const fns: ExportedFunction[] = [];
    const lines = content.split("\n");

    // Regex for exported JS/TS functions & Python functions
    // export async function getUser(userId: string, opts?: any)
    // export const getUser = (userId, opts) => ...
    // def get_user(user_id):
    const fnRegex =
      /(?:export\s+(?:async\s+)?function\s+([a-zA-Z0-9_]+)\s*\(([^)]*)\)|export\s+const\s+([a-zA-Z0-9_]+)\s*=\s*(?:async\s*)?\(([^)]*)\)\s*=>|def\s+([a-zA-Z0-9_]+)\s*\(([^)]*)\))/g;

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      fnRegex.lastIndex = 0;
      const match = fnRegex.exec(line);

      if (match) {
        const fnName = match[1] || match[3] || match[5];
        const rawParams = match[2] || match[4] || match[6] || "";

        const params = rawParams
          .split(",")
          .map((p) => {
            // Strip TypeScript type annotations e.g. "userId: string" -> "userId"
            const name = p.split(":")[0]?.trim().replace(/[?=]/g, "").trim();
            return name;
          })
          .filter(Boolean);

        // Approximate function body (next 60 lines or until export/end)
        const bodyLines = lines.slice(i, i + 60);
        fns.push({
          file: filePath,
          name: fnName,
          params,
          body: bodyLines.join("\n"),
          startLine: i + 1,
        });
      }
    }

    return fns;
  }

  /**
   * Extracts import references and resolves relative file locations.
   */
  public extractImports(
    content: string,
    currentFilePath: string,
    allFiles: Map<string, string>,
  ): ImportRef[] {
    const imports: ImportRef[] = [];
    const lines = content.split("\n");

    // import { getUser, findUser } from "./services/user.js"
    const importRegex = /import\s*\{\s*([a-zA-Z0-9_,\s]+)\s*\}\s*from\s*["']([^"']+)["']/g;

    const currentDir = path.dirname(currentFilePath);

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      importRegex.lastIndex = 0;
      const match = importRegex.exec(line);

      if (match) {
        const symbols = match[1]
          .split(",")
          .map((s) => s.trim())
          .filter(Boolean);
        const specifier = match[2];

        // Resolve local relative imports
        let resolvedFile: string | undefined;
        if (specifier.startsWith(".")) {
          const resolvedBase = this.normalizePath(path.join(currentDir, specifier));
          // Try exact, with .ts, .js, .tsx, /index.ts, etc.
          const candidates = [
            resolvedBase,
            `${resolvedBase}.ts`,
            `${resolvedBase}.js`,
            resolvedBase.replace(/\.js$/, ".ts"),
            `${resolvedBase}/index.ts`,
            `${resolvedBase}/index.js`,
          ];

          for (const cand of candidates) {
            if (allFiles.has(cand)) {
              resolvedFile = cand;
              break;
            }
          }
        }

        for (const symbol of symbols) {
          imports.push({
            symbol,
            moduleSpecifier: specifier,
            resolvedFile,
            line: i + 1,
          });
        }
      }
    }

    return imports;
  }

  /**
   * Detects a function call passing a tainted variable as an argument.
   */
  public findFunctionCallPassingVariable(
    content: string,
    functionName: string,
    variableName: string,
  ): { line: number; argIndex: number; expression: string } | null {
    const lines = content.split("\n");
    // Match functionName(...)
    const callPattern = new RegExp(`\\b${functionName}\\s*\\(([^)]*)\\)`);

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const match = line.match(callPattern);
      if (match) {
        const args = match[1].split(",").map((a) => a.trim());
        const argIndex = args.findIndex((a) => a === variableName || a.includes(variableName));
        if (argIndex !== -1) {
          return {
            line: i + 1,
            argIndex,
            expression: line.trim(),
          };
        }
      }
    }

    return null;
  }

  /**
   * Scans a target function body for dangerous sinks receiving the tainted parameter.
   */
  public findSinksInFunction(
    fn: ExportedFunction,
    paramName: string,
    targetFile: string,
    fullContent: string,
  ): Array<{
    ruleId: string;
    title: string;
    cwe: string;
    line: number;
    expression: string;
    remediation: string;
    file: string;
  }> {
    const results: Array<{
      ruleId: string;
      title: string;
      cwe: string;
      line: number;
      expression: string;
      remediation: string;
      file: string;
    }> = [];

    const lines = fullContent.split("\n");
    const searchRange = lines.slice(fn.startLine - 1, fn.startLine + 60);

    for (let offset = 0; offset < searchRange.length; offset++) {
      const line = searchRange[offset];
      const lineNum = fn.startLine + offset;
      const trimmed = line.trim();

      if (!trimmed.includes(paramName)) continue;

      // 1. SQL Injection Sinks
      if (
        /(?:db|pool|client|connection|knex|prisma|cursor)\.(?:query|execute|raw|\$queryRawUnsafe)\s*\(/i.test(
          trimmed,
        ) ||
        /(?:SELECT|INSERT|UPDATE|DELETE)\s+.*(?:WHERE|\+)/i.test(trimmed)
      ) {
        results.push({
          ruleId: "SAST-TAINT-SQL-INJECTION",
          title: "Cross-File Taint Flow: Untrusted Input Reaches SQL Query",
          cwe: "CWE-89",
          line: lineNum,
          expression: trimmed,
          remediation:
            "Use parameterized queries or prepared statements across service boundaries. Never concatenate external input directly into database queries.",
          file: targetFile,
        });
        continue;
      }

      // 2. Command Injection Sinks
      if (/(?:exec|execSync|spawn|os\.system|subprocess\.(?:Popen|run|call))\s*\(/i.test(trimmed)) {
        results.push({
          ruleId: "SAST-TAINT-COMMAND-INJECTION",
          title: "Cross-File Taint Flow: Untrusted Input Reaches Shell Command",
          cwe: "CWE-78",
          line: lineNum,
          expression: trimmed,
          remediation:
            "Avoid shell command execution with user-controlled input. Use argument lists and disable shell interpretation (shell: false).",
          file: targetFile,
        });
        continue;
      }

      // 3. SSRF Sinks
      if (/(?:fetch|axios(?:\.get|\.post)?|http\.get|urllib\.request)\s*\(/i.test(trimmed)) {
        results.push({
          ruleId: "SAST-TAINT-SSRF",
          title: "Cross-File Taint Flow: Untrusted Input Reaches HTTP Fetch Request",
          cwe: "CWE-918",
          line: lineNum,
          expression: trimmed,
          remediation:
            "Validate target URLs against an explicit domain allowlist and block private IP address ranges (127.0.0.1, 169.254.169.254, RFC 1918).",
          file: targetFile,
        });
        continue;
      }

      // 4. Path Traversal Sinks
      if (/(?:fs\.(?:readFile|writeFile|unlink)|path\.join)\s*\(/i.test(trimmed)) {
        results.push({
          ruleId: "SAST-TAINT-PATH-TRAVERSAL",
          title: "Cross-File Taint Flow: Untrusted Input Reaches Filesystem Operation",
          cwe: "CWE-22",
          line: lineNum,
          expression: trimmed,
          remediation:
            "Sanitize filename inputs, strip directory traversal characters (../, ..\\), and verify the canonical path remains within the intended root directory.",
          file: targetFile,
        });
      }
    }

    return results;
  }
}
