import * as fs from "node:fs/promises";
import * as path from "node:path";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { DastScanner } from "../dast/index.js";
import { PatchEngine } from "../patch/index.js";
import { SastScanner } from "../sast/index.js";
import { ScaScanner } from "../sca/index.js";
import { SecretHunter } from "../secrets/index.js";
import type { FindingSeverity } from "../types/index.js";

export function createMcpServer(): McpServer {
  const server = new McpServer({
    name: "web-sec-auditor",
    version: "1.0.0",
  });

  // 1. Tool: audit_url (DAST)
  server.tool(
    "audit_url",
    "Audit a live web application or API endpoint for missing security headers (CSP, HSTS, XFO), insecure cookies, dangerous CORS policies, and transport gaps.",
    {
      url: z.string().describe("Target URL to audit, e.g. https://example.com"),
      timeoutMs: z.number().optional().describe("Request timeout in milliseconds (default: 10000)"),
    },
    async ({ url, timeoutMs }) => {
      const scanner = new DastScanner({ timeoutMs });
      const report = await scanner.scanUrl(url);
      return {
        content: [
          {
            type: "text",
            text: JSON.stringify(report, null, 2),
          },
        ],
      };
    },
  );

  // 2. Tool: audit_code (SAST)
  server.tool(
    "audit_code",
    "Perform Static Application Security Testing (SAST) on source code or directories to detect SQLi, Command Injection, Path Traversal, DOM-XSS, SSRF, and broken cryptography.",
    {
      path: z.string().describe("Path to local file or directory to scan"),
      threshold: z
        .enum(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"])
        .optional()
        .describe("Minimum severity threshold"),
    },
    async ({ path: targetPath, threshold }) => {
      const scanner = new SastScanner();
      const report = await scanner.scanPath(targetPath, {
        threshold: threshold as FindingSeverity | undefined,
      });
      return {
        content: [
          {
            type: "text",
            text: JSON.stringify(report, null, 2),
          },
        ],
      };
    },
  );

  // 3. Tool: hunt_secrets (Secret Hunter)
  server.tool(
    "hunt_secrets",
    "Hunt for hardcoded cloud credentials (AWS, GCP), LLM API keys (OpenAI, Anthropic), payment tokens (Stripe), private keys, and high-entropy secrets in files or git history.",
    {
      path: z.string().describe("Path to local directory or git repository to scan"),
      gitHistory: z.boolean().optional().describe("Whether to scan git commit diff history"),
      minEntropy: z
        .number()
        .optional()
        .describe("Minimum Shannon entropy threshold (default: 3.5)"),
    },
    async ({ path: targetPath, gitHistory, minEntropy }) => {
      const hunter = new SecretHunter();
      const report = gitHistory
        ? await hunter.scanGitHistory(targetPath, { minEntropy })
        : await hunter.scanPath(targetPath, { minEntropy });
      return {
        content: [
          {
            type: "text",
            text: JSON.stringify(report, null, 2),
          },
        ],
      };
    },
  );

  // 4. Tool: audit_dependencies (SCA)
  server.tool(
    "audit_dependencies",
    "Audit third-party package dependencies in package.json against the OSV open-source vulnerability database for known CVEs and security advisories.",
    {
      manifestPath: z.string().describe("Path to package.json or directory containing it"),
      includeDev: z.boolean().optional().describe("Include devDependencies in the scan"),
    },
    async ({ manifestPath, includeDev }) => {
      const sca = new ScaScanner();
      const report = await sca.scanManifest(manifestPath, { includeDev });
      return {
        content: [
          {
            type: "text",
            text: JSON.stringify(report, null, 2),
          },
        ],
      };
    },
  );

  // 5. Tool: generate_patch (Auto-Patch)
  server.tool(
    "generate_patch",
    "Generate automated defensive remediation code and a unified git diff patch for a detected vulnerability.",
    {
      filePath: z.string().describe("Path to the vulnerable file"),
      lineNumber: z.number().describe("Line number where the vulnerability was flagged"),
      ruleId: z.string().describe("Vulnerability rule ID (e.g. SEC-INJ-SQLI, SEC-INJ-CMD)"),
    },
    async ({ filePath, lineNumber, ruleId }) => {
      const resolved = path.resolve(filePath);
      const content = await fs.readFile(resolved, "utf-8");
      const patchEngine = new PatchEngine();
      const recipe = patchEngine.generatePatch(resolved, content, lineNumber, ruleId);

      if (!recipe) {
        return {
          content: [
            {
              type: "text",
              text: `No automated patch recipe available for ${ruleId} at ${filePath}:${lineNumber}.`,
            },
          ],
        };
      }

      return {
        content: [
          {
            type: "text",
            text: JSON.stringify(recipe, null, 2),
          },
        ],
      };
    },
  );

  return server;
}

/**
 * Runs the MCP server over stdio for AI clients (Cursor, Claude Desktop, Antigravity, Windsurf).
 */
export async function startMcpServer(): Promise<void> {
  const server = createMcpServer();
  const transport = new StdioServerTransport();
  await server.connect(transport);
}
