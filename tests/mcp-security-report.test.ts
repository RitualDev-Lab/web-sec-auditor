import assert from "node:assert";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import {
  McpReportGenerator,
  McpSecurityScanner,
  TOP_100_MCP_SERVERS,
} from "../src/mcp-auditor/index.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

test("Top 100 MCP Server Vulnerability & Security Report Suite", async (t) => {
  await t.test("Loads exactly 100 top MCP server profiles", () => {
    assert.strictEqual(TOP_100_MCP_SERVERS.length, 100, "Must load exactly 100 MCP servers");
  });

  await t.test("Scanner correctly flags shell execution (CWE-78) on unsandboxed servers", () => {
    const scanner = new McpSecurityScanner();
    const shellServer = TOP_100_MCP_SERVERS.find((s) => s.id === "mcp-shell-exec");
    assert.ok(shellServer, "Shell server must exist in dataset");

    const result = scanner.auditServer(shellServer);
    assert.strictEqual(result.grade, "F", "Unsandboxed shell execution must receive Grade F");
    const cwe78 = result.findings.find((f) => f.cwe === "CWE-78");
    assert.ok(cwe78, "Must detect CWE-78");
    assert.strictEqual(cwe78.severity, "critical");
  });

  await t.test("Scanner assigns Grade A/A+ to sandboxed, bounded servers", () => {
    const scanner = new McpSecurityScanner();
    const gitServer = TOP_100_MCP_SERVERS.find((s) => s.id === "mcp-git");
    assert.ok(gitServer, "Git server must exist in dataset");

    const result = scanner.auditServer(gitServer);
    assert.ok(["A+", "A"].includes(result.grade), "Sandboxed server should receive Grade A or A+");
    assert.ok(result.securityScore >= 85);
  });

  await t.test("ReportGenerator generates comprehensive report and markdown table", () => {
    const report = McpReportGenerator.writeReports();
    assert.strictEqual(report.totalServersAudited, 100);
    assert.ok(report.averageScore > 0);
    assert.ok(report.servers.length === 100);

    const reportsDir = path.join(__dirname, "..", "reports");
    const mdPath = path.join(reportsDir, "top-100-mcp-security-report.md");
    const jsonPath = path.join(reportsDir, "top-100-mcp-security-report.json");

    assert.ok(fs.existsSync(mdPath), "Markdown report must exist");
    assert.ok(fs.existsSync(jsonPath), "JSON report must exist");

    const mdContent = fs.readFileSync(mdPath, "utf8");
    assert.ok(mdContent.includes("Top 100 MCP Server Vulnerability & Security Report"));
    assert.ok(mdContent.includes("CWE-78"));
    assert.ok(mdContent.includes("CWE-918"));
  });
});
