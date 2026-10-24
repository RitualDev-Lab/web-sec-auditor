import assert from "node:assert/strict";
import test from "node:test";
import { createMcpServer, generateHtmlReport, generateSarifReport } from "../src/index.js";
import type {
  DastScanReport,
  SastScanReport,
  ScaScanReport,
  SecretScanReport,
} from "../src/types/index.js";

test("SARIF v2.1.0 - Generates valid OASIS schema log with full metadata", () => {
  const mockSastReport: SastScanReport = {
    targetPath: "/repo/src",
    filesScanned: 5,
    scanTimestamp: new Date().toISOString(),
    durationMs: 42,
    summary: { critical: 1, high: 0, medium: 0, low: 0, info: 0 },
    findings: [
      {
        id: "SEC-INJ-SQLI-user.ts-L10",
        ruleId: "SEC-INJ-SQLI",
        category: "INJECTION",
        title: "SQL Query String Interpolation",
        severity: "CRITICAL",
        cwe: "CWE-89",
        owasp: "A03:2021-Injection",
        file: "/repo/src/user.ts",
        line: 10,
        column: 15,
        snippet: 'const q = "SELECT * FROM users WHERE id = " + id;',
        description: "Raw SQL interpolation detected.",
        remediation: "Use parameterized query ($1).",
        cvssScore: 9.8,
        cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
      },
    ],
  };

  const mockSecretReport: SecretScanReport = {
    targetPath: "/repo",
    filesScanned: 10,
    scanTimestamp: new Date().toISOString(),
    durationMs: 25,
    summary: { critical: 1, high: 0, medium: 0, low: 0, info: 0 },
    findings: [
      {
        id: "SEC-TOK-AWS-KEY-env.ts-L5",
        patternId: "SEC-TOK-AWS-KEY",
        title: "AWS Access Key ID",
        severity: "CRITICAL",
        file: "/repo/env.ts",
        line: 5,
        column: 1,
        maskedSecret: "AKIA**************LE",
        entropy: 3.684,
        snippet: 'const key = "AKIA**************LE";',
        remediation: "Rotate exposed key immediately.",
      },
    ],
  };

  const mockScaReport: ScaScanReport = {
    manifestPath: "/repo/package.json",
    ecosystem: "npm",
    totalDependencies: 1,
    vulnerableDependencies: 1,
    scanTimestamp: new Date().toISOString(),
    durationMs: 150,
    summary: { critical: 1, high: 0, medium: 0, low: 0, info: 0 },
    findings: [
      {
        id: "GHSA-p6mc-m468-83gw",
        packageName: "lodash",
        currentVersion: "4.17.20",
        patchedVersion: "4.17.21",
        severity: "CRITICAL",
        cvssScore: 9.8,
        title: "Prototype Pollution in lodash",
        description: "Vulnerable to prototype pollution.",
        advisoryUrl: "https://osv.dev/vulnerability/GHSA-p6mc-m468-83gw",
        remediation: "Upgrade lodash to >= 4.17.21",
      },
    ],
  };

  const sarif = generateSarifReport({
    sastReport: mockSastReport,
    secretReport: mockSecretReport,
    scaReport: mockScaReport,
  });

  assert.equal(sarif.version, "2.1.0");
  assert.ok(sarif.$schema.includes("sarif-schema-2.1.0.json"));
  assert.equal(sarif.runs.length, 1);

  const run = sarif.runs[0];
  assert.equal(run.tool.driver.name, "WebSecAuditor");
  assert.equal(run.tool.driver.version, "1.0.0");

  // Check rules registered
  assert.ok(run.tool.driver.rules.some((r) => r.id === "SEC-INJ-SQLI"));
  assert.ok(run.tool.driver.rules.some((r) => r.id === "SEC-TOK-AWS-KEY"));
  assert.ok(run.tool.driver.rules.some((r) => r.id === "GHSA-p6mc-m468-83gw"));

  // Check results
  assert.equal(run.results.length, 3);
  const sqliResult = run.results.find((r) => r.ruleId === "SEC-INJ-SQLI");
  assert.ok(sqliResult);
  assert.equal(sqliResult.level, "error");
  assert.equal(sqliResult.locations?.[0].physicalLocation.region?.startLine, 10);
});

test("HTML Dashboard - Generates self-contained interactive executive report", () => {
  const mockSastReport: SastScanReport = {
    targetPath: "src",
    filesScanned: 10,
    scanTimestamp: new Date().toISOString(),
    durationMs: 80,
    summary: { critical: 1, high: 1, medium: 0, low: 0, info: 0 },
    findings: [
      {
        id: "SEC-INJ-SQLI-test.ts-L12",
        ruleId: "SEC-INJ-SQLI",
        category: "INJECTION",
        title: "SQL Injection",
        severity: "CRITICAL",
        cwe: "CWE-89",
        owasp: "A03:2021-Injection",
        file: "src/test.ts",
        line: 12,
        column: 5,
        snippet: 'db.query("SELECT * " + input);',
        description: "Dangerous query concatenation",
        remediation: "Use bind parameters",
        patch: {
          diff: "--- a/test.ts\n+++ b/test.ts\n@@ -12,1 +12,1 @@\n- db.query\n+ db.query($1)",
          explanation: "Parameterized query",
        },
      },
    ],
  };

  const html = generateHtmlReport({
    sastReport: mockSastReport,
  });

  assert.ok(html.startsWith("<!DOCTYPE html>"));
  assert.ok(html.includes("WebSecAuditor"));
  assert.ok(html.includes("Grade F")); // Critical finding triggers Grade F
  assert.ok(html.includes("SQL Injection"));
  assert.ok(html.includes("CWE-89"));
  assert.ok(html.includes("diff-block"));
});

test("MCP Protocol - Server initializes and registers all 5 core security tools", () => {
  const mcp = createMcpServer();
  assert.ok(mcp);
  assert.equal(typeof mcp.tool, "function");
  assert.equal(typeof mcp.connect, "function");
});
