import assert from "node:assert";
import { describe, it } from "node:test";
import { InterFileTaintAnalyzer } from "../src/sast/taint-flow.js";

describe("Inter-File AST Taint Flow Analysis Suite", () => {
  const analyzer = new InterFileTaintAnalyzer();

  it("extracts HTTP input sources from route handlers", () => {
    const routeCode = `
      import express from "express";
      const app = express();

      app.get("/user/:id", (req, res) => {
        const userId = req.params.id;
        const { queryFilter } = req.query;
      });
    `;

    const sources = analyzer.extractTaintSources(routeCode, "src/routes/user.ts");
    assert.strictEqual(sources.length, 2);
    assert.ok(sources.some((s) => s.variable === "userId"));
    assert.ok(sources.some((s) => s.variable === "queryFilter"));
  });

  it("traces untrusted input from route handler to SQL query sink across modules", () => {
    const files = new Map<string, string>();

    // File A: Express Controller receiving user input
    files.set(
      "src/controllers/userController.ts",
      `
      import { findUserInDatabase } from "../services/userService.js";

      export async function handleGetUser(req: any, res: any) {
        const id = req.params.id;
        const user = await findUserInDatabase(id);
        res.json(user);
      }
    `.trim(),
    );

    // File B: Service module executing raw SQL query
    files.set(
      "src/services/userService.ts",
      `
      import { db } from "../db.js";

      export async function findUserInDatabase(userId: string) {
        return db.query("SELECT * FROM users WHERE id = " + userId);
      }
    `.trim(),
    );

    const findings = analyzer.analyzeProject(files);

    assert.strictEqual(findings.length, 1);
    const finding = findings[0];
    assert.strictEqual(finding.ruleId, "SAST-TAINT-SQL-INJECTION");
    assert.strictEqual(finding.cwe, "CWE-89");
    assert.strictEqual(finding.severity, "CRITICAL");
    assert.ok(finding.sourceFile.includes("userController.ts"));
    assert.ok(finding.sinkFile.includes("userService.ts"));
    assert.strictEqual(finding.taintTrace.length, 3);
    assert.strictEqual(finding.taintTrace[0].type, "SOURCE");
    assert.strictEqual(finding.taintTrace[1].type, "PROPAGATION");
    assert.strictEqual(finding.taintTrace[2].type, "SINK");
  });

  it("traces untrusted input to command injection sink across modules", () => {
    const files = new Map<string, string>();

    files.set(
      "src/routes/admin.ts",
      `
      import { runDiagnosticScript } from "../utils/system.js";

      app.post("/diagnostics", (req, res) => {
        const cmd = req.body.command;
        runDiagnosticScript(cmd);
      });
    `.trim(),
    );

    files.set(
      "src/utils/system.ts",
      `
      import { exec } from "child_process";

      export function runDiagnosticScript(targetCmd: string) {
        exec("sh -c " + targetCmd);
      }
    `.trim(),
    );

    const findings = analyzer.analyzeProject(files);

    assert.strictEqual(findings.length, 1);
    const finding = findings[0];
    assert.strictEqual(finding.ruleId, "SAST-TAINT-COMMAND-INJECTION");
    assert.strictEqual(finding.cwe, "CWE-78");
    assert.ok(finding.description.includes("targetCmd"));
  });

  it("does not flag clean code where parameters are not derived from sources", () => {
    const files = new Map<string, string>();

    files.set(
      "src/routes/safe.ts",
      `
      import { findUserInDatabase } from "../services/userService.js";

      export async function handleGetUser(req: any, res: any) {
        const safeStaticId = "static-constant-id";
        const user = await findUserInDatabase(safeStaticId);
        res.json(user);
      }
    `.trim(),
    );

    files.set(
      "src/services/userService.ts",
      `
      import { db } from "../db.js";

      export async function findUserInDatabase(userId: string) {
        return db.query("SELECT * FROM users WHERE id = " + userId);
      }
    `.trim(),
    );

    const findings = analyzer.analyzeProject(files);
    assert.strictEqual(findings.length, 0);
  });
});
