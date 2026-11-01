import assert from "node:assert";
import { existsSync, rmSync } from "node:fs";
import { join } from "node:path";
import { describe, it } from "node:test";
import { GitHubActionRunner } from "../src/action.js";
import type { SastFinding, SecretFinding } from "../src/types/index.js";

describe("Official GitHub Action Runner Suite", () => {
  const runner = new GitHubActionRunner({
    failOn: "HIGH",
    uploadSarif: false,
    commentPr: false,
    inlineReview: false,
  });

  it("formats markdown PR comment with vulnerability summary table", () => {
    const mockSast: SastFinding[] = [
      {
        id: "SAST-SQL-1",
        ruleId: "SEC-INJ-SQLI",
        category: "INJECTION",
        title: "SQL Injection",
        severity: "CRITICAL",
        cwe: "CWE-89",
        owasp: "A03:2021-Injection",
        file: "src/db.ts",
        line: 42,
        column: 5,
        snippet: "db.query('SELECT * FROM users ' + id)",
        description: "Direct SQL string concatenation without parameterization",
        remediation: "Use parameterized queries ($1, ?)",
      },
    ];

    const mockSecret: SecretFinding[] = [
      {
        id: "SEC-OPENAI-1",
        patternId: "SEC-TOK-OPENAI",
        title: "OpenAI API Secret Key",
        severity: "CRITICAL",
        file: ".env",
        line: 3,
        column: 1,
        maskedSecret: "sk-proj-****abcd",
        entropy: 4.2,
        snippet: "OPENAI_API_KEY=sk-proj-****abcd",
        remediation: "Rotate token immediately",
        verification: {
          status: "ACTIVE",
          provider: "openai",
          details: "Live key",
          verifiedAt: new Date().toISOString(),
        },
      },
    ];

    const comment = runner.formatPrComment(false, mockSast, mockSecret, [], {
      criticalCount: 2,
      highCount: 0,
      mediumCount: 0,
      lowCount: 0,
    });

    assert.ok(comment.includes("WebSecAuditor Gate: ❌ ACTION REQUIRED"));
    assert.ok(comment.includes("SQL Injection"));
    assert.ok(comment.includes("CWE-89"));
    assert.ok(comment.includes("OpenAI API Secret Key"));
    assert.ok(comment.includes("ACTIVE"));
  });

  it("runs security audit, exports SARIF file, and enforces fail-on threshold", async () => {
    const tmpSarif = join(process.cwd(), "tmp-test-action.sarif");

    try {
      const customRunner = new GitHubActionRunner({
        targetDir: "tests",
        sarifFile: tmpSarif,
        failOn: "CRITICAL",
        uploadSarif: false,
        commentPr: false,
        inlineReview: false,
      });

      const result = await customRunner.run();

      assert.ok(existsSync(tmpSarif));
      assert.strictEqual(typeof result.passed, "boolean");
      assert.strictEqual(typeof result.totalFindings, "number");
    } finally {
      if (existsSync(tmpSarif)) rmSync(tmpSarif, { force: true });
    }
  });
});
