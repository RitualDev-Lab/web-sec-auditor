import * as assert from "node:assert/strict";
import * as crypto from "node:crypto";
import { after, before, describe, it } from "node:test";
import {
  BotServer,
  GitHubClient,
  type GitHubRepositoryRef,
  PrDiffScanner,
  PrPatcher,
  isLineInDiff,
  parseUnifiedDiff,
  verifyWebhookSignature,
} from "../src/bot/index.js";
import type { SastFinding, SecretFinding } from "../src/types/index.js";

const SAMPLE_DIFF = `diff --git a/src/user-controller.ts b/src/user-controller.ts
index 1111111..2222222 100644
--- a/src/user-controller.ts
+++ b/src/user-controller.ts
@@ -10,4 +10,6 @@ export function getUser(req: any) {
   const userId = req.query.id;
-  const legacy = "SELECT * FROM users WHERE active = 1";
+  const query = "SELECT * FROM users WHERE id = " + userId;
+  const dbUri = "postgres://admin:SuperSecretPass123@internal.db:5432/app";
   return execute(query);
 }
diff --git a/src/safe-util.ts b/src/safe-util.ts
new file mode 100644
--- /dev/null
+++ b/src/safe-util.ts
@@ -0,0 +1,3 @@
+export function add(a: number, b: number) {
+  return a + b;
+}
`;

const SAMPLE_USER_CONTROLLER = `import { execute } from "./db.js";

// Legacy context line 3
// Legacy context line 4
// Legacy context line 5
// Legacy context line 6
// Legacy context line 7
// Legacy context line 8
export function getUser(req: any) {
  const userId = req.query.id;
  const query = "SELECT * FROM users WHERE id = " + userId;
  const dbUri = "postgres://admin:SuperSecretPass123@internal.db:5432/app";
  return execute(query);
}
`;

describe("GitHub Bot - Cryptographic Webhook Security", () => {
  const secret = "test_webhook_super_secret_42";
  const body = JSON.stringify({ action: "opened", number: 10 });

  it("Accepts valid HMAC-SHA256 signature", () => {
    const hmac = crypto.createHmac("sha256", secret);
    hmac.update(body);
    const signature = `sha256=${hmac.digest("hex")}`;

    const isValid = verifyWebhookSignature(body, signature, secret);
    assert.strictEqual(isValid, true);
  });

  it("Rejects tampered signature or modified payload", () => {
    const hmac = crypto.createHmac("sha256", secret);
    hmac.update(body);
    const signature = `sha256=${hmac.digest("hex")}`;

    const isTampered = verifyWebhookSignature(`${body}tampered`, signature, secret);
    assert.strictEqual(isTampered, false);

    const isWrongSig = verifyWebhookSignature(
      body,
      "sha256=0000000000000000000000000000000000000000000000000000000000000000",
      secret,
    );
    assert.strictEqual(isWrongSig, false);
  });

  it("Rejects missing signature header or secret", () => {
    assert.strictEqual(verifyWebhookSignature(body, undefined, secret), false);
    assert.strictEqual(verifyWebhookSignature(body, "sha256=123", ""), false);
  });
});

describe("GitHub Bot - Unified Diff Parser", () => {
  it("Parses multi-file git diff and tracks added lines accurately", () => {
    const files = parseUnifiedDiff(SAMPLE_DIFF);
    assert.strictEqual(files.length, 2);

    const userController = files.find((f) => f.newPath === "src/user-controller.ts");
    assert.ok(userController);
    assert.strictEqual(userController.status, "modified");

    // In hunk @@ -10,4 +10,6 @@
    // line 10: context '  const userId = req.query.id;' (line 10)
    // line -11 deleted
    // line +11: '  const query = "SELECT * FROM users WHERE id = " + userId;'
    // line +12: '  const apiKey = ...'
    assert.ok(userController.addedLines.includes(11));
    assert.ok(userController.addedLines.includes(12));

    const safeUtil = files.find((f) => f.newPath === "src/safe-util.ts");
    assert.ok(safeUtil);
    assert.strictEqual(safeUtil.status, "added");
    assert.strictEqual(safeUtil.addedLines.length, 3);
  });

  it("isLineInDiff detects modified lines and ignores unmodified lines", () => {
    const files = parseUnifiedDiff(SAMPLE_DIFF);

    assert.strictEqual(isLineInDiff(files, "src/user-controller.ts", 11), true);
    assert.strictEqual(isLineInDiff(files, "src/user-controller.ts", 12), true);
    // Line 1 is an untouched import line
    assert.strictEqual(isLineInDiff(files, "src/user-controller.ts", 1), false);
  });
});

describe("GitHub Bot - Diff-Aware PR Scanner", () => {
  it("Audits only lines in diff and attaches CVSS and 1-Click patch recipes", async () => {
    const scanner = new PrDiffScanner();
    const files = [
      {
        path: "src/user-controller.ts",
        content: SAMPLE_USER_CONTROLLER,
      },
    ];

    const summary = await scanner.scanDiff(files, SAMPLE_DIFF, {
      owner: "RitualDev-Lab",
      repo: "test-repo",
      prNumber: 42,
      headSha: "abc1234",
      failOnSeverity: "HIGH",
    });

    assert.strictEqual(summary.prNumber, 42);
    assert.strictEqual(summary.filesScanned, 1);
    assert.ok(summary.findings.length >= 2); // SQL Injection + Leaked Key

    // Verify findings are on lines 11 and 12
    const sqli = summary.findings.find(
      (f) => f.findingType === "SAST" && (f as SastFinding).line === 11,
    );
    assert.ok(sqli, "Should detect SQL injection on line 11");

    const secret = summary.findings.find(
      (f) => f.findingType === "SECRETS" && (f as SecretFinding).line === 12,
    );
    assert.ok(secret, "Should detect secret database URI on line 12");

    // Security gate should fail on HIGH/CRITICAL issues
    assert.strictEqual(summary.passedGate, false);

    // Annotations generation
    const annotations = scanner.generateAnnotations(summary);
    assert.ok(annotations.length >= 2);
    assert.strictEqual(annotations[0].annotation_level, "failure");

    // Markdown review comment generation
    const md = scanner.generateMarkdownReview(summary);
    assert.ok(md.includes("WebSecAuditor Pull Request Security Report"));
    assert.ok(md.includes("FAIL: Security Gate Broken"));
    assert.ok(md.includes("@web-sec-auditor fix"));
  });
});

describe("GitHub Bot - 1-Click Auto-Patch PR Generator", () => {
  it("Generates patched contents and unified diff without touching disk", async () => {
    const scanner = new PrDiffScanner();
    const patcher = new PrPatcher();

    const files = [
      {
        path: "src/user-controller.ts",
        content: SAMPLE_USER_CONTROLLER,
      },
    ];

    const summary = await scanner.scanDiff(files, SAMPLE_DIFF, {
      owner: "RitualDev-Lab",
      repo: "test-repo",
      prNumber: 42,
    });

    const { patchedFilesMap, combinedDiff, recipesApplied } = patcher.generatePatchedFiles(
      files,
      summary.findings,
    );

    assert.ok(recipesApplied >= 1, "Should apply at least 1 patch recipe");
    const patchedCode = patchedFilesMap.get("src/user-controller.ts");
    assert.ok(patchedCode);
    assert.ok(
      patchedCode.includes("$1") || patchedCode.includes("[userId]"),
      "Should parameterize the SQL query",
    );
    assert.ok(combinedDiff.includes("--- a/src/user-controller.ts"));
  });
});

describe("GitHub Bot - Webhook Server HTTP Lifecycle", () => {
  let server: BotServer;
  let port: number;
  const webhookSecret = "test_bot_secret_xyz";

  before(async () => {
    server = new BotServer({
      webhookSecret,
      autoPatchOnCritical: true,
      failOnSeverity: "HIGH",
    });
    port = await server.listen(0);
  });

  after(async () => {
    await server.close();
  });

  it("GET /health returns 200 and healthy metadata", async () => {
    const res = await fetch(`http://localhost:${port}/health`);
    assert.strictEqual(res.status, 200);
    const data = (await res.json()) as { status: string; service?: string };
    assert.strictEqual(data.status, "ok");
    assert.strictEqual(data.service, "web-sec-auditor-bot");
  });

  it("POST /webhook rejects requests with invalid or missing HMAC", async () => {
    const res = await fetch(`http://localhost:${port}/webhook`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ action: "opened" }),
    });
    assert.strictEqual(res.status, 401);
  });

  it("POST /webhook accepts requests with valid HMAC signature", async () => {
    const mockRepo: GitHubRepositoryRef = {
      id: 1,
      name: "demo-repo",
      full_name: "ritualdev/demo-repo",
      owner: { login: "ritualdev", id: 1 },
      private: false,
      html_url: "https://github.com/ritualdev/demo-repo",
      default_branch: "main",
    };

    const payload = JSON.stringify({
      action: "opened",
      repository: mockRepo,
      pull_request: {
        number: 1,
        title: "Test PR",
        state: "open",
        html_url: "https://github.com/ritualdev/demo-repo/pull/1",
        diff_url: "https://github.com/ritualdev/demo-repo/pull/1.diff",
        head: { ref: "feature", sha: "1111111", repo: mockRepo },
        base: { ref: "main", sha: "0000000", repo: mockRepo },
        user: { login: "dev" },
      },
    });

    const hmac = crypto.createHmac("sha256", webhookSecret);
    hmac.update(payload);
    const signature = `sha256=${hmac.digest("hex")}`;

    const res = await fetch(`http://localhost:${port}/webhook`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-GitHub-Event": "pull_request",
        "X-Hub-Signature-256": signature,
      },
      body: payload,
    });

    assert.strictEqual(res.status, 202);
    const data = (await res.json()) as { status: string };
    assert.strictEqual(data.status, "processing");
  });
});
