import { strict as assert } from "node:assert";
import { describe, it } from "node:test";
import { SignedRemediationEngine } from "../src/patch/remediation-engine.js";
import { generateSarifReport } from "../src/reporting/sarif.js";
import { WholeProgramCpgAnalyzer } from "../src/sast/cpg-analyzer.js";

describe("Phase 3 (WebSecAuditor): Whole-Program Code Property Graph (CPG) Analysis", () => {
  it("constructs CPG and tracks untrusted input to Prisma ORM injection sink", () => {
    const files = new Map<string, string>();

    files.set(
      "src/routes.ts",
      [
        "import { executeUserQuery } from './services/db.js';",
        "app.get('/users/:id', async (req, res) => {",
        "  const userId = req.params.id;",
        "  const user = await executeUserQuery(userId);",
        "  res.json(user);",
        "});",
      ].join("\n"),
    );

    files.set(
      "src/services/db.ts",
      [
        "import { prisma } from './prisma.js';",
        "export async function executeUserQuery(queryId: string) {",
        "  const query = `SELECT * FROM users WHERE id = '${queryId}'`;",
        "  return prisma.$queryRawUnsafe(query);",
        "}",
      ].join("\n"),
    );

    const analyzer = new WholeProgramCpgAnalyzer();
    const { graph, findings } = analyzer.analyzeProject(files);

    assert.ok(graph.nodes.size > 0);
    assert.ok(graph.edges.size > 0 || graph.edges.length > 0);

    const ormFinding = findings.find((f) => f.category === "ORM_INJECTION");
    assert.ok(ormFinding, "Expected ORM_INJECTION finding");
    assert.equal(ormFinding.severity, "CRITICAL");
    assert.equal(ormFinding.cwe, "CWE-89");
    assert.equal(ormFinding.owasp, "A03:2021-Injection");
    assert.ok(ormFinding.trace.length >= 2, "Trace must contain multiple steps");
    assert.equal(ormFinding.source.variable, "userId");
    assert.ok(ormFinding.sink.sinkType.includes("Prisma"));
  });

  it("tracks untrusted input through microservice RPC boundary (SSRF)", () => {
    const files = new Map<string, string>();
    files.set(
      "src/gateway.ts",
      [
        "app.get('/proxy', async (req, res) => {",
        "  const targetUrl = req.query.url;",
        "  const response = await axios.get(`http://internal-mesh.local/v1/data?ref=${targetUrl}`);",
        "  res.send(response.data);",
        "});",
      ].join("\n"),
    );

    const analyzer = new WholeProgramCpgAnalyzer();
    const { findings } = analyzer.analyzeProject(files);

    const ssrf = findings.find((f) => f.category === "MICROSERVICE_SSRF");
    assert.ok(ssrf, "Expected MICROSERVICE_SSRF finding");
    assert.equal(ssrf.cwe, "CWE-918");
    assert.equal(ssrf.severity, "CRITICAL");
  });

  it("does not report vulnerabilities when input is sanitized with Number() or validator", () => {
    const files = new Map<string, string>();
    files.set(
      "src/safe-routes.ts",
      [
        "app.get('/items/:id', async (req, res) => {",
        "  const rawId = req.params.id;",
        "  const safeId = Number(rawId);",
        "  const query = `SELECT * FROM items WHERE id = ${safeId}`;",
        "  return prisma.$queryRawUnsafe(query);",
        "});",
      ].join("\n"),
    );

    const analyzer = new WholeProgramCpgAnalyzer();
    const { findings } = analyzer.analyzeProject(files);

    const ormFinding = findings.find((f) => f.category === "ORM_INJECTION");
    assert.equal(ormFinding, undefined, "Sanitized input should not produce ORM_INJECTION finding");
  });
});

describe("Phase 3 (WebSecAuditor): Standardized SARIF 2.1.0 Artifacts with CodeFlows", () => {
  it("exports valid SARIF 2.1.0 with codeFlows and threadFlows for GitHub / GitLab", () => {
    const analyzer = new WholeProgramCpgAnalyzer();
    const files = new Map<string, string>();
    files.set(
      "src/api.ts",
      [
        "app.get('/order', async (req, res) => {",
        "  const orderId = req.query.id;",
        "  const sql = `SELECT * FROM orders WHERE id = ${orderId}`;",
        "  await prisma.$queryRawUnsafe(sql);",
        "});",
      ].join("\n"),
    );

    const { findings } = analyzer.analyzeProject(files);
    assert.ok(findings.length > 0);

    const sarif = generateSarifReport({ cpgFindings: findings });

    assert.equal(sarif.version, "2.1.0");
    assert.ok(sarif.runs.length > 0);
    const run = sarif.runs[0];
    assert.equal(run.tool.driver.name, "WebSecAuditor");

    const result = run.results.find((r) => r.ruleId.startsWith("CPG-"));
    assert.ok(result, "Expected CPG result in SARIF log");
    assert.equal(result.level, "error");
    assert.ok(result.codeFlows && result.codeFlows.length > 0);

    const codeFlow = result.codeFlows[0];
    assert.ok(codeFlow.threadFlows.length > 0);
    const threadFlow = codeFlow.threadFlows[0];
    assert.ok(threadFlow.locations.length >= 2);
    assert.equal(threadFlow.locations[0].importance, "essential");
    assert.ok(threadFlow.locations[0].location.physicalLocation.region?.startLine);
  });
});

describe("Phase 3 (WebSecAuditor): Cryptographically Signed Remediation Engine", () => {
  it("creates a cryptographically signed patch and verifies signature & digest", () => {
    const engine = new SignedRemediationEngine();
    const originalCode = "const result = await prisma.$queryRawUnsafe(query);";
    const patchedCode =
      "const result = await prisma.$queryRaw`SELECT * FROM users WHERE id = ${userId}`;";

    const signedPatch = engine.createSignedPatch({
      filePath: "src/services/db.ts",
      lineNumber: 42,
      originalCode,
      patchedCode,
      ruleId: "CPG-ORM_INJECTION",
      explanation:
        "Replaced raw unsafe SQL string concatenation with safe parameterized Prisma template tag.",
    });

    assert.ok(signedPatch.signature.length > 0);
    assert.ok(signedPatch.digest.length > 0);
    assert.ok(
      signedPatch.rawPatchWithSignature.includes("RITUALDEV CRYPTOGRAPHICALLY SIGNED REMEDIATION"),
    );
    assert.ok(signedPatch.rawPatchWithSignature.includes(signedPatch.digest));

    // Verify valid patch
    const verification = engine.verifySignedPatch(signedPatch.rawPatchWithSignature);
    assert.equal(verification.valid, true);
    assert.equal(verification.patchMetadata?.["rule-id"], "CPG-ORM_INJECTION");
  });

  it("rejects tampered signed patches when content or metadata is altered", () => {
    const engine = new SignedRemediationEngine();
    const signedPatch = engine.createSignedPatch({
      filePath: "src/services/db.ts",
      lineNumber: 42,
      originalCode: "executeUnsafe(input);",
      patchedCode: "executeSafe(input);",
      ruleId: "CPG-COMMAND_INJECTION",
      explanation: "Remediate command injection",
    });

    // Tamper with the diff content
    const tamperedPatch = signedPatch.rawPatchWithSignature.replace(
      "executeSafe",
      "maliciousBackdoor",
    );
    const verification = engine.verifySignedPatch(tamperedPatch);

    assert.equal(verification.valid, false);
    assert.ok(verification.reason?.includes("tamper") || verification.reason?.includes("mismatch"));
  });

  it("generates structured signed PR payload with verified commit metadata", () => {
    const engine = new SignedRemediationEngine();
    const signedPatch = engine.createSignedPatch({
      filePath: "src/services/db.ts",
      lineNumber: 10,
      originalCode: "res.send(req.query.x);",
      patchedCode: "res.json({ safe: req.query.x });",
      ruleId: "CPG-API_RESPONSE_XSS",
      explanation: "Escape untrusted payload in API response",
    });

    const prPayload = engine.generateSignedPrPayload({
      patch: signedPatch,
      baseBranch: "main",
    });

    assert.ok(prPayload.branchName.startsWith("ritualdev-remediation/api_response_xss-"));
    assert.ok(prPayload.body.includes("Verified Cryptographically Signed"));
    assert.ok(prPayload.commitMessage.includes("Signed-off-by: RitualDev Security Bot"));
    assert.ok(prPayload.commitMessage.includes("X-RitualDev-Signature:"));
  });
});
