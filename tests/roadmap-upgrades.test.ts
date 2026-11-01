import * as assert from "node:assert/strict";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import test from "node:test";
import {
  DastScanner,
  PatchEngine,
  SastScanner,
  ScaScanner,
  computeConfidenceScore,
  detectAndParseManifest,
  isTestFilePath,
  parseGoSum,
  parsePoetryLock,
  parseRequirementsTxt,
  probeCorsReflection,
  probeCsrfMutations,
  probeGraphqlIntrospection,
  runActiveProbes,
} from "../src/index.js";

// ─── 1. Expand AST SAST Detection Rules ───────────────────────

test("SAST - Detects Prototype Pollution in object merging and recursive key assignment", () => {
  const scanner = new SastScanner();
  const code = `
    function merge(target, source) {
      for (const key of Object.keys(source)) {
        target[key] = source[key];
      }
      return target;
    }
  `;
  const findings = scanner.scanContent(code, "utils/merge.ts");
  const protoFinding = findings.find((f) => f.ruleId === "SEC-INJ-PROTO-POLLUTION");
  assert.ok(protoFinding, "Expected SEC-INJ-PROTO-POLLUTION finding");
  assert.equal(protoFinding?.cwe, "CWE-1321");
  assert.equal(protoFinding?.severity, "HIGH");
  assert.ok(protoFinding?.patch, "Expected auto-patch recipe for prototype pollution");
});

test("SAST - Detects Insecure Deserialization (pickle, yaml, node-serialize)", () => {
  const scanner = new SastScanner();

  // Python pickle
  const pyCode = `
    import pickle
    data = pickle.loads(user_payload)
  `;
  const pyFindings = scanner.scanContent(pyCode, "server/handlers.py");
  assert.ok(pyFindings.some((f) => f.ruleId === "SEC-INJ-DESERIALIZATION"));

  // JS/TS unserialize
  const jsCode = `
    const serialize = require("node-serialize");
    const obj = serialize.unserialize(req.body.profile);
  `;
  const jsFindings = scanner.scanContent(jsCode, "routes/profile.js");
  const jsFinding = jsFindings.find((f) => f.ruleId === "SEC-INJ-DESERIALIZATION");
  assert.ok(jsFinding, "Expected SEC-INJ-DESERIALIZATION finding");
  assert.equal(jsFinding?.cwe, "CWE-502");
  assert.equal(jsFinding?.severity, "CRITICAL");
});

test("SAST - Detects NoSQL Query Injection ($where, $regex, unvalidated body)", () => {
  const scanner = new SastScanner();
  const code = `
    app.post("/users", async (req, res) => {
      const users = await db.collection("users").find(req.body);
      res.json(users);
    });
  `;
  const findings = scanner.scanContent(code, "routes/users.ts");
  const nosqlFinding = findings.find((f) => f.ruleId === "SEC-INJ-NOSQL");
  assert.ok(nosqlFinding, "Expected SEC-INJ-NOSQL finding");
  assert.equal(nosqlFinding?.cwe, "CWE-943");
  assert.equal(nosqlFinding?.severity, "HIGH");
});

test("SAST - Detects SSRF in axios and native fetch without IP/CIDR validation", () => {
  const scanner = new SastScanner();
  const code = `
    async function forwardWebhook(webhookUrl: string) {
      const res = await axios.post(webhookUrl);
      return res.data;
    }
  `;
  const findings = scanner.scanContent(code, "services/webhook.ts");
  const ssrfFinding = findings.find((f) => f.ruleId === "SEC-SSRF-AXIOS-FETCH");
  assert.ok(ssrfFinding, "Expected SEC-SSRF-AXIOS-FETCH finding");
  assert.equal(ssrfFinding?.cwe, "CWE-918");
  assert.equal(ssrfFinding?.severity, "HIGH");
});

// ─── 2. Multi-Ecosystem SCA Support ──────────────────────────

test("SCA - parseRequirementsTxt extracts Python dependencies", async () => {
  const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "sca-py-"));
  const reqPath = path.join(tmpDir, "requirements.txt");
  const content = `
# Core web dependencies
flask==2.0.1
requests>=2.25.1; python_version >= '3.7'
urllib3~=1.26.5
--extra-index-url https://pypi.org/simple
celery
`;
  await fs.writeFile(reqPath, content, "utf-8");

  const deps = await parseRequirementsTxt(reqPath);
  assert.equal(deps.length, 4);

  const flask = deps.find((d) => d.name === "flask");
  assert.ok(flask);
  assert.equal(flask?.version, "2.0.1");
  assert.equal(flask?.ecosystem, "PyPI");

  const reqs = deps.find((d) => d.name === "requests");
  assert.ok(reqs);
  assert.equal(reqs?.version, "2.25.1");
  assert.equal(reqs?.ecosystem, "PyPI");

  await fs.rm(tmpDir, { recursive: true, force: true });
});

test("SCA - parsePoetryLock extracts TOML dependencies", async () => {
  const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "sca-poetry-"));
  const lockPath = path.join(tmpDir, "poetry.lock");
  const content = `
[[package]]
name = "fastapi"
version = "0.78.0"
category = "main"

[[package]]
name = "pytest"
version = "7.1.2"
category = "dev"
`;
  await fs.writeFile(lockPath, content, "utf-8");

  // Default: exclude dev
  const prodDeps = await parsePoetryLock(lockPath, { includeDev: false });
  assert.equal(prodDeps.length, 1);
  assert.equal(prodDeps[0].name, "fastapi");
  assert.equal(prodDeps[0].version, "0.78.0");
  assert.equal(prodDeps[0].ecosystem, "PyPI");

  // With dev: include pytest
  const allDeps = await parsePoetryLock(lockPath, { includeDev: true });
  assert.equal(allDeps.length, 2);

  await fs.rm(tmpDir, { recursive: true, force: true });
});

test("SCA - parseGoSum extracts Go module dependencies", async () => {
  const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "sca-go-"));
  const goSumPath = path.join(tmpDir, "go.sum");
  const content = `
github.com/gin-gonic/gin v1.7.7 h1:xl/V8uicbkWbvNxpwmyphE2Vd9vB1mCLtw1ngzep1v0=
github.com/gin-gonic/gin v1.7.7/go.mod h1:iy8F57bFfhpSvU6fUihp3tVv0zS3Uv130o9eXk=
golang.org/x/crypto v0.0.0-20201221181555-eec23a3978ad h1:DN0cpUixA/wL05hS53yQ7kKsmx6A7YF3fJ00k2y=
`;
  await fs.writeFile(goSumPath, content, "utf-8");

  const deps = await parseGoSum(goSumPath);
  assert.equal(deps.length, 2);

  const gin = deps.find((d) => d.name === "github.com/gin-gonic/gin");
  assert.ok(gin);
  assert.equal(gin?.version, "1.7.7");
  assert.equal(gin?.ecosystem, "Go");

  await fs.rm(tmpDir, { recursive: true, force: true });
});

test("SCA - detectAndParseManifest auto-detects lockfile types", async () => {
  const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "sca-detect-"));
  const reqPath = path.join(tmpDir, "requirements.txt");
  await fs.writeFile(reqPath, "django==3.2.0\n", "utf-8");

  const result = await detectAndParseManifest(tmpDir);
  assert.equal(result.ecosystem, "PyPI");
  assert.equal(result.dependencies.length, 1);
  assert.equal(result.dependencies[0].name, "django");

  await fs.rm(tmpDir, { recursive: true, force: true });
});

test("SCA - ScaScanner scans Python manifest against mocked OSV endpoint", async () => {
  const mockFetch: typeof fetch = async (url, init) => {
    const body = JSON.parse(init?.body as string);
    assert.equal(body.queries[0].package.ecosystem, "PyPI");
    return new Response(
      JSON.stringify({
        results: [
          {
            vulns: [
              {
                id: "GHSA-pytest-vuln-01",
                summary: "Pytest remote code execution vulnerability",
                severity: [
                  { type: "CVSS_V3", score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H" },
                ],
                affected: [{ ranges: [{ events: [{ fixed: "7.2.0" }] }] }],
              },
            ],
          },
        ],
      }),
      { status: 200, headers: { "Content-Type": "application/json" } },
    );
  };

  const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "sca-scan-py-"));
  const reqPath = path.join(tmpDir, "requirements.txt");
  await fs.writeFile(reqPath, "pytest==7.1.0\n", "utf-8");

  const scanner = new ScaScanner({ customFetch: mockFetch });
  const report = await scanner.scanManifest(reqPath);

  assert.equal(report.ecosystem, "PyPI");
  assert.equal(report.findings.length, 1);
  assert.equal(report.findings[0].severity, "CRITICAL");
  assert.equal(report.findings[0].patchedVersion, "7.2.0");

  await fs.rm(tmpDir, { recursive: true, force: true });
});

// ─── 3. Active DAST Dynamic Probing ───────────────────────────

test("DAST - probeCorsReflection flags arbitrary reflected origin", async () => {
  const mockFetch: typeof fetch = async (url, init) => {
    return new Response(null, {
      status: 204,
      headers: {
        "Access-Control-Allow-Origin": "https://evil.com",
        "Access-Control-Allow-Credentials": "true",
      },
    });
  };

  const findings = await probeCorsReflection("https://api.target.com/data", {
    customFetch: mockFetch,
  });

  assert.equal(findings.length, 1);
  assert.equal(findings[0].id, "DAST-ACTIVE-CORS-REFLECT");
  assert.equal(findings[0].severity, "CRITICAL");
  assert.equal(findings[0].cwe, "CWE-942");
});

test("DAST - probeCsrfMutations flags missing anti-CSRF protection", async () => {
  const mockFetch: typeof fetch = async (url, init) => {
    return new Response(JSON.stringify({ ok: true }), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  };

  const findings = await probeCsrfMutations("https://api.target.com/profile/update", {
    customFetch: mockFetch,
  });

  assert.equal(findings.length, 1);
  assert.equal(findings[0].id, "DAST-ACTIVE-CSRF-MISSING");
  assert.equal(findings[0].severity, "MEDIUM");
});

test("DAST - probeGraphqlIntrospection flags exposed schema", async () => {
  const mockFetch: typeof fetch = async (url, init) => {
    return new Response(
      JSON.stringify({
        data: {
          __schema: {
            types: [{ name: "User" }, { name: "Query" }, { name: "Mutation" }],
          },
        },
      }),
      { status: 200, headers: { "Content-Type": "application/json" } },
    );
  };

  const findings = await probeGraphqlIntrospection("https://api.target.com/graphql", {
    customFetch: mockFetch,
  });

  assert.equal(findings.length, 1);
  assert.equal(findings[0].id, "DAST-ACTIVE-GRAPHQL-INTROSPECTION");
  assert.equal(findings[0].severity, "MEDIUM");
});

// ─── 4. Dry-Run Test Verification for Auto-Patches ────────────

test("Patch - verifyPatchWithTests executes subprocess test verification and reverts cleanly", async () => {
  const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "patch-verify-"));
  const testFile = path.join(tmpDir, "vulnerable.ts");
  const originalCode = `const q = "SELECT * FROM users WHERE id = " + req.query.id;`;
  await fs.writeFile(testFile, originalCode, "utf-8");

  const patchEngine = new PatchEngine();
  const recipe = patchEngine.generatePatch(testFile, originalCode, 1, "SEC-INJ-SQLI");
  assert.ok(recipe, "Expected recipe to be generated");

  // Run dry-run verification with a command that passes (node -e "process.exit(0)")
  const verifyResult = await patchEngine.verifyPatchWithTests(recipe, {
    repoDir: tmpDir,
    testCommand: `node -e "process.exit(0)"`,
  });

  assert.equal(verifyResult.passed, true);
  assert.equal(verifyResult.exitCode, 0);
  assert.equal(verifyResult.revertedCleanly, true);

  // Verify the file was restored to its exact original state
  const restoredContent = await fs.readFile(testFile, "utf-8");
  assert.equal(restoredContent, originalCode);

  // Test failure case (node -e "process.exit(1)")
  const failResult = await patchEngine.verifyPatchWithTests(recipe, {
    repoDir: tmpDir,
    testCommand: `node -e "process.exit(1)"`,
  });

  assert.equal(failResult.passed, false);
  assert.equal(failResult.exitCode, 1);
  assert.equal(failResult.revertedCleanly, true);

  // File must still remain in its original state
  const contentAfterFail = await fs.readFile(testFile, "utf-8");
  assert.equal(contentAfterFail, originalCode);

  await fs.rm(tmpDir, { recursive: true, force: true });
});

// ─── 5. AI-Assisted False-Positive Scoring ────────────────────

test("SAST - False-positive scoring classifies test files and discounts confidence", () => {
  assert.equal(isTestFilePath("tests/auth.test.ts"), true);
  assert.equal(isTestFilePath("src/__tests__/scanner.spec.js"), true);
  assert.equal(isTestFilePath("test_api.py"), true);
  assert.equal(isTestFilePath("src/controllers/auth.ts"), false);

  const testMeta = computeConfidenceScore(
    "SEC-INJ-SQLI",
    "tests/unit/db.test.ts",
    "query + req.id",
  );
  assert.equal(testMeta.isTestFile, true);
  assert.equal(testMeta.confidence, "LOW");
  assert.ok(testMeta.confidenceScore <= 0.4);

  const prodMeta = computeConfidenceScore("SEC-INJ-SQLI", "src/db.ts", "query + req.query.id");
  assert.equal(prodMeta.isTestFile, false);
  assert.equal(prodMeta.confidence, "HIGH");
  assert.ok(prodMeta.confidenceScore >= 0.85);
});

test("SAST - ignoreTestFiles and minConfidence filter out test findings", () => {
  const scanner = new SastScanner();
  const vulnerableCode = `
    const userQuery = "SELECT * FROM users WHERE name = '" + req.query.name + "'";
  `;

  // Default scan of test file: finding present with LOW confidence
  const defaultFindings = scanner.scanContent(vulnerableCode, "tests/unit/user.test.ts");
  assert.equal(defaultFindings.length, 1);
  assert.equal(defaultFindings[0].isTestFile, true);
  assert.equal(defaultFindings[0].confidence, "LOW");

  // With ignoreTestFiles: true -> findings stripped
  const ignoredFindings = scanner.scanContent(vulnerableCode, "tests/unit/user.test.ts", {
    ignoreTestFiles: true,
  });
  assert.equal(ignoredFindings.length, 0);

  // With minConfidence: "HIGH" -> low confidence findings filtered out
  const highOnlyFindings = scanner.scanContent(vulnerableCode, "tests/unit/user.test.ts", {
    minConfidence: "HIGH",
  });
  assert.equal(highOnlyFindings.length, 0);

  // Production file passes through minConfidence: "HIGH"
  const prodFindings = scanner.scanContent(vulnerableCode, "src/routes/user.ts", {
    minConfidence: "HIGH",
  });
  assert.equal(prodFindings.length, 1);
  assert.equal(prodFindings[0].confidence, "HIGH");
});
