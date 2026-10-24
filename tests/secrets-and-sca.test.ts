import assert from "node:assert/strict";
import test from "node:test";
import {
  ScaScanner,
  SecretHunter,
  calculateShannonEntropy,
  extractPatchedVersion,
  maskSecret,
  normalizeVersion,
  parseCvssSeverity,
  parsePackageJson,
} from "../src/index.js";

test("Secrets - calculateShannonEntropy correctly quantifies randomness", () => {
  // Constant string has 0 entropy
  assert.equal(calculateShannonEntropy("aaaaaa"), 0);

  // English word has low entropy
  const lowEntropy = calculateShannonEntropy("password");
  assert.ok(lowEntropy < 3.2);

  // Random base64 token has high entropy (> 4.0)
  const highEntropy = calculateShannonEntropy("4eC39HqLyjWDarjtT1zdp7dc");
  assert.ok(highEntropy > 4.0);
});

test("Secrets - maskSecret safely redacts plaintext tokens", () => {
  const awsKey = `AKIA${"IOSFODNN7EXAMPLE"}`;
  const masked = maskSecret(awsKey, 4, 2);
  assert.equal(masked.startsWith("AKIA"), true);
  assert.equal(masked.endsWith("LE"), true);
  assert.ok(masked.includes("**************"));
  assert.equal(masked.length, awsKey.length);

  // Short secret
  assert.equal(maskSecret("short", 4, 2), "*****");
});

test("Secrets - SecretHunter detects cloud, AI, payment, and VCS tokens", () => {
  const hunter = new SecretHunter();

  // Test values concatenated to prevent false alarms on VCS commit scanners
  const awsKey = ["AKIA", "IOSFODNN7EXAMPLE"].join("");
  const gcpKey = ["AIza", "SyD-1234567890abcdefghijklmnopqrst"].join("");
  const openAiKey = ["sk-proj", "abc12345def67890ghij12345klmn67890opqr"].join("-");
  const claudeKey = ["sk-ant-api03", "abcdefghijklmnopqrstuvwxyz1234567890"].join("-");
  const stripeKey = ["sk", "live", "51ABCDefgh1234567890IJKLMNOP"].join("_");
  const githubPat = ["ghp", "1234567890abcdefghijklmnopqrstuvwxyz"].join("_");
  const slackUrl = [
    "https:",
    "",
    "hooks.slack.com",
    "services",
    "T00000000",
    "B00000000",
    "XXXXXXXXXXXXXXXXXXXXXXXX",
  ].join("/");
  const dbUrl = "postgres://dbuser:MySuperSecretPass123@prod-db.internal:5432/main";
  const rsaKey = "-----BEGIN RSA PRIVATE KEY-----";

  const code = [
    `const AWS_KEY = "${awsKey}";`,
    `const GCP_KEY = "${gcpKey}";`,
    `const OPENAI_KEY = "${openAiKey}";`,
    `const ANTHROPIC_KEY = "${claudeKey}";`,
    `const STRIPE_SECRET = "${stripeKey}";`,
    `const GITHUB_PAT = "${githubPat}";`,
    `const SLACK_HOOK = "${slackUrl}";`,
    `const DB_URL = "${dbUrl}";`,
    `const RSA_KEY = "${rsaKey}";`,
  ].join("\n");

  const findings = hunter.scanContent(code, "config.ts");

  // Verify pattern IDs
  assert.ok(findings.some((f) => f.patternId === "SEC-TOK-AWS-KEY"));
  assert.ok(findings.some((f) => f.patternId === "SEC-TOK-GCP-API"));
  assert.ok(findings.some((f) => f.patternId === "SEC-TOK-OPENAI"));
  assert.ok(findings.some((f) => f.patternId === "SEC-TOK-ANTHROPIC"));
  assert.ok(findings.some((f) => f.patternId === "SEC-TOK-STRIPE"));
  assert.ok(findings.some((f) => f.patternId === "SEC-TOK-GITHUB"));
  assert.ok(findings.some((f) => f.patternId === "SEC-TOK-SLACK"));
  assert.ok(findings.some((f) => f.patternId === "SEC-TOK-DB-URI"));
  assert.ok(findings.some((f) => f.patternId === "SEC-TOK-PRIVATE-KEY"));

  // Verify that secrets in snippets and maskedSecret are redacted
  const awsFinding = findings.find((f) => f.patternId === "SEC-TOK-AWS-KEY");
  assert.ok(awsFinding);
  assert.ok(!awsFinding.maskedSecret.includes("IOSFODNN7EXAMP"));
  assert.ok(!awsFinding.snippet.includes(awsKey));

  const dbFinding = findings.find((f) => f.patternId === "SEC-TOK-DB-URI");
  assert.ok(dbFinding);
  assert.ok(!dbFinding.snippet.includes("MySuperSecretPass123"));
});

test("Secrets - SecretHunter detects generic high-entropy secret assignments", () => {
  const hunter = new SecretHunter();

  const code = `
    const jwtSecret = "dGhpcy1pcy1hLXZlcnktc2VjdXJlLWhpZ2gtZW50cm9weS1zZWNyZXQ=";
  `;

  const findings = hunter.scanContent(code, "auth.ts");
  assert.ok(findings.some((f) => f.patternId === "SEC-TOK-GENERIC-ENTROPY"));
});

test("Secrets - scanGitHistory executes without throwing on git repositories", async () => {
  const hunter = new SecretHunter();
  const report = await hunter.scanGitHistory(".", { maxCommits: 5 });

  assert.equal(typeof report.commitsScanned, "number");
  assert.ok((report.commitsScanned ?? 0) >= 0);
  assert.ok(Array.isArray(report.findings));
});

test("SCA - normalizeVersion strips semver prefix operators", () => {
  assert.equal(normalizeVersion("^4.17.21"), "4.17.21");
  assert.equal(normalizeVersion("~1.2.3"), "1.2.3");
  assert.equal(normalizeVersion(">= 2.0.0"), "2.0.0");
  assert.equal(normalizeVersion("v18.0.0"), "18.0.0");
  assert.equal(normalizeVersion("1.0.0 || 2.0.0"), "1.0.0");
});

test("SCA - parsePackageJson extracts dependencies and devDependencies", async () => {
  const deps = await parsePackageJson("package.json", { includeDev: true });
  assert.ok(deps.length > 0);

  // Check zod is present as dependency
  const zodDep = deps.find((d) => d.name === "zod");
  assert.ok(zodDep);
  assert.equal(zodDep.isDev, false);
});

test("SCA - parseCvssSeverity and extractPatchedVersion parse OSV metadata", () => {
  const mockVuln = {
    id: "GHSA-p6mc-m468-83gw",
    summary: "Prototype Pollution in lodash",
    severity: [
      {
        type: "CVSS_V3",
        score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
      },
    ],
    affected: [
      {
        ranges: [
          {
            type: "SEMVER",
            events: [{ introduced: "0" }, { fixed: "4.17.21" }],
          },
        ],
      },
    ],
  };

  const { severity, score } = parseCvssSeverity(mockVuln);
  assert.equal(severity, "HIGH");
  assert.equal(score, 7.5);

  const fixed = extractPatchedVersion(mockVuln);
  assert.equal(fixed, "4.17.21");
});

test("SCA - ScaScanner scans dependencies and returns structured advisory report", async () => {
  const mockFetch: typeof fetch = async () => {
    const mockOsvResponse = {
      results: [
        {
          vulns: [
            {
              id: "GHSA-p6mc-m468-83gw",
              summary: "Prototype Pollution in lodash",
              details: "Versions of lodash prior to 4.17.21 are vulnerable.",
              severity: [
                {
                  type: "CVSS_V3",
                  score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                },
              ],
              affected: [
                {
                  ranges: [
                    {
                      type: "SEMVER",
                      events: [{ introduced: "0" }, { fixed: "4.17.21" }],
                    },
                  ],
                },
              ],
            },
          ],
        },
      ],
    };

    return new Response(JSON.stringify(mockOsvResponse), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  };

  const scanner = new ScaScanner({ customFetch: mockFetch });
  const report = await scanner.scanManifest("package.json");

  assert.ok(report.totalDependencies > 0);
  assert.equal(report.findings.length, 1);
  assert.equal(report.findings[0].id, "GHSA-p6mc-m468-83gw");
  assert.equal(report.findings[0].severity, "CRITICAL");
  assert.equal(report.findings[0].patchedVersion, "4.17.21");
  assert.ok(report.findings[0].remediation.includes("Upgrade"));
});
