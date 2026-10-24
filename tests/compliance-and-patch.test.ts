import assert from "node:assert/strict";
import test from "node:test";
import {
  PatchEngine,
  SastScanner,
  calculateCvssV31,
  generateRemediation,
  generateUnifiedDiff,
  getComplianceMapping,
} from "../src/index.js";

test("CVSS v3.1 - Computes standard reference base scores and vectors", () => {
  // 1. Critical SQLi vector: AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
  const sqliResult = calculateCvssV31({
    attackVector: "NETWORK",
    attackComplexity: "LOW",
    privilegesRequired: "NONE",
    userInteraction: "NONE",
    scope: "UNCHANGED",
    confidentiality: "HIGH",
    integrity: "HIGH",
    availability: "HIGH",
  });
  assert.equal(sqliResult.baseScore, 9.8);
  assert.equal(sqliResult.severity, "CRITICAL");
  assert.equal(sqliResult.vectorString, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  // 2. Critical RCE / Command Injection with Changed Scope: S:C
  const rceResult = calculateCvssV31({
    attackVector: "NETWORK",
    attackComplexity: "LOW",
    privilegesRequired: "NONE",
    userInteraction: "NONE",
    scope: "CHANGED",
    confidentiality: "HIGH",
    integrity: "HIGH",
    availability: "HIGH",
  });
  assert.equal(rceResult.baseScore, 10.0);
  assert.equal(rceResult.severity, "CRITICAL");

  // 3. Medium DOM XSS vector: AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N
  const xssResult = calculateCvssV31({
    attackVector: "NETWORK",
    attackComplexity: "LOW",
    privilegesRequired: "NONE",
    userInteraction: "REQUIRED",
    scope: "CHANGED",
    confidentiality: "LOW",
    integrity: "LOW",
    availability: "NONE",
  });
  assert.equal(xssResult.baseScore, 6.1);
  assert.equal(xssResult.severity, "MEDIUM");

  // 4. High Path Traversal: AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N
  const pathResult = calculateCvssV31({
    attackVector: "NETWORK",
    attackComplexity: "LOW",
    privilegesRequired: "NONE",
    userInteraction: "NONE",
    scope: "UNCHANGED",
    confidentiality: "HIGH",
    integrity: "NONE",
    availability: "NONE",
  });
  assert.equal(pathResult.baseScore, 7.5);
  assert.equal(pathResult.severity, "HIGH");

  // 5. Zero Impact: All None
  const zeroResult = calculateCvssV31({
    attackVector: "NETWORK",
    attackComplexity: "LOW",
    privilegesRequired: "NONE",
    userInteraction: "NONE",
    scope: "UNCHANGED",
    confidentiality: "NONE",
    integrity: "NONE",
    availability: "NONE",
  });
  assert.equal(zeroResult.baseScore, 0.0);
  assert.equal(zeroResult.severity, "INFO");
});

test("Compliance - Maps findings to OWASP, PCI-DSS v4.0, SOC 2, and CWE Top 25", () => {
  // SQLi
  const sqliComp = getComplianceMapping("CWE-89");
  assert.ok(sqliComp);
  assert.equal(sqliComp.cweTop25Rank, 3);
  assert.equal(sqliComp.owasp, "A03:2021-Injection");
  assert.ok(sqliComp.pciDssV4.some((r) => r.includes("6.2.4")));
  assert.ok(sqliComp.soc2.some((r) => r.includes("CC6.1")));

  // Command Injection
  const cmdComp = getComplianceMapping("SEC-INJ-CMD");
  assert.ok(cmdComp);
  assert.equal(cmdComp.cweTop25Rank, 5);

  // XSS
  const xssComp = getComplianceMapping("CWE-79");
  assert.ok(xssComp);
  assert.equal(xssComp.cweTop25Rank, 2);
  assert.ok(xssComp.pciDssV4.some((r) => r.includes("6.4.3")));

  // Path Traversal
  const pathComp = getComplianceMapping("SEC-INJ-PATH");
  assert.ok(pathComp);
  assert.equal(pathComp.cweTop25Rank, 8);

  // Hardcoded Credentials
  const secretComp = getComplianceMapping("SEC-TOK-AWS-KEY");
  assert.ok(secretComp);
  assert.equal(secretComp.cweTop25Rank, 18);
});

test("Auto-Patch - generateRemediation produces defensive code recipes", () => {
  // 1. SQL Injection -> Parameterized query
  const sqliSnippet = `const query = "SELECT * FROM users WHERE email = '" + req.body.email;`;
  const sqliPatch = generateRemediation(sqliSnippet, "SEC-INJ-SQLI");
  assert.ok(sqliPatch);
  assert.ok(sqliPatch.replacementText.includes("$1"));
  assert.ok(sqliPatch.replacementText.includes("[req.body.email]"));

  // 2. Command Injection -> child_process.execFile
  const cmdSnippet = `child_process.exec("ping " + req.query.host);`;
  const cmdPatch = generateRemediation(cmdSnippet, "SEC-INJ-CMD");
  assert.ok(cmdPatch);
  assert.ok(cmdPatch.replacementText.includes("execFile"));
  assert.ok(cmdPatch.replacementText.includes("[String(req.query.host)]"));

  // 3. Path Traversal -> path.resolve + path.basename
  const pathSnippet = `const filePath = "/data/" + req.query.filename;`;
  const pathPatch = generateRemediation(pathSnippet, "SEC-INJ-PATH");
  assert.ok(pathPatch);
  assert.ok(pathPatch.replacementText.includes("path.basename"));

  // 4. DOM XSS -> .textContent
  const xssSnippet = "element.innerHTML = userInput;";
  const xssPatch = generateRemediation(xssSnippet, "SEC-INJ-XSS");
  assert.ok(xssPatch);
  assert.ok(xssPatch.replacementText.includes(".textContent"));

  // 5. Insecure TLS -> rejectUnauthorized: true
  const tlsSnippet = "const agent = new https.Agent({ rejectUnauthorized: false });";
  const tlsPatch = generateRemediation(tlsSnippet, "SEC-CONF-DISABLE-TLS");
  assert.ok(tlsPatch);
  assert.ok(tlsPatch.replacementText.includes("rejectUnauthorized: true"));
});

test("Auto-Patch - PatchEngine generates valid unified git diffs", () => {
  const engine = new PatchEngine();
  const fileContent = `
import * as db from "./db.js";

export async function getUser(req) {
  const query = "SELECT * FROM users WHERE email = '" + req.body.email;
  return db.query(query);
}
`;

  const recipe = engine.generatePatch("src/routes/user.ts", fileContent, 5, "SEC-INJ-SQLI");

  assert.ok(recipe);
  assert.equal(recipe.file, "src/routes/user.ts");
  assert.equal(recipe.line, 5);
  assert.ok(recipe.diff.includes("--- a/src/routes/user.ts"));
  assert.ok(recipe.diff.includes("+++ b/src/routes/user.ts"));
  assert.ok(
    recipe.diff.includes(
      '-  const query = "SELECT * FROM users WHERE email = \'" + req.body.email;',
    ),
  );
  assert.ok(
    recipe.diff.includes(
      '+  const query = "SELECT * FROM users WHERE email = $1", [req.body.email]',
    ),
  );
});

test("SAST - SastScanner automatically attaches CVSS, Compliance, and Patch", () => {
  const scanner = new SastScanner();
  const code = `
    const query = "SELECT * FROM users WHERE email = '" + req.body.email;
    db.query(query);
  `;

  const findings = scanner.scanContent(code, "controllers/auth.ts");
  const sqli = findings.find((f) => f.ruleId === "SEC-INJ-SQLI");

  assert.ok(sqli);
  assert.equal(sqli.cvssScore, 9.8);
  assert.ok(sqli.cvssVector?.includes("CVSS:3.1"));
  assert.equal(sqli.compliance?.cweTop25Rank, 3);
  assert.ok((sqli.compliance?.pciDss?.length ?? 0) > 0);
  assert.ok((sqli.compliance?.soc2?.length ?? 0) > 0);
  assert.ok(sqli.patch?.diff.includes("--- a/controllers/auth.ts"));
});
