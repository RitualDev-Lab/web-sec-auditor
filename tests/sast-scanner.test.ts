import assert from "node:assert/strict";
import test from "node:test";
import { RuleRegistry, SastScanner, detectLanguage, findMatchesInContent } from "../src/index.js";

test("SAST - detectLanguage correctly identifies extensions", () => {
  assert.equal(detectLanguage("src/index.ts"), "typescript");
  assert.equal(detectLanguage("components/App.tsx"), "typescript");
  assert.equal(detectLanguage("server.js"), "javascript");
  assert.equal(detectLanguage("api.mjs"), "javascript");
  assert.equal(detectLanguage("main.py"), "python");
  assert.equal(detectLanguage("handler.go"), "go");
  assert.equal(detectLanguage("styles.css"), "unknown");
  assert.equal(detectLanguage("README.md"), "unknown");
});

test("SAST - findMatchesInContent extracts correct line numbers and snippets", () => {
  const code = `
const x = 1;
const y = eval(userInput);
const z = 3;
`;
  const matches = findMatchesInContent(code, /\beval\s*\(/);
  assert.equal(matches.length, 1);
  assert.equal(matches[0].line, 3);
  assert.equal(matches[0].snippet, "const y = eval(userInput);");
  assert.equal(matches[0].evidence, "eval(");
});

test("SAST - Injection Rules detect SQL, Command, Path Traversal, XSS, and Eval", () => {
  const scanner = new SastScanner();

  // 1. SQL Injection
  const sqlCode = `
    const query = "SELECT * FROM users WHERE email = '" + req.body.email + "'";
    await db.query(query);
  `;
  const sqlFindings = scanner.scanContent(sqlCode, "controllers/user.ts");
  assert.ok(sqlFindings.some((f) => f.ruleId === "SEC-INJ-SQLI"));
  assert.equal(sqlFindings.find((f) => f.ruleId === "SEC-INJ-SQLI")?.severity, "CRITICAL");

  // 2. Command Injection
  const cmdCode = `
    const child_process = require('child_process');
    child_process.exec("ping " + req.query.host);
  `;
  const cmdFindings = scanner.scanContent(cmdCode, "utils/ping.js");
  assert.ok(cmdFindings.some((f) => f.ruleId === "SEC-INJ-CMD"));
  assert.equal(cmdFindings.find((f) => f.ruleId === "SEC-INJ-CMD")?.severity, "CRITICAL");

  // 3. Path Traversal
  const pathCode = `
    const filePath = "/data/" + req.query.filename;
    fs.readFile(filePath, 'utf-8');
  `;
  const pathFindings = scanner.scanContent(pathCode, "routes/download.ts");
  assert.ok(pathFindings.some((f) => f.ruleId === "SEC-INJ-PATH"));
  assert.equal(pathFindings.find((f) => f.ruleId === "SEC-INJ-PATH")?.severity, "HIGH");

  // 4. DOM-based XSS
  const xssCode = `
    element.innerHTML = userProvidedPayload;
  `;
  const xssFindings = scanner.scanContent(xssCode, "components/View.tsx");
  assert.ok(xssFindings.some((f) => f.ruleId === "SEC-INJ-XSS"));
  assert.equal(xssFindings.find((f) => f.ruleId === "SEC-INJ-XSS")?.severity, "HIGH");

  // 5. Code Execution (eval)
  const evalCode = `
    const fn = new Function("arg", req.body.code);
  `;
  const evalFindings = scanner.scanContent(evalCode, "evaluator.js");
  assert.ok(evalFindings.some((f) => f.ruleId === "SEC-INJ-EVAL"));
  assert.equal(evalFindings.find((f) => f.ruleId === "SEC-INJ-EVAL")?.severity, "CRITICAL");
});

test("SAST - Cryptographic Rules detect Weak Hashes, JWT None, Insecure Random, Fallbacks", () => {
  const scanner = new SastScanner();

  // 1. Weak Hash (MD5 / SHA-1)
  const hashTs = `
    const hash = crypto.createHash("md5").update(password).digest("hex");
  `;
  const hashFindings = scanner.scanContent(hashTs, "auth/hash.ts");
  assert.ok(hashFindings.some((f) => f.ruleId === "SEC-CRYP-WEAK-HASH"));

  const hashPy = `
    token = hashlib.sha1(user_data).hexdigest()
  `;
  const hashPyFindings = scanner.scanContent(hashPy, "auth/hash.py");
  assert.ok(hashPyFindings.some((f) => f.ruleId === "SEC-CRYP-WEAK-HASH"));

  // 2. JWT Alg None
  const jwtCode = `
    jwt.verify(token, key, { algorithms: ["none"] });
  `;
  const jwtFindings = scanner.scanContent(jwtCode, "middleware/jwt.ts");
  assert.ok(jwtFindings.some((f) => f.ruleId === "SEC-CRYP-JWT-NONE"));
  assert.equal(jwtFindings.find((f) => f.ruleId === "SEC-CRYP-JWT-NONE")?.severity, "CRITICAL");

  // 3. Insecure Randomness in Security Context
  const randCode = `
    const resetToken = Math.random().toString(36).substring(2);
  `;
  const randFindings = scanner.scanContent(randCode, "services/token.ts");
  assert.ok(randFindings.some((f) => f.ruleId === "SEC-CRYP-INSECURE-RANDOM"));

  // 4. Hardcoded Fallback Secret
  const secretCode = `
    const jwtSecret = process.env.JWT_SECRET || "fallback_super_secret_123";
  `;
  const secretFindings = scanner.scanContent(secretCode, "config/env.ts");
  assert.ok(secretFindings.some((f) => f.ruleId === "SEC-CRYP-FALLBACK-SECRET"));
  assert.equal(
    secretFindings.find((f) => f.ruleId === "SEC-CRYP-FALLBACK-SECRET")?.severity,
    "HIGH",
  );
});

test("SAST - Auth and Access Rules detect token in web storage and logged passwords", () => {
  const scanner = new SastScanner();

  // 1. Token in localStorage / sessionStorage
  const storageCode = `
    localStorage.setItem("authToken", res.data.token);
  `;
  const storageFindings = scanner.scanContent(storageCode, "client/auth.ts");
  assert.ok(storageFindings.some((f) => f.ruleId === "SEC-AUTH-STORAGE"));

  // 2. Logging passwords
  const logCode = `
    console.log("User login attempt with password:", password);
  `;
  const logFindings = scanner.scanContent(logCode, "routes/auth.js");
  assert.ok(logFindings.some((f) => f.ruleId === "SEC-AUTH-PASSWORD-LOG"));
});

test("SAST - SSRF & Misconfiguration Rules detect SSRF, TLS Disable, and Debug Mode", () => {
  const scanner = new SastScanner();

  // 1. SSRF
  const ssrfCode = `
    const result = await axios.get(req.query.targetUrl);
  `;
  const ssrfFindings = scanner.scanContent(ssrfCode, "proxy/fetcher.ts");
  assert.ok(ssrfFindings.some((f) => f.ruleId === "SEC-SSRF-UNVALIDATED"));
  assert.equal(ssrfFindings.find((f) => f.ruleId === "SEC-SSRF-UNVALIDATED")?.severity, "HIGH");

  // 2. TLS Disable
  const tlsCode = `
    const agent = new https.Agent({ rejectUnauthorized: false });
  `;
  const tlsFindings = scanner.scanContent(tlsCode, "http/client.ts");
  assert.ok(tlsFindings.some((f) => f.ruleId === "SEC-CONF-DISABLE-TLS"));
  assert.equal(tlsFindings.find((f) => f.ruleId === "SEC-CONF-DISABLE-TLS")?.severity, "CRITICAL");

  // 3. Debug mode
  const debugPy = `
    app.run(debug=True, host="0.0.0.0")
  `;
  const debugFindings = scanner.scanContent(debugPy, "server.py");
  assert.ok(debugFindings.some((f) => f.ruleId === "SEC-CONF-DEBUG"));
});

test("SAST - Threshold filtering filters findings by severity", () => {
  const registry = new RuleRegistry();
  const criticalOnlyRules = registry.getRulesForLanguage("typescript", "CRITICAL");
  for (const r of criticalOnlyRules) {
    assert.equal(r.severity, "CRITICAL");
  }

  const highAndAbove = registry.getRulesForLanguage("typescript", "HIGH");
  for (const r of highAndAbove) {
    assert.ok(r.severity === "CRITICAL" || r.severity === "HIGH");
  }
});

test("SAST - Full directory scan recursively discovers issues and generates report", async () => {
  const scanner = new SastScanner();
  const report = await scanner.scanPath("src", { threshold: "LOW" });

  assert.ok(report.filesScanned > 0);
  assert.equal(typeof report.durationMs, "number");
  assert.ok(report.summary.critical >= 0);
  assert.ok(Array.isArray(report.findings));
});
