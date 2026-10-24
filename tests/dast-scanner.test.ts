import assert from "node:assert/strict";
import http from "node:http";
import test from "node:test";
import {
  DastScanner,
  calculateSecurityScore,
  evaluateCookies,
  evaluateCors,
  evaluateSecurityHeaders,
} from "../src/index.js";

test("evaluateSecurityHeaders - Flags missing critical security headers", () => {
  const emptyHeaders = {};
  const { headerItems, findings } = evaluateSecurityHeaders(emptyHeaders, true);

  assert.equal(headerItems.length, 6); // CSP, HSTS, XFO, XCTO, Referrer, Permissions

  const cspItem = headerItems.find((h) => h.name === "Content-Security-Policy");
  assert.ok(cspItem);
  assert.equal(cspItem.status, "MISSING");

  const hstsItem = headerItems.find((h) => h.name === "Strict-Transport-Security");
  assert.ok(hstsItem);
  assert.equal(hstsItem.status, "MISSING");

  const xfoItem = headerItems.find((h) => h.name === "X-Frame-Options");
  assert.ok(xfoItem);
  assert.equal(xfoItem.status, "MISSING");

  const xctoItem = headerItems.find((h) => h.name === "X-Content-Type-Options");
  assert.ok(xctoItem);
  assert.equal(xctoItem.status, "MISSING");

  // Verify findings
  assert.ok(findings.some((f) => f.id === "SEC-HDR-CSP-MISSING"));
  assert.ok(findings.some((f) => f.id === "SEC-HDR-HSTS-MISSING"));
  assert.ok(findings.some((f) => f.id === "SEC-HDR-CLICKJACKING-RISK"));
  assert.ok(findings.some((f) => f.id === "SEC-HDR-XCTO-MISSING"));
});

test("evaluateSecurityHeaders - Detects unsafe CSP directives ('unsafe-inline', 'unsafe-eval')", () => {
  const headers = {
    "content-security-policy":
      "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval';",
    "strict-transport-security": "max-age=31536000; includeSubDomains; preload",
    "x-frame-options": "DENY",
    "x-content-type-options": "nosniff",
    "referrer-policy": "strict-origin-when-cross-origin",
  };

  const { headerItems, findings } = evaluateSecurityHeaders(headers, true);
  const cspItem = headerItems.find((h) => h.name === "Content-Security-Policy");
  assert.ok(cspItem);
  assert.equal(cspItem.status, "SUBOPTIMAL");
  assert.ok(findings.some((f) => f.id === "SEC-HDR-CSP-UNSAFE-INLINE"));
  assert.ok(findings.some((f) => f.id === "SEC-HDR-CSP-UNSAFE-EVAL"));
});

test("evaluateSecurityHeaders - Detects server and tech stack disclosure", () => {
  const headers = {
    server: "Apache/2.4.41 (Ubuntu)",
    "x-powered-by": "Express",
  };

  const { findings } = evaluateSecurityHeaders(headers, false);
  assert.ok(findings.some((f) => f.id === "SEC-HDR-INFO-DISCLOSURE-SERVER"));
  assert.ok(findings.some((f) => f.id === "SEC-HDR-INFO-DISCLOSURE-POWERED-BY"));
});

test("evaluateCookies - Detects missing Secure, HttpOnly, and SameSite attributes", () => {
  const rawCookies = [
    "session_id=abc123xyz; Path=/", // Sensitive: missing Secure, HttpOnly, SameSite
    "preferences=dark; Path=/; Secure; HttpOnly; SameSite=Lax", // Fully secured
  ];

  const { cookieItems, findings } = evaluateCookies(rawCookies, true);
  assert.equal(cookieItems.length, 2);

  const sessionCookie = cookieItems[0];
  assert.equal(sessionCookie.secure, false);
  assert.equal(sessionCookie.httpOnly, false);
  assert.equal(sessionCookie.sameSite, undefined);
  assert.equal(sessionCookie.issues.length, 3);

  assert.ok(findings.some((f) => f.id === "SEC-CK-NO-SECURE-SESSION_ID"));
  assert.ok(findings.some((f) => f.id === "SEC-CK-NO-HTTPONLY-SESSION_ID"));
  assert.ok(findings.some((f) => f.id === "SEC-CK-NO-SAMESITE-SESSION_ID"));

  const prefCookie = cookieItems[1];
  assert.equal(prefCookie.secure, true);
  assert.equal(prefCookie.httpOnly, true);
  assert.equal(prefCookie.sameSite, "Lax");
  assert.equal(prefCookie.issues.length, 0);
});

test("evaluateCors - Catches dangerous wildcard with credentials and null origin", () => {
  // 1. Critical: Wildcard origin with credentials
  const badCors = {
    "access-control-allow-origin": "*",
    "access-control-allow-credentials": "true",
  };
  const { corsResult: res1, findings: findings1 } = evaluateCors(badCors);
  assert.equal(res1.status, "CRITICAL");
  assert.equal(res1.isWildcardWithCredentials, true);
  assert.ok(findings1.some((f) => f.id === "SEC-CORS-WILDCARD-CREDENTIALS"));

  // 2. High: Null origin
  const nullCors = {
    "access-control-allow-origin": "null",
  };
  const { corsResult: res2, findings: findings2 } = evaluateCors(nullCors);
  assert.equal(res2.status, "WARN");
  assert.ok(findings2.some((f) => f.id === "SEC-CORS-NULL-ORIGIN"));

  // 3. Safe: Strict origin
  const safeCors = {
    "access-control-allow-origin": "https://app.example.com",
    "access-control-allow-credentials": "true",
  };
  const { corsResult: res3, findings: findings3 } = evaluateCors(safeCors);
  assert.equal(res3.status, "SAFE");
  assert.equal(findings3.length, 0);
});

test("calculateSecurityScore - Computes correct scores and letter grades", () => {
  // A+ Posture
  const perfect = calculateSecurityScore([]);
  assert.equal(perfect.score, 100);
  assert.equal(perfect.grade, "A+");

  // Critical finding -> Automatically capped at F (< 40)
  const criticalFindings = [
    {
      id: "SEC-TEST-1",
      category: "CORS" as const,
      title: "Critical Vulnerability",
      severity: "CRITICAL" as const,
      scoreImpact: 35,
      description: "Critical bug",
      remediation: "Fix it",
    },
  ];
  const criticalResult = calculateSecurityScore(criticalFindings);
  assert.equal(criticalResult.grade, "F");
  assert.ok(criticalResult.score <= 39);

  // High finding -> Automatically capped at C or lower
  const highFindings = [
    {
      id: "SEC-TEST-2",
      category: "HEADERS" as const,
      title: "Missing CSP",
      severity: "HIGH" as const,
      scoreImpact: 20,
      description: "No CSP",
      remediation: "Add CSP",
    },
  ];
  const highResult = calculateSecurityScore(highFindings);
  assert.ok(highResult.score <= 69);
  assert.ok(highResult.grade === "C" || highResult.grade === "D");
});

test("DastScanner - End-to-end audit against a mock local HTTP server", async () => {
  const port = 19688;
  const server = http.createServer((_req, res) => {
    res.writeHead(200, {
      "Content-Type": "text/html",
      Server: "TestServer/1.0.0",
      "X-Powered-By": "NodeTest",
      "Set-Cookie": "auth_token=secret123; Path=/", // Insecure cookie
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Credentials": "true", // Insecure CORS
    });
    res.end("<html><body>Test App</body></html>");
  });

  await new Promise<void>((resolve) => server.listen(port, "127.0.0.1", resolve));
  server.unref();

  try {
    const scanner = new DastScanner({ timeoutMs: 3000, checkTlsCert: false });
    const report = await scanner.scanUrl(`http://127.0.0.1:${port}`);

    assert.equal(report.statusCode, 200);
    assert.equal(report.targetUrl, `http://127.0.0.1:${port}`);
    assert.ok(report.findings.length > 0);

    // Verify finding categories
    assert.ok(report.findings.some((f) => f.category === "CORS"));
    assert.ok(report.findings.some((f) => f.category === "COOKIES"));
    assert.ok(report.findings.some((f) => f.category === "HEADERS"));
    assert.ok(report.findings.some((f) => f.category === "DISCLOSURE"));

    // Critical CORS finding should drop score to F
    assert.equal(report.grade, "F");
    assert.ok(report.score <= 39);
    assert.ok(report.summary.critical >= 1);
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
});
