import assert from "node:assert";
import * as http from "node:http";
import { after, before, describe, it } from "node:test";
import { ApiContractFuzzer } from "../src/dast/fuzzer.js";

describe("Contract-Driven API Fuzzing Suite", () => {
  let server: http.Server;
  let serverUrl: string;

  const sampleOpenApi = {
    openapi: "3.0.0",
    info: { title: "Test API", version: "1.0.0" },
    paths: {
      "/api/v1/users": {
        get: {
          summary: "Get users",
          parameters: [
            {
              name: "search",
              in: "query",
              required: false,
              schema: { type: "string" },
            },
          ],
        },
        post: {
          summary: "Create user",
          requestBody: {
            content: {
              "application/json": {
                schema: { type: "object" },
              },
            },
          },
        },
      },
    },
  };

  before(async () => {
    server = http.createServer((req, res) => {
      const url = new URL(req.url || "/", "http://localhost");

      // Vulnerable SQL query behavior: if search parameter contains quote, return SQL error
      if (req.method === "GET" && url.pathname === "/api/v1/users") {
        const search = url.searchParams.get("search") || "";
        if (search.includes("'")) {
          res.writeHead(500, { "Content-Type": "application/json" });
          res.end(
            JSON.stringify({
              error: "sqlite3.OperationalError: syntax error near 'OR'",
            }),
          );
          return;
        }
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify([{ id: 1, name: "Alice" }]));
        return;
      }

      // Vulnerable Prototype pollution: if body has polluted, reflect it
      if (req.method === "POST" && url.pathname === "/api/v1/users") {
        let body = "";
        req.on("data", (chunk) => {
          body += chunk;
        });
        req.on("end", () => {
          if (body.includes("__proto__")) {
            res.writeHead(200, { "Content-Type": "application/json" });
            res.end(JSON.stringify({ status: "success", polluted: true }));
            return;
          }
          res.writeHead(201, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ id: 2, created: true }));
        });
        return;
      }

      res.writeHead(404);
      res.end("Not Found");
    });

    await new Promise<void>((resolve) => {
      server.listen(0, "127.0.0.1", () => {
        const addr = server.address() as { port: number };
        serverUrl = `http://127.0.0.1:${addr.port}`;
        resolve();
      });
    });
  });

  after(() => {
    server.close();
  });

  it("parses endpoint definitions from OpenAPI JSON spec", () => {
    const targets = ApiContractFuzzer.parseEndpointsFromSpec(sampleOpenApi);
    assert.strictEqual(targets.length, 2);

    const getEp = targets.find((t) => t.method === "GET");
    assert.ok(getEp);
    assert.strictEqual(getEp.path, "/api/v1/users");
    assert.strictEqual(getEp.parameters.length, 1);
    assert.strictEqual(getEp.parameters[0].name, "search");

    const postEp = targets.find((t) => t.method === "POST");
    assert.ok(postEp);
    assert.strictEqual(postEp.hasJsonBody, true);
  });

  it("detects SQL injection vulnerabilities when fuzzed endpoint leaks database errors", async () => {
    const fuzzer = new ApiContractFuzzer();
    const report = await fuzzer.fuzz(sampleOpenApi, serverUrl, {
      testPrototypePollution: false,
      testBoundaryBuffer: false,
    });

    assert.ok(report.probesExecuted > 0);
    const sqli = report.findings.find((f) => f.mutationType === "SQL_INJECTION");
    assert.ok(sqli);
    assert.strictEqual(sqli.severity, "CRITICAL");
    assert.strictEqual(sqli.cwe, "CWE-89");
    assert.ok(sqli.evidence.includes("syntax error near"));
  });

  it("detects prototype pollution mutations on JSON endpoints", async () => {
    const fuzzer = new ApiContractFuzzer();
    const report = await fuzzer.fuzz(sampleOpenApi, serverUrl, {
      testSqlInjection: false,
      testBoundaryBuffer: false,
    });

    const protoFinding = report.findings.find((f) => f.mutationType === "PROTOTYPE_POLLUTION");
    assert.ok(protoFinding);
    assert.strictEqual(protoFinding.severity, "HIGH");
    assert.strictEqual(protoFinding.cwe, "CWE-1321");
  });
});
