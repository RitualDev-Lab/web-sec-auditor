/**
 * Contract-Driven API Fuzzer
 *
 * Automatically inspects OpenAPI / Swagger schemas to fuzz exposed HTTP endpoints
 * with contract mutations: SQL injection validation probes, prototype pollution,
 * and boundary buffer violations to verify server resiliency.
 */

import type {
  ApiFuzzFinding,
  ApiFuzzOptions,
  ApiFuzzReport,
  FindingSeverity,
} from "../types/index.js";

export interface FuzzEndpointTarget {
  path: string;
  method: string;
  parameters: Array<{
    name: string;
    in: "path" | "query" | "header" | string;
    required?: boolean;
    schema?: Record<string, unknown>;
  }>;
  hasJsonBody: boolean;
}

const SQL_INJECTION_PROBES = [
  "' OR '1'='1",
  '" OR ""="',
  "1; SELECT 1 --",
  "' UNION SELECT NULL --",
  "1' AND 1=1 --",
];

const PROTOTYPE_POLLUTION_PROBES: string[] = [
  '{"__proto__": {"polluted": true, "role": "admin"}}',
  '{"constructor": {"prototype": {"polluted": true}}}',
];

const BOUNDARY_BUFFER_PROBES = [
  "A".repeat(4096),
  9007199254740992,
  -9007199254740992,
  "admin\x00bypass",
];

const SQL_ERROR_PATTERNS = [
  /syntax error near/i,
  /sqlite3\.(?:OperationalError|DatabaseError)/i,
  /PostgreSQL.*(?:ERROR|FATAL)/i,
  /ORA-[0-9]{5}/i,
  /mysql_(?:fetch|query|errno)/i,
  /SQLSTATE\[[0-9A-Z]+\]/i,
  /unhandled sql exception/i,
  /unclosed quotation mark after the character string/i,
];

export class ApiContractFuzzer {
  /**
   * Parses an OpenAPI 3.x or Swagger 2.0 specification (JSON or object)
   * into executable fuzzing endpoint targets.
   */
  public static parseEndpointsFromSpec(
    specInput: string | Record<string, unknown>,
  ): FuzzEndpointTarget[] {
    let spec: Record<string, unknown>;
    if (typeof specInput === "string") {
      try {
        spec = JSON.parse(specInput);
      } catch {
        throw new Error("Failed to parse OpenAPI spec: Invalid JSON format");
      }
    } else {
      spec = specInput;
    }

    const targets: FuzzEndpointTarget[] = [];
    const paths = (spec.paths as Record<string, Record<string, unknown>>) || {};

    for (const [pathStr, pathItem] of Object.entries(paths)) {
      if (!pathItem || typeof pathItem !== "object") continue;

      const methods = ["get", "post", "put", "delete", "patch"];
      for (const method of methods) {
        const operation = pathItem[method] as Record<string, unknown> | undefined;
        if (!operation) continue;

        const rawParams = (operation.parameters || pathItem.parameters || []) as Array<
          Record<string, unknown>
        >;
        const parameters = rawParams.map((p) => ({
          name: String(p.name || ""),
          in: String(p.in || "query"),
          required: Boolean(p.required),
          schema: (p.schema as Record<string, unknown>) || {},
        }));

        const reqBody = operation.requestBody as Record<string, unknown> | undefined;
        const content = reqBody?.content as Record<string, unknown> | undefined;
        const hasJsonBody = Boolean(content && ("application/json" in content || "*/*" in content));

        targets.push({
          path: pathStr,
          method: method.toUpperCase(),
          parameters,
          hasJsonBody,
        });
      }
    }

    return targets;
  }

  /**
   * Executes contract-driven mutation fuzzing across endpoints defined in an OpenAPI specification.
   */
  public async fuzz(
    specInput: string | Record<string, unknown>,
    targetBaseUrl: string,
    options: ApiFuzzOptions = {},
  ): Promise<ApiFuzzReport> {
    const startTime = Date.now();
    const cleanBaseUrl = targetBaseUrl.replace(/\/+$/, "");
    const endpoints = ApiContractFuzzer.parseEndpointsFromSpec(specInput);

    const findings: ApiFuzzFinding[] = [];
    let probesExecuted = 0;

    const timeoutMs = options.timeoutMs ?? 5000;
    const testSql = options.testSqlInjection ?? true;
    const testProto = options.testPrototypePollution ?? true;
    const testBoundary = options.testBoundaryBuffer ?? true;

    for (const ep of endpoints) {
      // 1. Fuzz Parameters with SQL Injection Verification Probes
      if (testSql) {
        for (const probe of SQL_INJECTION_PROBES) {
          probesExecuted++;
          const result = await this.executeProbe(cleanBaseUrl, ep, {
            queryParamValue: probe,
            bodyPayload: ep.hasJsonBody ? { input: probe } : undefined,
            timeoutMs,
            customHeaders: options.headers,
          });

          if (result) {
            const hasSqlError = SQL_ERROR_PATTERNS.some((p) => p.test(result.body));
            if (hasSqlError || result.statusCode >= 500) {
              findings.push({
                id: `DAST-FUZZ-SQL-${ep.method}-${ep.path.replace(/[^a-zA-Z0-9]/g, "_")}`,
                endpoint: ep.path,
                method: ep.method,
                mutationType: "SQL_INJECTION",
                payload: probe,
                statusCode: result.statusCode,
                evidence: hasSqlError
                  ? `Database error signature detected in response: ${result.body.slice(0, 160)}`
                  : `Server responded with HTTP ${result.statusCode} unhandled error under SQL probe mutation.`,
                severity: "CRITICAL",
                description: `Endpoint ${ep.method} ${ep.path} leaks database errors or crashes when fuzzed with SQL syntax probe: '${probe}'.`,
                remediation:
                  "Enforce parameterized queries or ORM sanitization. Implement input validation rejecting raw SQL meta-characters.",
                cwe: "CWE-89",
              });
              break; // Flag once per endpoint
            }
          }
        }
      }

      // 2. Fuzz JSON Endpoints with Prototype Pollution Mutations
      if (testProto && ep.hasJsonBody) {
        for (const protoPayload of PROTOTYPE_POLLUTION_PROBES) {
          probesExecuted++;
          const result = await this.executeProbe(cleanBaseUrl, ep, {
            bodyPayload: protoPayload,
            timeoutMs,
            customHeaders: options.headers,
          });

          if (result) {
            const reflectsPollution =
              result.body.includes('"polluted":true') || result.body.includes('"role":"admin"');
            const unhandledTypeError =
              result.statusCode >= 500 &&
              (result.body.includes("TypeError") ||
                result.body.includes("Cannot read property") ||
                result.body.includes("Cannot set property"));

            if (reflectsPollution || unhandledTypeError) {
              findings.push({
                id: `DAST-FUZZ-PROTO-${ep.method}-${ep.path.replace(/[^a-zA-Z0-9]/g, "_")}`,
                endpoint: ep.path,
                method: ep.method,
                mutationType: "PROTOTYPE_POLLUTION",
                payload: protoPayload,
                statusCode: result.statusCode,
                evidence: reflectsPollution
                  ? "Injected prototype pollution key reflected in server response structure."
                  : `Server crashed with TypeError under prototype mutation: ${result.body.slice(0, 140)}`,
                severity: "HIGH",
                description: `Endpoint ${ep.method} ${ep.path} vulnerable to prototype mutation or unhandled object assignment.`,
                remediation:
                  "Freeze object prototypes (Object.freeze(Object.prototype)) or sanitize keys (denying '__proto__', 'constructor', 'prototype') before recursive assignment.",
                cwe: "CWE-1321",
              });
              break;
            }
          }
        }
      }

      // 3. Fuzz Parameters with Boundary Buffer Violations
      if (testBoundary) {
        for (const bufferPayload of BOUNDARY_BUFFER_PROBES) {
          probesExecuted++;
          const result = await this.executeProbe(cleanBaseUrl, ep, {
            queryParamValue: String(bufferPayload),
            bodyPayload: ep.hasJsonBody ? { buffer: bufferPayload } : undefined,
            timeoutMs,
            customHeaders: options.headers,
          });

          if (result && result.statusCode >= 500) {
            findings.push({
              id: `DAST-FUZZ-BOUNDARY-${ep.method}-${ep.path.replace(/[^a-zA-Z0-9]/g, "_")}`,
              endpoint: ep.path,
              method: ep.method,
              mutationType: "BOUNDARY_BUFFER",
              payload:
                typeof bufferPayload === "string" && bufferPayload.length > 50
                  ? `${bufferPayload.slice(0, 30)}...[${bufferPayload.length} bytes]`
                  : bufferPayload,
              statusCode: result.statusCode,
              evidence: `Server crashed with HTTP ${result.statusCode} on extreme boundary value.`,
              severity: "MEDIUM",
              description: `Endpoint ${ep.method} ${ep.path} failed to handle boundary/buffer violation gracefully with 400 Bad Request.`,
              remediation:
                "Validate payload boundaries with JSON schema validators (Zod, Ajv). Set explicit maxLength, maximum, and minimum constraints.",
              cwe: "CWE-754",
            });
            break;
          }
        }
      }
    }

    const summary = {
      critical: findings.filter((f) => f.severity === "CRITICAL").length,
      high: findings.filter((f) => f.severity === "HIGH").length,
      medium: findings.filter((f) => f.severity === "MEDIUM").length,
      low: findings.filter((f) => f.severity === "LOW").length,
      info: findings.filter((f) => f.severity === "INFO").length,
    };

    return {
      targetBaseUrl,
      totalEndpoints: endpoints.length,
      probesExecuted,
      scanTimestamp: new Date().toISOString(),
      durationMs: Date.now() - startTime,
      summary,
      findings,
    };
  }

  /**
   * Executes a single mutated probe against a target endpoint.
   */
  private async executeProbe(
    baseUrl: string,
    ep: FuzzEndpointTarget,
    options: {
      queryParamValue?: string;
      bodyPayload?: unknown;
      timeoutMs: number;
      customHeaders?: Record<string, string>;
    },
  ): Promise<{ statusCode: number; body: string } | null> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), options.timeoutMs);

    try {
      // Substitute path parameters with placeholder
      let resolvedPath = ep.path;
      for (const param of ep.parameters) {
        if (param.in === "path") {
          resolvedPath = resolvedPath.replace(`{${param.name}}`, "1");
        }
      }

      let fullUrl = `${baseUrl}${resolvedPath.startsWith("/") ? "" : "/"}${resolvedPath}`;

      if (
        options.queryParamValue &&
        (ep.method === "GET" || ep.parameters.some((p) => p.in === "query"))
      ) {
        const urlObj = new URL(fullUrl);
        const queryName = ep.parameters.find((p) => p.in === "query")?.name || "q";
        urlObj.searchParams.set(queryName, options.queryParamValue);
        fullUrl = urlObj.toString();
      }

      const headers: Record<string, string> = {
        "User-Agent": "WebSecAuditor-ContractFuzzer/1.0",
        Accept: "application/json, text/plain, */*",
        ...(options.customHeaders || {}),
      };

      let body: string | undefined;
      if (options.bodyPayload && ep.method !== "GET") {
        headers["Content-Type"] = "application/json";
        body =
          typeof options.bodyPayload === "string"
            ? options.bodyPayload
            : JSON.stringify(options.bodyPayload);
      }

      const res = await fetch(fullUrl, {
        method: ep.method,
        headers,
        body,
        signal: controller.signal,
      });

      const text = await res.text();
      return {
        statusCode: res.status,
        body: text,
      };
    } catch {
      return null;
    } finally {
      clearTimeout(timer);
    }
  }
}
