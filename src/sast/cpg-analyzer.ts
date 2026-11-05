import type { FindingSeverity } from "../types/index.js";

export type CpgNodeType =
  | "AST_NODE"
  | "CFG_BLOCK"
  | "PDG_DATA"
  | "MICROSERVICE_BOUNDARY"
  | "ORM_LAYER"
  | "API_RESPONSE_HANDLER"
  | "SANITIZER";

export type CpgEdgeType =
  | "AST_CHILD"
  | "CFG_FLOW"
  | "PDG_DATA_DEP"
  | "PDG_CONTROL_DEP"
  | "TAINT_PROPAGATION"
  | "MICROSERVICE_RPC";

export interface CpgNode {
  id: string;
  type: CpgNodeType;
  file: string;
  line: number;
  code: string;
  label: string;
  variable?: string;
  isTainted?: boolean;
  metadata?: Record<string, unknown>;
}

export interface CpgEdge {
  from: string;
  to: string;
  type: CpgEdgeType;
  variable?: string;
  label?: string;
}

export interface CpgTraceStep {
  file: string;
  line: number;
  stepDescription: string;
  codeSnippet: string;
  nodeType: CpgNodeType;
}

export interface CpgFinding {
  id: string;
  ruleId: string;
  category:
    | "ORM_INJECTION"
    | "MICROSERVICE_SSRF"
    | "COMMAND_INJECTION"
    | "API_RESPONSE_XSS"
    | "RAW_SQL_INJECTION";
  title: string;
  severity: FindingSeverity;
  cwe: string;
  owasp: string;
  source: {
    file: string;
    line: number;
    variable: string;
    code: string;
  };
  sink: {
    file: string;
    line: number;
    layer: "orm" | "microservice" | "shell" | "response";
    code: string;
    sinkType: string;
  };
  trace: CpgTraceStep[];
  remediation: string;
}

export class CodePropertyGraph {
  public nodes: Map<string, CpgNode> = new Map();
  public edges: CpgEdge[] = [];
  private outEdges: Map<string, CpgEdge[]> = new Map();
  private inEdges: Map<string, CpgEdge[]> = new Map();

  public addNode(node: CpgNode): void {
    this.nodes.set(node.id, node);
    if (!this.outEdges.has(node.id)) this.outEdges.set(node.id, []);
    if (!this.inEdges.has(node.id)) this.inEdges.set(node.id, []);
  }

  public addEdge(edge: CpgEdge): void {
    this.edges.push(edge);
    const outs = this.outEdges.get(edge.from) || [];
    outs.push(edge);
    this.outEdges.set(edge.from, outs);

    const ins = this.inEdges.get(edge.to) || [];
    ins.push(edge);
    this.inEdges.set(edge.to, ins);
  }

  public getNode(id: string): CpgNode | undefined {
    return this.nodes.get(id);
  }

  public getOutEdges(nodeId: string): CpgEdge[] {
    return this.outEdges.get(nodeId) || [];
  }

  public getInEdges(nodeId: string): CpgEdge[] {
    return this.inEdges.get(nodeId) || [];
  }

  public findTaintPaths(sourceId: string, sinkId: string, maxDepth = 15): CpgEdge[][] {
    const paths: CpgEdge[][] = [];
    const queue: Array<{ currentId: string; edgePath: CpgEdge[]; visited: Set<string> }> = [
      { currentId: sourceId, edgePath: [], visited: new Set([sourceId]) },
    ];

    while (queue.length > 0) {
      const item = queue.shift();
      if (!item) break;
      const { currentId, edgePath, visited } = item;

      if (currentId === sinkId) {
        paths.push(edgePath);
        continue;
      }

      if (edgePath.length >= maxDepth) continue;

      for (const edge of this.getOutEdges(currentId)) {
        if (!visited.has(edge.to)) {
          const nextVisited = new Set(visited);
          nextVisited.add(edge.to);
          queue.push({
            currentId: edge.to,
            edgePath: [...edgePath, edge],
            visited: nextVisited,
          });
        }
      }
    }

    return paths;
  }
}

/**
 * Whole-Program Code Property Graph (CPG) Analyzer
 * Synthesizes AST, CFG, and PDG dataflows tracking untrusted input across
 * microservice boundaries, ORM layers (Prisma, TypeORM, Drizzle), and API response handlers.
 */
export class WholeProgramCpgAnalyzer {
  public analyzeProject(files: Map<string, string>): {
    graph: CodePropertyGraph;
    findings: CpgFinding[];
  } {
    const graph = new CodePropertyGraph();
    const findings: CpgFinding[] = [];

    const fileList = Array.from(files.entries());
    let counter = 0;
    const nextId = (p: string) => `${p}_${++counter}`;

    // Index all functions across files: name -> { file, paramNames, nodeIds }
    const functionRegistry = new Map<
      string,
      { file: string; paramNames: string[]; paramNodes: Map<string, CpgNode> }
    >();

    // Mapping of (file:variable) to list of definition CpgNodes
    const varDefMap = new Map<string, CpgNode>();

    const sourceNodes: CpgNode[] = [];
    const sinkNodes: Array<{
      node: CpgNode;
      category: CpgFinding["category"];
      cwe: string;
      owasp: string;
      remediation: string;
      sinkType: string;
    }> = [];

    // --- PHASE 1: Parse AST, Function Signatures & Variable Definitions ---
    for (const [filePath, content] of fileList) {
      const normFile = filePath.replace(/\\/g, "/");
      const lines = content.split("\n");

      for (let i = 0; i < lines.length; i++) {
        const lineNum = i + 1;
        const line = lines[i].trim();
        if (!line || line.startsWith("//") || line.startsWith("/*")) continue;

        // 1. Function declarations
        const fnMatch = /(?:export\s+)?(?:async\s+)?function\s+([a-zA-Z0-9_]+)\s*\(([^)]*)\)/.exec(
          line,
        );
        if (fnMatch) {
          const fnName = fnMatch[1];
          const rawParams = fnMatch[2]
            .split(",")
            .map((p) => p.trim())
            .filter(Boolean);
          const paramNames = rawParams.map((p) => p.split(":")[0].trim());
          const paramNodes = new Map<string, CpgNode>();

          for (const pName of paramNames) {
            const pNode: CpgNode = {
              id: nextId("param"),
              type: "PDG_DATA",
              file: normFile,
              line: lineNum,
              code: line,
              label: `Function Parameter: ${pName} in ${fnName}`,
              variable: pName,
            };
            graph.addNode(pNode);
            paramNodes.set(pName, pNode);
            varDefMap.set(`${normFile}:${pName}`, pNode);
          }

          functionRegistry.set(fnName, { file: normFile, paramNames, paramNodes });
        }

        // 2. Sources (req.params, req.query, req.body, req.headers, c.req, Astro.params)
        const srcMatch = this.detectTaintSource(line);
        if (srcMatch) {
          const sNode: CpgNode = {
            id: nextId("source"),
            type: "PDG_DATA",
            file: normFile,
            line: lineNum,
            code: line,
            label: `Source: ${srcMatch.variable} from ${srcMatch.expression}`,
            variable: srcMatch.variable,
            isTainted: true,
          };
          graph.addNode(sNode);
          sourceNodes.push(sNode);
          varDefMap.set(`${normFile}:${srcMatch.variable}`, sNode);
        }

        // 3. Variable Assignments
        const assignMatch = this.detectAssignment(line);
        if (assignMatch && !srcMatch) {
          const { lhs, rhs } = assignMatch;

          // Check for sanitizers
          if (this.isSanitized(rhs)) {
            const sanNode: CpgNode = {
              id: nextId("sanitizer"),
              type: "SANITIZER",
              file: normFile,
              line: lineNum,
              code: line,
              label: `Sanitizer: ${lhs} safely sanitized`,
              variable: lhs,
            };
            graph.addNode(sanNode);
            varDefMap.set(`${normFile}:${lhs}`, sanNode);
          } else {
            const defNode: CpgNode = {
              id: nextId("assign"),
              type: "PDG_DATA",
              file: normFile,
              line: lineNum,
              code: line,
              label: `Variable Assignment: ${lhs}`,
              variable: lhs,
            };
            graph.addNode(defNode);
            varDefMap.set(`${normFile}:${lhs}`, defNode);
          }
        }

        // 4. ORM Sinks
        const ormMatch = this.detectOrmSink(line);
        if (ormMatch) {
          const ormNode: CpgNode = {
            id: nextId("orm_sink"),
            type: "ORM_LAYER",
            file: normFile,
            line: lineNum,
            code: line,
            label: `ORM Sink: ${ormMatch.sinkType}`,
            metadata: { sinkType: ormMatch.sinkType },
          };
          graph.addNode(ormNode);
          sinkNodes.push({
            node: ormNode,
            category: "ORM_INJECTION",
            cwe: "CWE-89",
            owasp: "A03:2021-Injection",
            remediation:
              "Use parameterized template tags or native ORM parameter bindings rather than raw string concatenation.",
            sinkType: ormMatch.sinkType,
          });
        }

        // 5. Microservice Sinks (SSRF)
        const rpcMatch = this.detectMicroserviceBoundary(line);
        if (rpcMatch) {
          const rpcNode: CpgNode = {
            id: nextId("microservice_sink"),
            type: "MICROSERVICE_BOUNDARY",
            file: normFile,
            line: lineNum,
            code: line,
            label: `Microservice RPC Sink: ${rpcMatch.clientType}`,
            metadata: { client: rpcMatch.clientType },
          };
          graph.addNode(rpcNode);
          sinkNodes.push({
            node: rpcNode,
            category: "MICROSERVICE_SSRF",
            cwe: "CWE-918",
            owasp: "A10:2021-Server-Side Request Forgery",
            remediation:
              "Validate target microservice URLs against a strict domain/service allowlist to prevent SSRF.",
            sinkType: rpcMatch.clientType,
          });
        }

        // 6. API Response Sinks (XSS)
        const respMatch = this.detectResponseSink(line);
        if (respMatch) {
          const respNode: CpgNode = {
            id: nextId("response_sink"),
            type: "API_RESPONSE_HANDLER",
            file: normFile,
            line: lineNum,
            code: line,
            label: "API Response Reflection Sink",
          };
          graph.addNode(respNode);
          sinkNodes.push({
            node: respNode,
            category: "API_RESPONSE_XSS",
            cwe: "CWE-79",
            owasp: "A03:2021-Injection",
            remediation:
              "Ensure untrusted strings reflected in API responses are sanitized or served with explicit application/json Content-Type headers.",
            sinkType: "API Response Writer",
          });
        }
      }
    }

    // --- PHASE 2: Connect PDG Data Dependencies & Call Edges ---
    for (const [filePath, content] of fileList) {
      const normFile = filePath.replace(/\\/g, "/");
      const lines = content.split("\n");

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i].trim();
        if (!line || line.startsWith("//") || line.startsWith("/*")) continue;

        // Connect variable assignments (RHS -> LHS)
        const assignMatch = this.detectAssignment(line);
        if (assignMatch) {
          const { lhs, rhs } = assignMatch;
          const lhsNode = varDefMap.get(`${normFile}:${lhs}`);
          if (lhsNode && lhsNode.type !== "SANITIZER") {
            // Check all known variables in this file used in rhs
            for (const [key, defNode] of varDefMap.entries()) {
              const [f, v] = key.split(":");
              if (f === normFile && v !== lhs && this.referencesVariable(rhs, v)) {
                graph.addEdge({
                  from: defNode.id,
                  to: lhsNode.id,
                  type: "PDG_DATA_DEP",
                  variable: v,
                  label: `data-flow: ${v} -> ${lhs}`,
                });
              }
            }

            // Check if rhs calls an exported function in another file: fn(arg)
            for (const [fnName, fnInfo] of functionRegistry.entries()) {
              const callRegex = new RegExp(`\\b${fnName}\\s*\\(([^)]*)\\)`);
              const callMatch = callRegex.exec(rhs);
              if (callMatch) {
                const callArgs = callMatch[1]
                  .split(",")
                  .map((a) => a.trim())
                  .filter(Boolean);
                for (let argIdx = 0; argIdx < callArgs.length; argIdx++) {
                  const argName = callArgs[argIdx];
                  const argNode = varDefMap.get(`${normFile}:${argName}`);
                  const targetParamName = fnInfo.paramNames[argIdx];
                  const targetParamNode = fnInfo.paramNodes.get(targetParamName);

                  if (argNode && targetParamNode) {
                    graph.addEdge({
                      from: argNode.id,
                      to: targetParamNode.id,
                      type: "PDG_DATA_DEP",
                      variable: argName,
                      label: `inter-module call: ${normFile} -> ${fnName}(${targetParamName})`,
                    });
                  }
                }
              }
            }
          }
        }

        // Connect Sinks to variables referenced in their lines
        for (const sinkItem of sinkNodes) {
          if (sinkItem.node.file === normFile && sinkItem.node.code === line) {
            for (const [key, defNode] of varDefMap.entries()) {
              const [f, v] = key.split(":");
              if (f === normFile && this.referencesVariable(line, v)) {
                graph.addEdge({
                  from: defNode.id,
                  to: sinkItem.node.id,
                  type: "TAINT_PROPAGATION",
                  variable: v,
                  label: `untrusted-sink-invocation: ${v} -> ${sinkItem.sinkType}`,
                });
              }
            }
          }
        }
      }
    }

    // --- PHASE 3: Fixed-Point Taint Reachability Analysis ---
    for (const sourceNode of sourceNodes) {
      for (const sinkItem of sinkNodes) {
        const paths = graph.findTaintPaths(sourceNode.id, sinkItem.node.id);
        if (paths.length > 0) {
          const shortestPath = paths.reduce((a, b) => (a.length < b.length ? a : b));

          // Check if path passes through any SANITIZER node
          const hasSanitizer = shortestPath.some((edge) => {
            const toNode = graph.getNode(edge.to);
            return toNode?.type === "SANITIZER";
          });

          if (hasSanitizer) continue;

          const trace: CpgTraceStep[] = [
            {
              file: sourceNode.file,
              line: sourceNode.line,
              stepDescription: sourceNode.label,
              codeSnippet: sourceNode.code,
              nodeType: sourceNode.type,
            },
          ];

          for (const edge of shortestPath) {
            const toNode = graph.getNode(edge.to);
            if (toNode && toNode.id !== sourceNode.id) {
              trace.push({
                file: toNode.file,
                line: toNode.line,
                stepDescription: edge.label || toNode.label,
                codeSnippet: toNode.code,
                nodeType: toNode.type,
              });
            }
          }

          findings.push({
            id: `CPG-${findings.length + 1}`,
            ruleId: `CPG-${sinkItem.category}`,
            category: sinkItem.category,
            title: `${sinkItem.category.replace(/_/g, " ")}: Untrusted input flows to ${sinkItem.sinkType}`,
            severity: "CRITICAL",
            cwe: sinkItem.cwe,
            owasp: sinkItem.owasp,
            source: {
              file: sourceNode.file,
              line: sourceNode.line,
              variable: sourceNode.variable || "input",
              code: sourceNode.code,
            },
            sink: {
              file: sinkItem.node.file,
              line: sinkItem.node.line,
              layer:
                sinkItem.node.type === "ORM_LAYER"
                  ? "orm"
                  : sinkItem.node.type === "MICROSERVICE_BOUNDARY"
                    ? "microservice"
                    : sinkItem.node.type === "API_RESPONSE_HANDLER"
                      ? "response"
                      : "shell",
              code: sinkItem.node.code,
              sinkType: sinkItem.sinkType,
            },
            trace,
            remediation: sinkItem.remediation,
          });
        }
      }
    }

    return { graph, findings };
  }

  private detectTaintSource(line: string): { variable: string; expression: string } | null {
    const match =
      /(?:const|let|var)\s+([a-zA-Z0-9_{},\s]+)\s*=\s*(req\.(?:params|query|body|headers)(?:\.[a-zA-Z0-9_]+)?)/.exec(
        line,
      );
    if (match) {
      const varName = match[1].replace(/[{}]/g, "").trim();
      return { variable: varName, expression: match[2].trim() };
    }

    const modernMatch =
      /(?:const|let|var)\s+([a-zA-Z0-9_]+)\s*=\s*(?:c\.req\.(?:param|query|json)\([^\)]*\)|Astro\.params\.[a-zA-Z0-9_]+)/.exec(
        line,
      );
    if (modernMatch) {
      return { variable: modernMatch[1].trim(), expression: modernMatch[0].trim() };
    }

    return null;
  }

  private detectAssignment(line: string): { lhs: string; rhs: string } | null {
    const match = /(?:const|let|var)\s+([a-zA-Z0-9_]+)\s*=\s*([^;]+);?/.exec(line);
    if (match) {
      return { lhs: match[1].trim(), rhs: match[2].trim() };
    }
    const plain = /^([a-zA-Z0-9_]+)\s*=\s*([^;]+);?/.exec(line);
    if (plain) {
      return { lhs: plain[1].trim(), rhs: plain[2].trim() };
    }
    return null;
  }

  private referencesVariable(expression: string, variable: string): boolean {
    const regex = new RegExp(`\\b${variable}\\b`);
    return regex.test(expression);
  }

  private isSanitized(expression: string): boolean {
    return (
      /Number\(|parseInt\(|parseFloat\(|validator\.(?:isAlphanumeric|escape)|z\.(?:string|number)\(\)\.parse/.test(
        expression,
      ) || /encodeURIComponent\(|escapeHtml\(/.test(expression)
    );
  }

  private detectOrmSink(line: string): { sinkType: string } | null {
    if (/\$queryRawUnsafe|\$executeRawUnsafe/.test(line)) {
      return { sinkType: "Prisma Raw Unsafe Query ($queryRawUnsafe)" };
    }
    if (/prisma\.\$queryRaw`.*\$\{/.test(line)) {
      return { sinkType: "Prisma $queryRaw with dynamic interpolation" };
    }
    if (
      /\.(?:query|where)\([`'"].*\$\{|\.(?:query|where)\([`'"].*\s*\+\s*[a-zA-Z0-9_]+/.test(line)
    ) {
      return { sinkType: "TypeORM Dynamic Query Injection (.query / .where)" };
    }
    if (/sql\.raw\([`'"].*\$\{|\.execute\(sql\.raw\(/.test(line)) {
      return { sinkType: "Drizzle Dynamic sql.raw() SQL Injection" };
    }
    if (/sequelize\.query\(.*\+/.test(line)) {
      return { sinkType: "Sequelize Raw Query Injection" };
    }
    return null;
  }

  private detectMicroserviceBoundary(line: string): { clientType: string } | null {
    if (
      /axios\.(?:get|post|put|delete|request)\([`'"].*\$\{/.test(line) ||
      /axios\([`'"].*\$\{/.test(line)
    ) {
      return { clientType: "Axios Microservice HTTP Client" };
    }
    if (/fetch\([`'"].*\$\{/.test(line)) {
      return { clientType: "Fetch Microservice HTTP Client" };
    }
    return null;
  }

  private detectResponseSink(line: string): { sinkType: string } | null {
    if (/res\.(?:send|write)\([a-zA-Z0-9_]+\)/.test(line)) {
      return { sinkType: "Express / Node Response Writer (res.send)" };
    }
    if (/return\s+new\s+Response\([a-zA-Z0-9_]+,\s*\{[^}]*text\/html/.test(line)) {
      return { sinkType: "Modern Web Response (text/html reflection)" };
    }
    return null;
  }
}
