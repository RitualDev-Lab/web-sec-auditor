import type { McpServerProfile, McpAuditFinding, McpAuditResult, McpSecurityGrade } from './types.js';

export class McpSecurityScanner {
  public auditServer(server: McpServerProfile): McpAuditResult {
    const findings: McpAuditFinding[] = [];
    let score = 100;

    // Rule 1: Command Execution / Excessive Agency (CWE-78 / LLM06)
    for (const tool of server.tools) {
      const isExecTool = /(execute|exec|run_command|shell|terminal|eval|system_cmd)/i.test(tool.name);
      const hasCommandParam = tool.parameters.some((p) => /(command|cmd|shell_script|cli_command|eval)/i.test(p.name));

      if ((isExecTool || hasCommandParam) && !server.hasSandboxing) {
        findings.push({
          ruleId: 'MCP-001',
          severity: 'critical',
          title: 'Unconstrained Host Command Execution',
          cwe: 'CWE-78',
          owaspLlm: 'LLM06: Excessive Agency',
          toolName: tool.name,
          description: `Tool allows raw shell command execution without AgentShield/eBPF kernel isolation.`,
          remediation: `Confine command execution using AgentShield Linux eBPF/Zygote sandbox or restrict to allowlisted binaries.`
        });
        score -= 65; // Critical failure automatically drops to Grade F
      }

      // Rule 2: Arbitrary Filesystem Traversal (CWE-22 / LLM02)
      const hasFilePathParam = tool.parameters.some((p) => /(filepath|path|directory|filename|dest)/i.test(p.name));
      if (hasFilePathParam && !server.hasSandboxing) {
        findings.push({
          ruleId: 'MCP-002',
          severity: 'high',
          title: 'Unrestricted Filesystem Path Traversal',
          cwe: 'CWE-22',
          owaspLlm: 'LLM02: Sensitive Information Disclosure',
          toolName: tool.name,
          description: `Tool accepts arbitrary paths without boundary checking or chroot isolation.`,
          remediation: `Enforce canonicalized path resolution against allowed root directories (chroot / Landlock).`
        });
        score -= 20;
      }

      // Rule 3: SSRF / Cloud Metadata Probing (CWE-918 / LLM02)
      const isNetworkTool = /(fetch|curl|http|request|webhook|browse|scrape)/i.test(tool.name);
      const hasUrlParam = tool.parameters.some((p) => /(url|endpoint|uri|target_url)/i.test(p.name));
      if (isNetworkTool || hasUrlParam) {
        findings.push({
          ruleId: 'MCP-003',
          severity: 'critical',
          title: 'Potential Server-Side Request Forgery (SSRF) & IMDS Leak',
          cwe: 'CWE-918',
          owaspLlm: 'LLM02: Sensitive Information Disclosure',
          toolName: tool.name,
          description: `Network request tool does not explicitly filter AWS/GCP IMDS (169.254.169.254) or RFC 1918 private IPs.`,
          remediation: `Implement DNS pinning and blocklist link-local (169.254.0.0/16) and localhost (127.0.0.1) addresses.`
        });
        score -= 30;
      }

      // Rule 4: Raw SQL Query Execution (CWE-89 / LLM06)
      const isSqlTool = /(query|sql|database|execute_sql)/i.test(tool.name);
      const hasQueryParam = tool.parameters.some((p) => /(query|sql|statement)/i.test(p.name));
      if (isSqlTool || hasQueryParam) {
        findings.push({
          ruleId: 'MCP-004',
          severity: 'high',
          title: 'Direct Unchecked SQL Execution Without Wire Proxy',
          cwe: 'CWE-89',
          owaspLlm: 'LLM06: Excessive Agency',
          toolName: tool.name,
          description: `Database tool executes raw SQL strings without DBShield wire-level dry-run or rollback defenses.`,
          remediation: `Deploy DBShield wire proxy with instant rollback on unconstrained DROP/TRUNCATE/UPDATE statements.`
        });
        score -= 25;
      }

      // Rule 5: Indirect Prompt Injection in Tool Description (CWE-1426 / LLM01)
      if (/(system|override|ignore previous|always grant|superadmin)/i.test(tool.description)) {
        findings.push({
          ruleId: 'MCP-005',
          severity: 'high',
          title: 'Suspicious / Poisoned Tool Description',
          cwe: 'CWE-1426',
          owaspLlm: 'LLM01: Prompt Injection',
          toolName: tool.name,
          description: `Tool description contains prompt-altering keywords capable of hijacking the LLM agent instruction stack.`,
          remediation: `Sanitize MCP tool descriptions and enforce deterministic schema evaluation.`
        });
        score -= 20;
      }
    }

    // Rule 6: Missing Rate Limiting / DoS (CWE-400)
    if (!server.hasRateLimiting) {
      findings.push({
        ruleId: 'MCP-006',
        severity: 'medium',
        title: 'Lack of Tool Invocation Rate Limiting',
        cwe: 'CWE-400',
        owaspLlm: 'LLM04: Model Denial of Service',
        description: `Server does not implement token bucket or concurrency caps, risking upstream quota exhaustion.`,
        remediation: `Apply mcp-monetize or edge clearinghouse rate-limiting gates.`
      });
      score -= 10;
    }

    // Clamp score
    score = Math.max(0, Math.min(100, score));

    let grade: McpSecurityGrade = 'A';
    if (score >= 95) grade = 'A+';
    else if (score >= 85) grade = 'A';
    else if (score >= 70) grade = 'B';
    else if (score >= 55) grade = 'C';
    else if (score >= 40) grade = 'D';
    else grade = 'F';

    return {
      serverId: server.id,
      serverName: server.name,
      vendor: server.vendor,
      category: server.category,
      repository: server.repository,
      grade,
      securityScore: score,
      findings,
      summary: `Audited ${server.tools.length} tools. Detected ${findings.length} findings (${findings.filter(f => f.severity === 'critical').length} critical). Overall Security Grade: ${grade} (${score}/100).`
    };
  }
}
