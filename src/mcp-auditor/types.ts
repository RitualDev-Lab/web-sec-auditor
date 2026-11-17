export type McpSecurityGrade = 'A+' | 'A' | 'B' | 'C' | 'D' | 'F';

export interface McpToolParameter {
  name: string;
  type: string;
  description?: string;
  required?: boolean;
}

export interface McpToolDefinition {
  name: string;
  description: string;
  parameters: McpToolParameter[];
}

export interface McpServerProfile {
  id: string;
  name: string;
  vendor: string;
  category: 'Developer Tools' | 'Cloud & DevOps' | 'Database & Storage' | 'Filesystem & OS' | 'Productivity' | 'Search & Web';
  repository: string;
  downloadsWeekly: number;
  tools: McpToolDefinition[];
  hasSandboxing: boolean;
  hasRateLimiting: boolean;
}

export interface McpAuditFinding {
  ruleId: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  title: string;
  cwe: string;
  owaspLlm: string;
  toolName?: string;
  description: string;
  remediation: string;
}

export interface McpAuditResult {
  serverId: string;
  serverName: string;
  vendor: string;
  category: string;
  repository: string;
  grade: McpSecurityGrade;
  securityScore: number; // 0 - 100
  findings: McpAuditFinding[];
  summary: string;
}

export interface McpEcosystemReport {
  generatedAt: string;
  totalServersAudited: number;
  averageScore: number;
  gradeDistribution: Record<McpSecurityGrade, number>;
  topCwes: { cwe: string; count: number; description: string }[];
  servers: McpAuditResult[];
}
