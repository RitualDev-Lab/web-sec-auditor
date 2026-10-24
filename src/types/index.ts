export type FindingSeverity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";

export type SecurityGrade = "A+" | "A" | "B" | "C" | "D" | "F";

export type FindingCategory =
  | "HEADERS"
  | "COOKIES"
  | "CORS"
  | "TLS"
  | "DISCLOSURE"
  | "INJECTION"
  | "AUTH"
  | "SECRETS"
  | "SCA";

export interface SecurityFinding {
  id: string; // e.g. "SEC-HDR-001"
  category: FindingCategory;
  title: string;
  severity: FindingSeverity;
  scoreImpact: number; // e.g. -20
  cwe?: string; // e.g. "CWE-693"
  owasp?: string; // e.g. "A05:2021-Security Misconfiguration"
  description: string;
  evidence?: string;
  remediation: string;
  references?: string[];
}

export type HeaderStatus = "OPTIMAL" | "SUBOPTIMAL" | "MISSING" | "DANGEROUS";

export interface HeaderAuditItem {
  name: string;
  present: boolean;
  value?: string;
  status: HeaderStatus;
  issues: string[];
  recommendation?: string;
}

export interface CookieAuditItem {
  name: string;
  value: string;
  secure: boolean;
  httpOnly: boolean;
  sameSite?: "Strict" | "Lax" | "None" | string;
  raw: string;
  issues: string[];
}

export interface CorsAuditResult {
  allowedOrigin?: string;
  allowsCredentials?: boolean;
  allowedMethods?: string[];
  allowedHeaders?: string[];
  isWildcardWithCredentials: boolean;
  issues: string[];
  status: "SAFE" | "WARN" | "CRITICAL";
}

export interface TlsAuditResult {
  isHttps: boolean;
  certificateValid?: boolean;
  issuer?: string;
  validTo?: string;
  daysRemaining?: number;
  redirectsToHttps: boolean;
  redirectHops: string[];
  issues: string[];
}

export interface DastScanReport {
  targetUrl: string;
  finalUrl: string;
  scanTimestamp: string;
  statusCode: number;
  responseTimeMs: number;
  grade: SecurityGrade;
  score: number; // 0 to 100
  summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
  headers: HeaderAuditItem[];
  cookies: CookieAuditItem[];
  cors: CorsAuditResult;
  tls: TlsAuditResult;
  findings: SecurityFinding[];
}

export interface DastScanOptions {
  timeoutMs?: number; // default: 10000ms
  userAgent?: string;
  followRedirects?: boolean;
  checkTlsCert?: boolean;
  customHeaders?: Record<string, string>;
}

export type SupportedLanguage = "typescript" | "javascript" | "python" | "go" | "all";

export interface RuleMatch {
  line: number;
  column: number;
  snippet: string;
  evidence?: string;
}

export interface SastRule {
  id: string;
  name: string;
  category: FindingCategory;
  severity: FindingSeverity;
  cwe: string;
  owasp: string;
  description: string;
  remediation: string;
  languages: SupportedLanguage[];
  evaluate(content: string, filePath: string): RuleMatch[];
}

export interface SastFinding {
  id: string;
  ruleId: string;
  category: FindingCategory;
  title: string;
  severity: FindingSeverity;
  cwe: string;
  owasp: string;
  file: string;
  line: number;
  column: number;
  snippet: string;
  description: string;
  remediation: string;
  cvssScore?: number;
  cvssVector?: string;
  compliance?: {
    cweTop25Rank?: number;
    pciDss?: string[];
    soc2?: string[];
  };
  patch?: {
    diff: string;
    explanation: string;
  };
}

export interface SastScanReport {
  targetPath: string;
  filesScanned: number;
  scanTimestamp: string;
  durationMs: number;
  summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
  findings: SastFinding[];
}

export interface SastScanOptions {
  threshold?: FindingSeverity;
  languages?: SupportedLanguage[];
  excludeDirs?: string[];
  maxFileSizeKb?: number;
}

// ─── Phase 3: Secret Detection Types ─────────────────────────

export interface SecretPattern {
  id: string;
  name: string;
  category: "SECRETS";
  severity: FindingSeverity;
  description: string;
  regex: RegExp;
  minEntropy?: number;
  mask(match: string): string;
}

export interface SecretFinding {
  id: string;
  patternId: string;
  title: string;
  severity: FindingSeverity;
  file: string;
  line: number;
  column: number;
  maskedSecret: string;
  entropy: number;
  snippet: string;
  remediation: string;
  commitHash?: string;
  commitAuthor?: string;
}

export interface SecretScanReport {
  targetPath: string;
  filesScanned: number;
  commitsScanned?: number;
  scanTimestamp: string;
  durationMs: number;
  summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
  findings: SecretFinding[];
}

export interface SecretScanOptions {
  minEntropy?: number;
  scanGitHistory?: boolean;
  maxCommits?: number;
  excludeDirs?: string[];
  maxFileSizeKb?: number;
}

// ─── Phase 3: Software Composition Analysis (SCA) Types ──────

export interface PackageDependency {
  name: string;
  version: string;
  isDev: boolean;
}

export interface ScaFinding {
  id: string;
  packageName: string;
  currentVersion: string;
  vulnerableRange?: string;
  patchedVersion?: string;
  severity: FindingSeverity;
  cvssScore?: number;
  title: string;
  description: string;
  advisoryUrl?: string;
  remediation: string;
}

export interface ScaScanReport {
  manifestPath: string;
  ecosystem: string;
  totalDependencies: number;
  vulnerableDependencies: number;
  scanTimestamp: string;
  durationMs: number;
  summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
  findings: ScaFinding[];
}

export interface ScaScanOptions {
  includeDev?: boolean;
  threshold?: FindingSeverity;
  timeoutMs?: number;
}
