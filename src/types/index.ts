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
