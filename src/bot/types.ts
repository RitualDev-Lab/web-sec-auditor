import type { FindingSeverity, SastFinding, ScaFinding, SecretFinding } from "../types/index.js";

export type BotSeverityGate = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "NONE";

export interface BotConfig {
  port?: number;
  webhookSecret?: string;
  appId?: string;
  privateKey?: string;
  githubToken?: string;
  autoPatchOnCritical?: boolean;
  failOnSeverity?: BotSeverityGate;
  baseUrl?: string;
}

export interface WebhookHeaders {
  "x-github-event"?: string;
  "x-github-delivery"?: string;
  "x-hub-signature-256"?: string;
  [key: string]: string | undefined;
}

export interface GitHubRepositoryRef {
  id: number;
  name: string;
  full_name: string;
  owner: {
    login: string;
    id: number;
  };
  private: boolean;
  html_url: string;
  default_branch: string;
}

export interface GitHubPullRequestRef {
  number: number;
  title: string;
  state: "open" | "closed";
  html_url: string;
  diff_url: string;
  head: {
    ref: string;
    sha: string;
    repo: GitHubRepositoryRef;
  };
  base: {
    ref: string;
    sha: string;
    repo: GitHubRepositoryRef;
  };
  user: {
    login: string;
  };
}

export interface GitHubWebhookPayload {
  action: string;
  repository?: GitHubRepositoryRef;
  pull_request?: GitHubPullRequestRef;
  sender?: {
    login: string;
    type: string;
  };
  installation?: {
    id: number;
  };
  comment?: {
    id: number;
    body: string;
    user: {
      login: string;
    };
    html_url: string;
  };
  check_run?: {
    id: number;
    head_sha: string;
    name: string;
  };
  issue?: {
    number: number;
    pull_request?: {
      url: string;
      html_url?: string;
      diff_url?: string;
    };
  };
}

export interface DiffLineRange {
  oldStart: number;
  oldCount: number;
  newStart: number;
  newCount: number;
}

export interface ParsedDiffFile {
  oldPath: string;
  newPath: string;
  status: "added" | "modified" | "deleted";
  addedLines: number[]; // 1-based line numbers in the new file
  hunks: Array<{
    header: string;
    lines: string[];
    range: DiffLineRange;
  }>;
}

export type AnyAuditFinding = (SastFinding | SecretFinding | ScaFinding) & {
  findingType: "SAST" | "SECRETS" | "SCA";
};

export interface CheckRunAnnotation {
  path: string;
  start_line: number;
  end_line: number;
  annotation_level: "notice" | "warning" | "failure";
  title: string;
  message: string;
  raw_details?: string;
}

export interface CheckRunOutput {
  title: string;
  summary: string;
  text?: string;
  annotations: CheckRunAnnotation[];
}

export interface PrScanSummary {
  owner: string;
  repo: string;
  prNumber: number;
  headSha: string;
  filesScanned: number;
  linesAnalyzed: number;
  findings: AnyAuditFinding[];
  passedGate: boolean;
  failOnLevel: BotSeverityGate;
  counts: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
  patchableCount: number;
  scanDurationMs: number;
}

export interface PatchPrResult {
  success: boolean;
  branchName: string;
  commitSha?: string;
  patchPrNumber?: number;
  patchPrUrl?: string;
  filesPatched: string[];
  unifiedDiff: string;
  error?: string;
}
