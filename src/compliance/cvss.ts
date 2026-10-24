import type { FindingSeverity } from "../types/index.js";

export type AttackVector = "NETWORK" | "ADJACENT" | "LOCAL" | "PHYSICAL";
export type AttackComplexity = "LOW" | "HIGH";
export type PrivilegesRequired = "NONE" | "LOW" | "HIGH";
export type UserInteraction = "NONE" | "REQUIRED";
export type Scope = "UNCHANGED" | "CHANGED";
export type CiaImpact = "NONE" | "LOW" | "HIGH";

export interface CvssV31Vector {
  attackVector: AttackVector;
  attackComplexity: AttackComplexity;
  privilegesRequired: PrivilegesRequired;
  userInteraction: UserInteraction;
  scope: Scope;
  confidentiality: CiaImpact;
  integrity: CiaImpact;
  availability: CiaImpact;
}

export interface CvssScoreResult {
  baseScore: number;
  severity: FindingSeverity;
  vectorString: string;
  exploitabilitySubscore: number;
  impactSubscore: number;
}

const AV_VALUES: Record<AttackVector, number> = {
  NETWORK: 0.85,
  ADJACENT: 0.62,
  LOCAL: 0.55,
  PHYSICAL: 0.2,
};

const AC_VALUES: Record<AttackComplexity, number> = {
  LOW: 0.77,
  HIGH: 0.44,
};

const PR_UNCHANGED: Record<PrivilegesRequired, number> = {
  NONE: 0.85,
  LOW: 0.62,
  HIGH: 0.27,
};

const PR_CHANGED: Record<PrivilegesRequired, number> = {
  NONE: 0.85,
  LOW: 0.68,
  HIGH: 0.5,
};

const UI_VALUES: Record<UserInteraction, number> = {
  NONE: 0.85,
  REQUIRED: 0.62,
};

const CIA_VALUES: Record<CiaImpact, number> = {
  NONE: 0.0,
  LOW: 0.22,
  HIGH: 0.56,
};

/**
 * CVSS v3.1 round up function: smallest number to one decimal place >= input.
 */
function roundUp(input: number): number {
  return Math.ceil(Math.round(input * 100000) / 10000) / 10;
}

/**
 * Calculate CVSS v3.1 Base Score, Exploitability, and Impact according to official FIRST specification.
 */
export function calculateCvssV31(vector: CvssV31Vector): CvssScoreResult {
  const av = AV_VALUES[vector.attackVector];
  const ac = AC_VALUES[vector.attackComplexity];
  const pr =
    vector.scope === "CHANGED"
      ? PR_CHANGED[vector.privilegesRequired]
      : PR_UNCHANGED[vector.privilegesRequired];
  const ui = UI_VALUES[vector.userInteraction];

  const c = CIA_VALUES[vector.confidentiality];
  const i = CIA_VALUES[vector.integrity];
  const a = CIA_VALUES[vector.availability];

  // 1. Calculate ISS (Impact Sub Score Base)
  const iss = 1 - (1 - c) * (1 - i) * (1 - a);

  // 2. Calculate Impact
  let impact: number;
  if (vector.scope === "UNCHANGED") {
    impact = 6.42 * iss;
  } else {
    impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15;
  }

  // 3. Calculate Exploitability
  const exploitability = 8.22 * av * ac * pr * ui;

  // 4. Calculate Base Score
  let baseScore = 0;
  if (impact > 0) {
    if (vector.scope === "UNCHANGED") {
      baseScore = roundUp(Math.min(impact + exploitability, 10));
    } else {
      baseScore = roundUp(Math.min(1.08 * (impact + exploitability), 10));
    }
  }

  // 5. Severity mapping
  let severity: FindingSeverity = "INFO";
  if (baseScore >= 9.0) severity = "CRITICAL";
  else if (baseScore >= 7.0) severity = "HIGH";
  else if (baseScore >= 4.0) severity = "MEDIUM";
  else if (baseScore > 0.0) severity = "LOW";

  // 6. Vector string format
  const avCode = vector.attackVector[0];
  const acCode = vector.attackComplexity[0];
  const prCode = vector.privilegesRequired[0];
  const uiCode = vector.userInteraction[0];
  const sCode = vector.scope[0];
  const cCode = vector.confidentiality[0];
  const iCode = vector.integrity[0];
  const aCode = vector.availability[0];

  const vectorString = `CVSS:3.1/AV:${avCode}/AC:${acCode}/PR:${prCode}/UI:${uiCode}/S:${sCode}/C:${cCode}/I:${iCode}/A:${aCode}`;

  return {
    baseScore: Number(baseScore.toFixed(1)),
    severity,
    vectorString,
    exploitabilitySubscore: Number(exploitability.toFixed(1)),
    impactSubscore: Number(impact.toFixed(1)),
  };
}

/**
 * Pre-configured CVSS v3.1 vectors for standard vulnerability classes.
 */
export const DEFAULT_CVSS_MAP: Record<string, CvssV31Vector> = {
  "SEC-INJ-SQLI": {
    attackVector: "NETWORK",
    attackComplexity: "LOW",
    privilegesRequired: "NONE",
    userInteraction: "NONE",
    scope: "UNCHANGED",
    confidentiality: "HIGH",
    integrity: "HIGH",
    availability: "HIGH",
  },
  "SEC-INJ-CMD": {
    attackVector: "NETWORK",
    attackComplexity: "LOW",
    privilegesRequired: "NONE",
    userInteraction: "NONE",
    scope: "CHANGED",
    confidentiality: "HIGH",
    integrity: "HIGH",
    availability: "HIGH",
  },
  "SEC-INJ-PATH": {
    attackVector: "NETWORK",
    attackComplexity: "LOW",
    privilegesRequired: "NONE",
    userInteraction: "NONE",
    scope: "UNCHANGED",
    confidentiality: "HIGH",
    integrity: "NONE",
    availability: "NONE",
  },
  "SEC-INJ-XSS": {
    attackVector: "NETWORK",
    attackComplexity: "LOW",
    privilegesRequired: "NONE",
    userInteraction: "REQUIRED",
    scope: "CHANGED",
    confidentiality: "LOW",
    integrity: "LOW",
    availability: "NONE",
  },
  "SEC-CRYP-JWT-NONE": {
    attackVector: "NETWORK",
    attackComplexity: "LOW",
    privilegesRequired: "NONE",
    userInteraction: "NONE",
    scope: "UNCHANGED",
    confidentiality: "HIGH",
    integrity: "HIGH",
    availability: "NONE",
  },
  "SEC-SSRF-UNVALIDATED": {
    attackVector: "NETWORK",
    attackComplexity: "LOW",
    privilegesRequired: "NONE",
    userInteraction: "NONE",
    scope: "CHANGED",
    confidentiality: "HIGH",
    integrity: "LOW",
    availability: "NONE",
  },
  "SEC-TOK-AWS-KEY": {
    attackVector: "NETWORK",
    attackComplexity: "LOW",
    privilegesRequired: "NONE",
    userInteraction: "NONE",
    scope: "CHANGED",
    confidentiality: "HIGH",
    integrity: "HIGH",
    availability: "HIGH",
  },
};
