export {
  calculateCvssV31,
  DEFAULT_CVSS_MAP,
  type CvssV31Vector,
  type CvssScoreResult,
  type AttackVector,
  type AttackComplexity,
  type PrivilegesRequired,
  type UserInteraction,
  type Scope,
  type CiaImpact,
} from "./cvss.js";

export {
  getComplianceMapping,
  COMPLIANCE_REGISTRY,
  type ComplianceMapping,
} from "./frameworks.js";
