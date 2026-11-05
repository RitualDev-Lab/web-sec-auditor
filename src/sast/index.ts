export { SastScanner, isTestFilePath, computeConfidenceScore } from "./engine.js";
export { InterFileTaintAnalyzer } from "./taint-flow.js";
export {
  WholeProgramCpgAnalyzer,
  CodePropertyGraph,
  type CpgFinding,
  type CpgNode,
  type CpgEdge,
  type CpgNodeType,
  type CpgEdgeType,
  type CpgTraceStep,
} from "./cpg-analyzer.js";
export { RuleRegistry } from "./registry.js";
export { findMatchesInContent, detectLanguage } from "./utils.js";
export {
  ALL_SAST_RULES,
  INJECTION_RULES,
  CRYPTO_RULES,
  AUTH_ACCESS_RULES,
  SSRF_MISCONFIG_RULES,
} from "./rules/index.js";
