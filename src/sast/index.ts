export { SastScanner, isTestFilePath, computeConfidenceScore } from "./engine.js";
export { InterFileTaintAnalyzer } from "./taint-flow.js";
export { RuleRegistry } from "./registry.js";
export { findMatchesInContent, detectLanguage } from "./utils.js";
export {
  ALL_SAST_RULES,
  INJECTION_RULES,
  CRYPTO_RULES,
  AUTH_ACCESS_RULES,
  SSRF_MISCONFIG_RULES,
} from "./rules/index.js";
