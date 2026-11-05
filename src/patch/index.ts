export { PatchEngine, generateUnifiedDiff, type AutoPatchRecipe } from "./engine.js";
export { generateRemediation, type PatchReplacement } from "./templates.js";
export {
  SignedRemediationEngine,
  type SignedRemediationOptions,
  type SignedRemediationPatch,
  type SignedPrPayload,
} from "./remediation-engine.js";
