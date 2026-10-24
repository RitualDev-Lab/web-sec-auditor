import type { SastRule } from "../../types/index.js";
import { authAccessRules } from "./auth-access.js";
import { cryptoRules } from "./crypto.js";
import { injectionRules } from "./injection.js";
import { ssrfMisconfigRules } from "./ssrf-misconfig.js";

export * from "./injection.js";
export * from "./crypto.js";
export * from "./auth-access.js";
export * from "./ssrf-misconfig.js";

export const INJECTION_RULES = injectionRules;
export const CRYPTO_RULES = cryptoRules;
export const AUTH_ACCESS_RULES = authAccessRules;
export const SSRF_MISCONFIG_RULES = ssrfMisconfigRules;

export const ALL_SAST_RULES: SastRule[] = [
  ...injectionRules,
  ...cryptoRules,
  ...authAccessRules,
  ...ssrfMisconfigRules,
];
