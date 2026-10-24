import type { FindingSeverity, SastRule, SupportedLanguage } from "../types/index.js";
import { ALL_SAST_RULES } from "./rules/index.js";

const SEVERITY_WEIGHTS: Record<FindingSeverity, number> = {
  CRITICAL: 5,
  HIGH: 4,
  MEDIUM: 3,
  LOW: 2,
  INFO: 1,
};

export class RuleRegistry {
  private rules: Map<string, SastRule> = new Map();

  constructor(initialRules: SastRule[] = ALL_SAST_RULES) {
    for (const r of initialRules) {
      this.register(r);
    }
  }

  public register(rule: SastRule): void {
    this.rules.set(rule.id, rule);
  }

  public getRule(id: string): SastRule | undefined {
    return this.rules.get(id);
  }

  public getAllRules(): SastRule[] {
    return Array.from(this.rules.values());
  }

  public getRulesForLanguage(lang: SupportedLanguage, threshold?: FindingSeverity): SastRule[] {
    return this.getAllRules().filter((rule) => {
      // 1. Language filter
      const langMatch = rule.languages.includes("all") || rule.languages.includes(lang);
      if (!langMatch) return false;

      // 2. Severity threshold filter
      if (threshold) {
        const ruleWeight = SEVERITY_WEIGHTS[rule.severity];
        const threshWeight = SEVERITY_WEIGHTS[threshold];
        if (ruleWeight < threshWeight) return false;
      }

      return true;
    });
  }
}
