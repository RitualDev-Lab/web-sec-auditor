import type { FindingSeverity, SecurityFinding, SecurityGrade } from "../types/index.js";

export interface ScoreCalculationResult {
  score: number; // 0 to 100
  grade: SecurityGrade;
  summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
}

export function calculateSecurityScore(findings: SecurityFinding[]): ScoreCalculationResult {
  let score = 100;
  const summary = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };

  for (const f of findings) {
    switch (f.severity) {
      case "CRITICAL":
        summary.critical++;
        break;
      case "HIGH":
        summary.high++;
        break;
      case "MEDIUM":
        summary.medium++;
        break;
      case "LOW":
        summary.low++;
        break;
      case "INFO":
        summary.info++;
        break;
    }
    score -= f.scoreImpact;
  }

  // Enforcement of severity ceilings:
  // Any CRITICAL finding automatically caps score at 39 (Grade F)
  if (summary.critical > 0) {
    score = Math.min(score, 39);
  } else if (summary.high > 0) {
    // Any HIGH finding caps score at 69 (Grade C max)
    score = Math.min(score, 69);
  } else if (summary.medium > 2) {
    // Multiple medium findings cap score at 79 (Grade B max)
    score = Math.min(score, 79);
  }

  score = Math.max(0, Math.min(100, Math.round(score)));

  let grade: SecurityGrade = "F";
  if (score >= 95) grade = "A+";
  else if (score >= 85) grade = "A";
  else if (score >= 70) grade = "B";
  else if (score >= 55) grade = "C";
  else if (score >= 40) grade = "D";
  else grade = "F";

  return { score, grade, summary };
}
