import type {
  DastScanReport,
  FindingSeverity,
  SastScanReport,
  ScaScanReport,
  SecretScanReport,
} from "../types/index.js";

export interface SarifRegion {
  startLine: number;
  startColumn?: number;
  snippet?: {
    text: string;
  };
}

export interface SarifArtifactLocation {
  uri: string;
  uriBaseId?: string;
}

export interface SarifPhysicalLocation {
  artifactLocation: SarifArtifactLocation;
  region?: SarifRegion;
}

export interface SarifLocation {
  physicalLocation: SarifPhysicalLocation;
}

export interface SarifMessage {
  text: string;
}

export interface SarifRule {
  id: string;
  name: string;
  shortDescription?: SarifMessage;
  fullDescription?: SarifMessage;
  defaultConfiguration: {
    level: "error" | "warning" | "note";
  };
  help?: {
    text: string;
    markdown?: string;
  };
  properties?: {
    tags?: string[];
    problem?: {
      severity?: string;
    };
  };
}

export interface SarifResult {
  ruleId: string;
  ruleIndex?: number;
  level: "error" | "warning" | "note";
  message: SarifMessage;
  locations?: SarifLocation[];
}

export interface SarifRun {
  tool: {
    driver: {
      name: string;
      version: string;
      informationUri: string;
      rules: SarifRule[];
    };
  };
  results: SarifResult[];
}

export interface SarifLog {
  $schema: string;
  version: "2.1.0";
  runs: SarifRun[];
}

function severityToSarifLevel(severity: FindingSeverity): "error" | "warning" | "note" {
  switch (severity) {
    case "CRITICAL":
    case "HIGH":
      return "error";
    case "MEDIUM":
      return "warning";
    case "LOW":
    case "INFO":
      return "note";
  }
}

export interface GenerateSarifOptions {
  dastReport?: DastScanReport;
  sastReport?: SastScanReport;
  secretReport?: SecretScanReport;
  scaReport?: ScaScanReport;
}

/**
 * Generates an OASIS SARIF v2.1.0 compliant log from auditor findings.
 */
export function generateSarifReport(options: GenerateSarifOptions): SarifLog {
  const rulesMap = new Map<string, SarifRule>();
  const results: SarifResult[] = [];

  // 1. Process SAST findings
  if (options.sastReport) {
    for (const f of options.sastReport.findings) {
      if (!rulesMap.has(f.ruleId)) {
        rulesMap.set(f.ruleId, {
          id: f.ruleId,
          name: f.title,
          shortDescription: { text: f.title },
          fullDescription: { text: f.description },
          defaultConfiguration: {
            level: severityToSarifLevel(f.severity),
          },
          help: {
            text: f.remediation,
            markdown: `### Remediation\n\n${f.remediation}\n\n- **CWE**: ${f.cwe}\n- **OWASP**: ${f.owasp}`,
          },
          properties: {
            tags: ["security", f.cwe, f.owasp, "sast"],
          },
        });
      }

      results.push({
        ruleId: f.ruleId,
        level: severityToSarifLevel(f.severity),
        message: {
          text: `${f.title}: ${f.description}`,
        },
        locations: [
          {
            physicalLocation: {
              artifactLocation: {
                uri: f.file.replace(/\\/g, "/"),
              },
              region: {
                startLine: f.line,
                startColumn: f.column,
                snippet: {
                  text: f.snippet,
                },
              },
            },
          },
        ],
      });
    }
  }

  // 2. Process Secret findings
  if (options.secretReport) {
    for (const s of options.secretReport.findings) {
      if (!rulesMap.has(s.patternId)) {
        rulesMap.set(s.patternId, {
          id: s.patternId,
          name: s.title,
          shortDescription: { text: s.title },
          defaultConfiguration: {
            level: severityToSarifLevel(s.severity),
          },
          help: {
            text: s.remediation,
            markdown: `### Remediation\n\n${s.remediation}\n\n- **Entropy**: ${s.entropy}`,
          },
          properties: {
            tags: ["security", "secrets", "credentials"],
          },
        });
      }

      results.push({
        ruleId: s.patternId,
        level: severityToSarifLevel(s.severity),
        message: {
          text: `Exposed ${s.title}: ${s.maskedSecret}`,
        },
        locations: [
          {
            physicalLocation: {
              artifactLocation: {
                uri: s.file.replace(/\\/g, "/"),
              },
              region: {
                startLine: s.line,
                startColumn: s.column,
                snippet: {
                  text: s.snippet,
                },
              },
            },
          },
        ],
      });
    }
  }

  // 3. Process SCA findings
  if (options.scaReport) {
    for (const sca of options.scaReport.findings) {
      if (!rulesMap.has(sca.id)) {
        rulesMap.set(sca.id, {
          id: sca.id,
          name: sca.title,
          shortDescription: { text: sca.title },
          fullDescription: { text: sca.description },
          defaultConfiguration: {
            level: severityToSarifLevel(sca.severity),
          },
          help: {
            text: sca.remediation,
            markdown: `### Remediation\n\n${sca.remediation}\n\n- **Advisory**: ${sca.advisoryUrl || "N/A"}`,
          },
          properties: {
            tags: ["security", "sca", "dependencies"],
          },
        });
      }

      results.push({
        ruleId: sca.id,
        level: severityToSarifLevel(sca.severity),
        message: {
          text: `Vulnerable dependency ${sca.packageName}@${sca.currentVersion}: ${sca.title}`,
        },
        locations: [
          {
            physicalLocation: {
              artifactLocation: {
                uri: options.scaReport.manifestPath.replace(/\\/g, "/"),
              },
            },
          },
        ],
      });
    }
  }

  // 4. Process DAST findings
  if (options.dastReport) {
    for (const d of options.dastReport.findings) {
      if (!rulesMap.has(d.id)) {
        rulesMap.set(d.id, {
          id: d.id,
          name: d.title,
          shortDescription: { text: d.title },
          fullDescription: { text: d.description },
          defaultConfiguration: {
            level: severityToSarifLevel(d.severity),
          },
          help: {
            text: d.remediation,
          },
          properties: {
            tags: ["security", "dast", d.cwe || "CWE-693"],
          },
        });
      }

      results.push({
        ruleId: d.id,
        level: severityToSarifLevel(d.severity),
        message: {
          text: `${d.title} on ${options.dastReport.targetUrl}: ${d.description}`,
        },
        locations: [
          {
            physicalLocation: {
              artifactLocation: {
                uri: options.dastReport.targetUrl,
              },
            },
          },
        ],
      });
    }
  }

  return {
    $schema:
      "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "WebSecAuditor",
            version: "1.0.0",
            informationUri: "https://github.com/RitualDev-Lab/web-sec-auditor",
            rules: Array.from(rulesMap.values()),
          },
        },
        results,
      },
    ],
  };
}
