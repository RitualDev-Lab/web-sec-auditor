export interface ComplianceMapping {
  cwe: string;
  cweTitle: string;
  cweTop25Rank?: number;
  owasp: string;
  pciDssV4: string[];
  soc2: string[];
}

export const COMPLIANCE_REGISTRY: Record<string, ComplianceMapping> = {
  "CWE-89": {
    cwe: "CWE-89",
    cweTitle: "Improper Neutralization of Special Elements in an SQL Command ('SQL Injection')",
    cweTop25Rank: 3,
    owasp: "A03:2021-Injection",
    pciDssV4: ["Req 6.2.4 - Injection Protection", "Req 6.3.2 - Code Reviews"],
    soc2: ["CC6.1 - Logical Access Controls", "CC7.1 - Vulnerability Management"],
  },
  "CWE-78": {
    cwe: "CWE-78",
    cweTitle: "Improper Neutralization of Special Elements in an OS Command ('Command Injection')",
    cweTop25Rank: 5,
    owasp: "A03:2021-Injection",
    pciDssV4: ["Req 6.2.4 - Injection Protection"],
    soc2: ["CC6.1 - Access Controls", "CC6.6 - Boundary Protection"],
  },
  "CWE-79": {
    cwe: "CWE-79",
    cweTitle:
      "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
    cweTop25Rank: 2,
    owasp: "A03:2021-Injection",
    pciDssV4: ["Req 6.4.3 - Payment Page Script Management", "Req 6.2.4 - XSS Defense"],
    soc2: ["CC6.6 - Perimeter Defense"],
  },
  "CWE-22": {
    cwe: "CWE-22",
    cweTitle: "Improper Limitation of Pathname to a Restricted Directory ('Path Traversal')",
    cweTop25Rank: 8,
    owasp: "A03:2021-Injection",
    pciDssV4: ["Req 6.2.4 - Directory Traversal Prevention"],
    soc2: ["CC6.1 - Logical Access", "CC6.3 - Data Access Restrictions"],
  },
  "CWE-95": {
    cwe: "CWE-95",
    cweTitle:
      "Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')",
    owasp: "A03:2021-Injection",
    pciDssV4: ["Req 6.2.4 - Code Injection Controls"],
    soc2: ["CC6.6 - System Boundaries"],
  },
  "CWE-918": {
    cwe: "CWE-918",
    cweTitle: "Server-Side Request Forgery (SSRF)",
    cweTop25Rank: 19,
    owasp: "A10:2021-Server-Side Request Forgery",
    pciDssV4: ["Req 6.2.4 - SSRF Mitigation", "Req 1.2 - Network Security Controls"],
    soc2: ["CC6.6 - Boundary Security", "CC6.7 - Transmission Protection"],
  },
  "CWE-798": {
    cwe: "CWE-798",
    cweTitle: "Use of Hard-coded Credentials",
    cweTop25Rank: 18,
    owasp: "A07:2021-Identification and Authentication Failures",
    pciDssV4: ["Req 8.3.1 - Strong Authentication", "Req 3.3.1 - Key Management"],
    soc2: ["CC6.1 - Access Control", "CC6.2 - Credential Management"],
  },
  "CWE-327": {
    cwe: "CWE-327",
    cweTitle: "Use of a Broken or Risky Cryptographic Algorithm",
    owasp: "A02:2021-Cryptographic Failures",
    pciDssV4: ["Req 3.4.1 - Strong Cryptography", "Req 4.1.2 - Transport Encryption"],
    soc2: ["CC6.7 - Data Encryption at Rest and Transit"],
  },
  "CWE-693": {
    cwe: "CWE-693",
    cweTitle: "Protection Mechanism Failure (Missing Security Headers)",
    owasp: "A05:2021-Security Misconfiguration",
    pciDssV4: ["Req 6.4.3 - Browser Script Defense", "Req 4.1.2 - TLS Transport"],
    soc2: ["CC6.6 - Perimeter Defenses"],
  },
  "CWE-922": {
    cwe: "CWE-922",
    cweTitle: "Insecure Storage of Sensitive Information (localStorage / sessionStorage)",
    owasp: "A07:2021-Identification and Authentication Failures",
    pciDssV4: ["Req 3.4.1 - Protection of Cardholder Data in Storage"],
    soc2: ["CC6.1 - Credential Storage Controls"],
  },
};

/**
 * Look up compliance standards (OWASP, PCI-DSS v4.0, SOC 2, CWE Top 25) by CWE or rule ID.
 */
export function getComplianceMapping(cweOrRuleId: string): ComplianceMapping | undefined {
  // Direct CWE match
  if (COMPLIANCE_REGISTRY[cweOrRuleId]) {
    return COMPLIANCE_REGISTRY[cweOrRuleId];
  }

  // If passed rule ID, extract standard CWE
  const upper = cweOrRuleId.toUpperCase();
  if (upper.includes("SQLI")) return COMPLIANCE_REGISTRY["CWE-89"];
  if (upper.includes("CMD")) return COMPLIANCE_REGISTRY["CWE-78"];
  if (upper.includes("XSS")) return COMPLIANCE_REGISTRY["CWE-79"];
  if (upper.includes("PATH")) return COMPLIANCE_REGISTRY["CWE-22"];
  if (upper.includes("EVAL")) return COMPLIANCE_REGISTRY["CWE-95"];
  if (upper.includes("SSRF")) return COMPLIANCE_REGISTRY["CWE-918"];
  if (upper.includes("SECRET") || upper.includes("TOK")) return COMPLIANCE_REGISTRY["CWE-798"];
  if (upper.includes("HASH") || upper.includes("JWT")) return COMPLIANCE_REGISTRY["CWE-327"];
  if (upper.includes("HDR") || upper.includes("CSP")) return COMPLIANCE_REGISTRY["CWE-693"];
  if (upper.includes("STORAGE")) return COMPLIANCE_REGISTRY["CWE-922"];

  return undefined;
}
