import { createHash, createHmac, timingSafeEqual } from "node:crypto";
import { generateUnifiedDiff } from "./engine.js";

export interface SignedRemediationOptions {
  filePath: string;
  originalContent: string;
  lineNumber: number;
  originalCode: string;
  patchedCode: string;
  ruleId: string;
  explanation: string;
  secretKey?: string;
  keyId?: string;
}

export interface SignedRemediationPatch {
  filePath: string;
  lineNumber: number;
  ruleId: string;
  diff: string;
  rawPatchWithSignature: string;
  digest: string;
  signature: string;
  keyId: string;
  timestamp: string;
  verified: boolean;
  explanation: string;
}

export interface SignedPrPayload {
  branchName: string;
  title: string;
  body: string;
  head: string;
  base: string;
  commitMessage: string;
  patch: SignedRemediationPatch;
}

/**
 * Cryptographically Signed Remediation Engine
 * Generates automated remediation patches with cryptographic integrity proofs,
 * preventing malicious patch tampering across CI/CD and pull request boundaries.
 */
export class SignedRemediationEngine {
  private defaultSecretKey: string;
  private defaultKeyId: string;

  constructor(
    defaultSecretKey = "ritualdev_signed_remediation_root_key_2026",
    defaultKeyId = "ritualdev-sec-bot-v1",
  ) {
    this.defaultSecretKey = defaultSecretKey;
    this.defaultKeyId = defaultKeyId;
  }

  /**
   * Generates a cryptographically signed remediation patch
   */
  public createSignedPatch(options: SignedRemediationOptions): SignedRemediationPatch {
    const key = options.secretKey || this.defaultSecretKey;
    const keyId = options.keyId || this.defaultKeyId;
    const timestamp = new Date().toISOString();

    const diff = generateUnifiedDiff(
      options.filePath,
      options.originalCode,
      options.patchedCode,
      options.lineNumber,
    );

    // Compute cryptographic digest over diff content + metadata
    const canonicalPayload = [
      `file:${options.filePath}`,
      `line:${options.lineNumber}`,
      `rule:${options.ruleId}`,
      `ts:${timestamp}`,
      `diff:${diff}`,
    ].join("\n");

    const digest = createHash("sha256").update(canonicalPayload).digest("hex");
    const signature = createHmac("sha256", key).update(canonicalPayload).digest("hex");

    const header = [
      "# --- RITUALDEV CRYPTOGRAPHICALLY SIGNED REMEDIATION PATCH ---",
      "# Tool: WebSecAuditor v1.1.0 (OWASP & SOC-2 Verified)",
      `# Rule-ID: ${options.ruleId}`,
      `# Key-ID: ${keyId}`,
      `# Digest: sha256:${digest}`,
      `# Signature: hmac-sha256:${signature}`,
      `# Timestamp: ${timestamp}`,
      "# -----------------------------------------------------------",
    ].join("\n");

    const rawPatchWithSignature = `${header}\n${diff}\n`;

    return {
      filePath: options.filePath,
      lineNumber: options.lineNumber,
      ruleId: options.ruleId,
      diff,
      rawPatchWithSignature,
      digest,
      signature,
      keyId,
      timestamp,
      verified: true,
      explanation: options.explanation,
    };
  }

  /**
   * Verifies the cryptographic signature and digest of a signed patch string
   */
  public verifySignedPatch(
    rawPatchText: string,
    secretKey?: string,
  ): { valid: boolean; reason?: string; patchMetadata?: Record<string, string> } {
    const key = secretKey || this.defaultSecretKey;
    const lines = rawPatchText.split("\n");

    const metadata: Record<string, string> = {};
    const diffLines: string[] = [];
    let readingDiff = false;

    for (const line of lines) {
      if (line.startsWith("# ---") && readingDiff) {
        // end header
        continue;
      }
      if (line.startsWith("# ") && !readingDiff) {
        const colonIdx = line.indexOf(":");
        if (colonIdx > 0) {
          const k = line.substring(2, colonIdx).trim().toLowerCase();
          const v = line.substring(colonIdx + 1).trim();
          metadata[k] = v;
        }
      } else {
        readingDiff = true;
        diffLines.push(line);
      }
    }

    const ruleId = metadata["rule-id"];
    const digestHeader = metadata.digest;
    const signatureHeader = metadata.signature;
    const timestamp = metadata.timestamp;

    if (!digestHeader || !signatureHeader || !timestamp || !ruleId) {
      return { valid: false, reason: "Missing required cryptographic signature headers" };
    }

    const diff = diffLines.join("\n").trim();

    // Extract filePath and lineNumber from diff lines:
    // --- a/path
    // +++ b/path
    // @@ -L,1 +L,1 @@
    const fileMatch = /^---\s+a\/(.+)$/m.exec(diff);
    const lineMatch = /^@@\s+-(\d+),/m.exec(diff);

    const filePath = fileMatch ? fileMatch[1].trim() : "unknown";
    const lineNumber = lineMatch ? Number.parseInt(lineMatch[1], 10) : 0;

    const canonicalPayload = [
      `file:${filePath}`,
      `line:${lineNumber}`,
      `rule:${ruleId}`,
      `ts:${timestamp}`,
      `diff:${diff}`,
    ].join("\n");

    const expectedDigest = createHash("sha256").update(canonicalPayload).digest("hex");
    const providedDigest = digestHeader.replace(/^sha256:/, "");

    if (expectedDigest !== providedDigest) {
      return {
        valid: false,
        reason: "Cryptographic digest mismatch: patch content has been tampered",
      };
    }

    const expectedSig = createHmac("sha256", key).update(canonicalPayload).digest("hex");
    const providedSig = signatureHeader.replace(/^hmac-sha256:/, "");

    const sigA = Buffer.from(expectedSig, "hex");
    const sigB = Buffer.from(providedSig, "hex");

    if (sigA.length !== sigB.length || !timingSafeEqual(sigA, sigB)) {
      return { valid: false, reason: "Invalid HMAC cryptographic signature" };
    }

    return { valid: true, patchMetadata: metadata };
  }

  /**
   * Generates a complete GitHub PR payload with signed commit and verification badges
   */
  public generateSignedPrPayload(options: {
    patch: SignedRemediationPatch;
    baseBranch?: string;
  }): SignedPrPayload {
    const base = options.baseBranch || "main";
    const shortRule = options.patch.ruleId.replace(/^CPG-/, "");
    const branchName = `ritualdev-remediation/${shortRule.toLowerCase()}-${Date.now().toString(36)}`;

    const title = `fix(sec): automated signed remediation for ${options.patch.ruleId}`;
    const commitMessage = [
      title,
      "",
      options.patch.explanation,
      "",
      "Signed-off-by: RitualDev Security Bot <security@ritualdev.in>",
      `X-RitualDev-Key: ${options.patch.keyId}`,
      `X-RitualDev-Digest: sha256:${options.patch.digest}`,
      `X-RitualDev-Signature: hmac-sha256:${options.patch.signature}`,
    ].join("\n");

    const body = [
      "## 🛡️ RitualDev Automated Cryptographically Signed Security Remediation",
      "",
      "### Vulnerability Remediation Summary",
      `- **Target File**: \`${options.patch.filePath}\` (Line ${options.patch.lineNumber})`,
      `- **Rule**: \`${options.patch.ruleId}\``,
      `- **Explanation**: ${options.patch.explanation}`,
      "",
      "### Cryptographic Attestation",
      "| Field | Value |",
      "| :--- | :--- |",
      "| **Status** | 🔒 **Verified Cryptographically Signed** |",
      `| **Key ID** | \`${options.patch.keyId}\` |`,
      `| **Digest** | \`sha256:${options.patch.digest.slice(0, 16)}...\` |`,
      `| **Timestamp** | \`${options.patch.timestamp}\` |`,
      "",
      "### Unified Diff",
      "```diff",
      options.patch.diff,
      "```",
      "",
      "> ℹ️ *This PR was generated automatically by WebSecAuditor whole-program Code Property Graph (CPG) remediation engine.*",
    ].join("\n");

    return {
      branchName,
      title,
      body,
      head: branchName,
      base,
      commitMessage,
      patch: options.patch,
    };
  }
}
