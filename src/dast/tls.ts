import tls from "node:tls";
import type { SecurityFinding, TlsAuditResult } from "../types/index.js";

export interface TlsCheckOptions {
  timeoutMs?: number;
}

export async function evaluateTls(
  urlStr: string,
  options: TlsCheckOptions = {},
): Promise<{ tlsResult: TlsAuditResult; findings: SecurityFinding[] }> {
  const findings: SecurityFinding[] = [];
  const issues: string[] = [];
  const url = new URL(urlStr);
  const isHttps = url.protocol === "https:";
  const timeoutMs = options.timeoutMs ?? 5000;

  if (!isHttps) {
    issues.push("Target URL protocol is unencrypted HTTP.");
    findings.push({
      id: "SEC-TLS-UNENCRYPTED-HTTP",
      category: "TLS",
      title: "Plaintext Unencrypted HTTP Protocol in Use",
      severity: "HIGH",
      scoreImpact: 25,
      cwe: "CWE-319",
      owasp: "A02:2021-Cryptographic Failures",
      description:
        "The web application serves traffic over unencrypted HTTP (port 80). Passwords, tokens, cookies, and sensitive data can be intercepted by on-path network attackers.",
      remediation:
        "Upgrade the service to HTTPS and configure an automatic 301 permanent redirect from HTTP to HTTPS.",
    });

    return {
      tlsResult: {
        isHttps: false,
        redirectsToHttps: false,
        redirectHops: [],
        issues,
      },
      findings,
    };
  }

  // Target is HTTPS - Inspect Peer Certificate using Node tls
  const port = url.port ? Number.parseInt(url.port, 10) : 443;
  const host = url.hostname;

  return new Promise((resolve) => {
    const socket = tls.connect(
      {
        host,
        port,
        servername: host,
        rejectUnauthorized: false, // Allow inspection of expired/self-signed certs
      },
      () => {
        try {
          const cert = socket.getPeerCertificate();
          const authorized = socket.authorized;
          const authError = socket.authorizationError;

          let certificateValid = authorized;
          let issuer: string | undefined;
          let validTo: string | undefined;
          let daysRemaining: number | undefined;

          if (cert && Object.keys(cert).length > 0) {
            if (typeof cert.issuer === "object" && cert.issuer) {
              const rawIssuer = cert.issuer.O || cert.issuer.CN;
              issuer = Array.isArray(rawIssuer) ? rawIssuer.join(", ") : rawIssuer;
            } else if (cert.issuer) {
              issuer = String(cert.issuer);
            }
            validTo = cert.valid_to;

            if (validTo) {
              const expireDate = new Date(validTo);
              const now = new Date();
              daysRemaining = Math.floor(
                (expireDate.getTime() - now.getTime()) / (1000 * 60 * 60 * 24),
              );

              if (daysRemaining < 0) {
                certificateValid = false;
                issues.push(`TLS certificate has expired (${Math.abs(daysRemaining)} days ago).`);
                findings.push({
                  id: "SEC-TLS-CERT-EXPIRED",
                  category: "TLS",
                  title: "TLS Certificate Has Expired",
                  severity: "CRITICAL",
                  scoreImpact: 35,
                  cwe: "CWE-295",
                  owasp: "A02:2021-Cryptographic Failures",
                  description: `The SSL/TLS certificate expired on ${validTo}. Browsers will display security interstitial warnings and refuse secure communication.`,
                  evidence: `Valid To: ${validTo}`,
                  remediation:
                    "Renew the SSL/TLS certificate immediately via your CA or automated ACME (Let's Encrypt).",
                });
              } else if (daysRemaining < 14) {
                issues.push(`TLS certificate expires soon (in ${daysRemaining} days).`);
                findings.push({
                  id: "SEC-TLS-CERT-EXPIRING-SOON",
                  category: "TLS",
                  title: "TLS Certificate Expiring Soon (< 14 Days)",
                  severity: "MEDIUM",
                  scoreImpact: 10,
                  cwe: "CWE-295",
                  description: `The SSL/TLS certificate will expire in ${daysRemaining} days on ${validTo}.`,
                  remediation: "Schedule immediate certificate renewal before it expires.",
                });
              }
            }

            if (!authorized && authError) {
              issues.push(`TLS Certificate verification error: ${authError.message || authError}`);
              findings.push({
                id: "SEC-TLS-CERT-UNTRUSTED",
                category: "TLS",
                title: "Untrusted or Self-Signed TLS Certificate",
                severity: "HIGH",
                scoreImpact: 25,
                cwe: "CWE-295",
                owasp: "A02:2021-Cryptographic Failures",
                description: `Certificate verification failed: ${authError.message || authError}. Possible self-signed certificate, mismatched hostname, or untrusted CA.`,
                remediation:
                  "Install a valid SSL/TLS certificate issued by a trusted public Certificate Authority.",
              });
            }
          }

          socket.end();
          resolve({
            tlsResult: {
              isHttps: true,
              certificateValid,
              issuer,
              validTo,
              daysRemaining,
              redirectsToHttps: true,
              redirectHops: [],
              issues,
            },
            findings,
          });
        } catch (err) {
          socket.destroy();
          issues.push(`TLS inspection exception: ${(err as Error).message}`);
          resolve({
            tlsResult: {
              isHttps: true,
              certificateValid: false,
              redirectsToHttps: true,
              redirectHops: [],
              issues,
            },
            findings,
          });
        }
      },
    );

    socket.setTimeout(timeoutMs, () => {
      socket.destroy();
      issues.push("TLS inspection timed out.");
      resolve({
        tlsResult: {
          isHttps: true,
          certificateValid: false,
          redirectsToHttps: true,
          redirectHops: [],
          issues,
        },
        findings,
      });
    });

    socket.on("error", (err) => {
      issues.push(`TLS connection error: ${err.message}`);
      resolve({
        tlsResult: {
          isHttps: true,
          certificateValid: false,
          redirectsToHttps: true,
          redirectHops: [],
          issues,
        },
        findings,
      });
    });
  });
}
