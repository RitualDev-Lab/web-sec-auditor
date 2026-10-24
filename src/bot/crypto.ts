import * as crypto from "node:crypto";

/**
 * Cryptographically verifies a GitHub Webhook HMAC-SHA256 signature against the raw payload.
 * Defends against timing attacks using timingSafeEqual.
 */
export function verifyWebhookSignature(
  rawBody: string | Buffer,
  signatureHeader: string | undefined,
  secret: string,
): boolean {
  if (!signatureHeader || !secret) {
    return false;
  }

  const prefix = "sha256=";
  if (!signatureHeader.startsWith(prefix)) {
    return false;
  }

  const providedHash = signatureHeader.slice(prefix.length);
  const hmac = crypto.createHmac("sha256", secret);
  hmac.update(rawBody);
  const expectedHash = hmac.digest("hex");

  const providedBuffer = Buffer.from(providedHash, "utf8");
  const expectedBuffer = Buffer.from(expectedHash, "utf8");

  if (providedBuffer.length !== expectedBuffer.length) {
    return false;
  }

  return crypto.timingSafeEqual(providedBuffer, expectedBuffer);
}

/**
 * Generates an RS256 signed JSON Web Token (JWT) for authenticating as a GitHub App.
 * Uses native Node.js crypto module without external dependencies.
 */
export function createGitHubAppJwt(
  appId: string,
  privateKeyPem: string,
  expiresInSec = 600,
): string {
  const now = Math.floor(Date.now() / 1000);
  const header = {
    alg: "RS256",
    typ: "JWT",
  };

  const payload = {
    iat: now - 60, // 60 seconds clock drift allowance
    exp: now + expiresInSec,
    iss: appId,
  };

  const base64UrlEncode = (obj: unknown): string => {
    return Buffer.from(JSON.stringify(obj)).toString("base64url");
  };

  const encodedHeader = base64UrlEncode(header);
  const encodedPayload = base64UrlEncode(payload);
  const dataToSign = `${encodedHeader}.${encodedPayload}`;

  const signer = crypto.createSign("RSA-SHA256");
  signer.update(dataToSign);
  const signature = signer.sign(privateKeyPem, "base64url");

  return `${dataToSign}.${signature}`;
}
