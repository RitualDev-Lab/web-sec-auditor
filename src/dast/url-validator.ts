/**
 * SSRF (Server-Side Request Forgery) Defense Validator
 *
 * Validates URLs before dispatching outbound HTTP requests.
 * Blocks private RFC 1918 ranges, localhost/loopback, link-local metadata (169.254.169.254),
 * and unsupported protocols unless explicitly allowed.
 */

export interface UrlValidationResult {
  valid: boolean;
  error?: string;
  isPrivate?: boolean;
}

export function validateSafeUrl(urlString: string, allowPrivate = false): UrlValidationResult {
  let parsed: URL;
  try {
    parsed = new URL(urlString);
  } catch {
    return { valid: false, error: `Invalid URL format: "${urlString}"` };
  }

  // 1. Only allow HTTP and HTTPS protocols
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    return {
      valid: false,
      error: `Blocked protocol "${parsed.protocol}". Only "http:" and "https:" URLs are permitted.`,
    };
  }

  const hostname = parsed.hostname.toLowerCase();

  // 2. Identify if address is private, loopback, or cloud metadata
  const isLoopback =
    hostname === "localhost" ||
    hostname.endsWith(".localhost") ||
    hostname === "127.0.0.1" ||
    hostname === "::1" ||
    hostname === "[::1]" ||
    hostname === "0.0.0.0" ||
    hostname.startsWith("127.");

  const isLinkLocal =
    hostname.startsWith("169.254.") ||
    hostname.startsWith("fe80:") ||
    hostname.startsWith("[fe80:");

  const isCloudMetadata =
    hostname === "metadata.google.internal" ||
    hostname === "instance-data" ||
    hostname === "169.254.169.254";

  // Check IPv4 private ranges (RFC 1918)
  const isRfc1918 = isPrivateIpv4(hostname);

  const isPrivate = isLoopback || isLinkLocal || isCloudMetadata || isRfc1918;

  if (isPrivate && !allowPrivate) {
    return {
      valid: false,
      isPrivate: true,
      error: `SSRF Protection: Auditing private, localhost, or link-local endpoints ("${hostname}") is blocked by default to prevent Server-Side Request Forgery. Pass allowPrivate: true or --allow-private if testing local development servers.`,
    };
  }

  return { valid: true, isPrivate };
}

function isPrivateIpv4(hostname: string): boolean {
  // Regex to check if hostname is an IPv4 address
  const ipv4Match = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(hostname);
  if (!ipv4Match) return false;

  const octet1 = Number.parseInt(ipv4Match[1], 10);
  const octet2 = Number.parseInt(ipv4Match[2], 10);

  // 10.0.0.0/8
  if (octet1 === 10) return true;

  // 172.16.0.0/12 (172.16.0.0 - 172.31.255.255)
  if (octet1 === 172 && octet2 >= 16 && octet2 <= 31) return true;

  // 192.168.0.0/16
  if (octet1 === 192 && octet2 === 168) return true;

  // 100.64.0.0/10 (Carrier-Grade NAT)
  if (octet1 === 100 && octet2 >= 64 && octet2 <= 127) return true;

  // 0.0.0.0/8
  if (octet1 === 0) return true;

  return false;
}
