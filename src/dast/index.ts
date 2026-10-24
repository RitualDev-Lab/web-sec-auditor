import type {
  DastScanOptions,
  DastScanReport,
  SecurityFinding,
  TlsAuditResult,
} from "../types/index.js";
import { evaluateCookies } from "./cookies.js";
import { evaluateCors } from "./cors.js";
import { evaluateSecurityHeaders } from "./headers.js";
import { calculateSecurityScore } from "./scoring.js";
import { evaluateTls } from "./tls.js";

export * from "./headers.js";
export * from "./cookies.js";
export * from "./cors.js";
export * from "./tls.js";
export * from "./scoring.js";

export class DastScanner {
  private defaultOptions: DastScanOptions;

  constructor(options: DastScanOptions = {}) {
    this.defaultOptions = {
      timeoutMs: 10000,
      userAgent: "WebSecAuditor/0.1.0 (+https://github.com/RitualDev-Lab/web-sec-auditor)",
      followRedirects: true,
      checkTlsCert: true,
      ...options,
    };
  }

  /**
   * Scan a live URL for HTTP security headers, cookie flags, CORS configuration, and TLS posture.
   */
  public async scanUrl(
    targetUrl: string,
    customOptions?: DastScanOptions,
  ): Promise<DastScanReport> {
    const opts = { ...this.defaultOptions, ...customOptions };
    const parsedUrl = new URL(targetUrl);
    const isHttps = parsedUrl.protocol === "https:";

    const allFindings: SecurityFinding[] = [];
    const startTime = Date.now();

    // 1. Fetch live response from target URL
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), opts.timeoutMs);

    let response: Response;
    let finalUrl = targetUrl;
    try {
      response = await fetch(targetUrl, {
        method: "GET",
        headers: {
          "User-Agent": opts.userAgent || "WebSecAuditor",
          Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
          ...opts.customHeaders,
        },
        redirect: opts.followRedirects ? "follow" : "manual",
        signal: controller.signal,
      });
      finalUrl = response.url || targetUrl;
    } finally {
      clearTimeout(timeoutId);
    }

    const responseTimeMs = Date.now() - startTime;

    // 2. Extract Response Headers
    const headersRecord: Record<string, string> = {};
    response.headers.forEach((value, key) => {
      headersRecord[key.toLowerCase()] = value;
    });

    // Extract raw Set-Cookie headers
    let setCookieHeaders: string[] = [];
    // Node.js fetch supports getSetCookie()
    if (
      typeof (response.headers as unknown as { getSetCookie?: () => string[] }).getSetCookie ===
      "function"
    ) {
      setCookieHeaders = (
        response.headers as unknown as { getSetCookie: () => string[] }
      ).getSetCookie();
    } else {
      const rawCookie = response.headers.get("set-cookie");
      if (rawCookie) setCookieHeaders = [rawCookie];
    }

    // 3. Evaluate Security Headers
    const { headerItems, findings: headerFindings } = evaluateSecurityHeaders(
      headersRecord,
      isHttps,
    );
    allFindings.push(...headerFindings);

    // 4. Evaluate Cookie Flags
    const { cookieItems, findings: cookieFindings } = evaluateCookies(setCookieHeaders, isHttps);
    allFindings.push(...cookieFindings);

    // 5. Evaluate CORS Policies
    const { corsResult, findings: corsFindings } = evaluateCors(headersRecord);
    allFindings.push(...corsFindings);

    // 6. Evaluate TLS & Certificate (if HTTPS)
    let tlsResult: TlsAuditResult = {
      isHttps,
      certificateValid: isHttps,
      redirectsToHttps: isHttps,
      redirectHops: [],
      issues: [],
    };

    if (isHttps && opts.checkTlsCert) {
      try {
        const tlsEval = await evaluateTls(finalUrl, { timeoutMs: opts.timeoutMs });
        tlsResult = tlsEval.tlsResult;
        allFindings.push(...tlsEval.findings);
      } catch {
        // Fallback gracefully if raw TLS socket check fails
      }
    } else if (!isHttps) {
      const tlsEval = await evaluateTls(finalUrl);
      allFindings.push(...tlsEval.findings);
      tlsResult = tlsEval.tlsResult;
    }

    // 7. Calculate Overall Security Score & Letter Grade
    const { score, grade, summary } = calculateSecurityScore(allFindings);

    return {
      targetUrl,
      finalUrl,
      scanTimestamp: new Date().toISOString(),
      statusCode: response.status,
      responseTimeMs,
      score,
      grade,
      summary,
      headers: headerItems,
      cookies: cookieItems,
      cors: corsResult,
      tls: tlsResult,
      findings: allFindings,
    };
  }
}
