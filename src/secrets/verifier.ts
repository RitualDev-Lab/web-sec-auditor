/**
 * Non-Destructive AI Secret Verifier
 *
 * Performs safe, non-destructive read-only metadata verification pings against
 * official AI provider APIs (OpenAI, Anthropic, HuggingFace, Google Gemini)
 * to confirm whether exposed credentials are actively live or safely revoked.
 */

import type { SecretVerificationResult, SecretVerificationStatus } from "../types/index.js";

export interface VerifyOptions {
  timeoutMs?: number;
  customFetch?: typeof fetch;
}

/**
 * Executes a non-destructive verification ping to determine if an AI secret key is active.
 */
export async function verifyAiSecret(
  provider: "openai" | "anthropic" | "huggingface" | "gemini",
  secret: string,
  options: VerifyOptions = {},
): Promise<SecretVerificationResult> {
  const timeoutMs = options.timeoutMs ?? 3500;
  const fetchImpl = options.customFetch ?? fetch;
  const verifiedAt = new Date().toISOString();

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

  try {
    switch (provider) {
      case "openai": {
        // Non-destructive probe: read-only model list
        const res = await fetchImpl("https://api.openai.com/v1/models", {
          method: "GET",
          headers: {
            Authorization: `Bearer ${secret}`,
            "User-Agent": "WebSecAuditor-SecretHunter/1.0",
          },
          signal: controller.signal,
        });

        if (res.ok) {
          return {
            status: "ACTIVE",
            provider: "openai",
            details: "Live and active OpenAI API key (HTTP 200 OK)",
            verifiedAt,
          };
        }
        if (res.status === 401) {
          return {
            status: "REVOKED",
            provider: "openai",
            details: "Revoked or invalid OpenAI credential (HTTP 401 Unauthorized)",
            verifiedAt,
          };
        }
        if (res.status === 429) {
          return {
            status: "ACTIVE",
            provider: "openai",
            details: "Valid OpenAI key recognized, but rate-limited or quota exhausted (HTTP 429)",
            verifiedAt,
          };
        }
        return {
          status: "UNKNOWN",
          provider: "openai",
          details: `Unexpected response status HTTP ${res.status}`,
          verifiedAt,
        };
      }

      case "anthropic": {
        // Non-destructive probe: send empty payload to validate auth header
        const res = await fetchImpl("https://api.anthropic.com/v1/messages", {
          method: "POST",
          headers: {
            "x-api-key": secret,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
            "User-Agent": "WebSecAuditor-SecretHunter/1.0",
          },
          body: JSON.stringify({}),
          signal: controller.signal,
        });

        if (res.status === 401) {
          return {
            status: "REVOKED",
            provider: "anthropic",
            details: "Revoked or invalid Anthropic API key (HTTP 401 Unauthorized)",
            verifiedAt,
          };
        }
        // HTTP 400 with invalid request indicates the API key authenticated successfully
        if (res.status === 400 || res.ok) {
          return {
            status: "ACTIVE",
            provider: "anthropic",
            details: "Live and authenticated Anthropic API key",
            verifiedAt,
          };
        }
        return {
          status: "UNKNOWN",
          provider: "anthropic",
          details: `Unexpected response status HTTP ${res.status}`,
          verifiedAt,
        };
      }

      case "huggingface": {
        // Non-destructive probe: whoami metadata endpoint
        const res = await fetchImpl("https://huggingface.co/api/whoami-v2", {
          method: "GET",
          headers: {
            Authorization: `Bearer ${secret}`,
            "User-Agent": "WebSecAuditor-SecretHunter/1.0",
          },
          signal: controller.signal,
        });

        if (res.ok) {
          let user = "valid user";
          try {
            const data = (await res.json()) as { name?: string };
            if (data?.name) user = data.name;
          } catch {
            // fallback
          }
          return {
            status: "ACTIVE",
            provider: "huggingface",
            details: `Live and active Hugging Face token (authenticated as ${user})`,
            verifiedAt,
          };
        }
        if (res.status === 401) {
          return {
            status: "REVOKED",
            provider: "huggingface",
            details: "Revoked or invalid Hugging Face token (HTTP 401 Unauthorized)",
            verifiedAt,
          };
        }
        return {
          status: "UNKNOWN",
          provider: "huggingface",
          details: `Unexpected response status HTTP ${res.status}`,
          verifiedAt,
        };
      }

      case "gemini": {
        // Non-destructive probe: read-only models query
        const url = `https://generativelanguage.googleapis.com/v1beta/models?key=${encodeURIComponent(secret)}`;
        const res = await fetchImpl(url, {
          method: "GET",
          headers: {
            "User-Agent": "WebSecAuditor-SecretHunter/1.0",
          },
          signal: controller.signal,
        });

        if (res.ok) {
          return {
            status: "ACTIVE",
            provider: "gemini",
            details: "Live and active Google Gemini API key (HTTP 200 OK)",
            verifiedAt,
          };
        }
        if (res.status === 400 || res.status === 403 || res.status === 401) {
          const errText = await res.text();
          if (
            errText.includes("API_KEY_INVALID") ||
            errText.includes("not valid") ||
            res.status === 403
          ) {
            return {
              status: "REVOKED",
              provider: "gemini",
              details: "Revoked or invalid Gemini API key",
              verifiedAt,
            };
          }
        }
        return {
          status: "UNKNOWN",
          provider: "gemini",
          details: `Response status HTTP ${res.status}`,
          verifiedAt,
        };
      }

      default:
        return {
          status: "UNKNOWN",
          provider: "generic",
          details: `Provider not supported for automated verification`,
          verifiedAt,
        };
    }
  } catch (err: unknown) {
    const errMsg = err instanceof Error ? err.message : String(err);
    return {
      status: "UNKNOWN",
      provider,
      details: `Verification request failed or timed out: ${errMsg}`,
      verifiedAt,
    };
  } finally {
    clearTimeout(timeoutId);
  }
}
