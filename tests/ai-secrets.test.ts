import assert from "node:assert";
import { describe, it } from "node:test";
import { SecretHunter, verifyAiSecret } from "../src/secrets/index.js";

describe("Modern AI Secret Scanning & Verification Suite", () => {
  const hunter = new SecretHunter();

  it("detects modern OpenAI Project (sk-proj-*), Anthropic (sk-ant-*), HuggingFace (hf_*), and Gemini (AIzaSy*) keys", () => {
    // Construct test tokens with high entropy
    const openAiProj = "sk-proj-9x7k2m1q8pZ" + "WvUtSrQpOnMlKjIhGfEdCbA1234567890abcdef";
    const claudeKey = "sk-ant-api03-abcdef" + "ghijklmnopqrstuvwxyz1234567890ABCDEF";
    const hfToken = "hf_" + "abcdefghijklmnopqrstuvwxyz12345678";
    const geminiKey = "AIzaSy" + "D-1234567890abcdefghijklmnopqr";

    const code = `
      const OPENAI_PROJ = "${openAiProj}";
      const CLAUDE_KEY = "${claudeKey}";
      const HF_KEY = "${hfToken}";
      const GEMINI_KEY = "${geminiKey}";
    `;

    const findings = hunter.scanContent(code, "config.env");

    assert.ok(findings.some((f) => f.patternId === "SEC-TOK-OPENAI"));
    assert.ok(findings.some((f) => f.patternId === "SEC-TOK-ANTHROPIC"));
    assert.ok(findings.some((f) => f.patternId === "SEC-TOK-HUGGINGFACE"));
    assert.ok(findings.some((f) => f.patternId === "SEC-TOK-GEMINI"));
  });

  it("executes non-destructive verification ping confirming active OpenAI key", async () => {
    const mockFetch: typeof fetch = async (url, init) => {
      assert.strictEqual(url, "https://api.openai.com/v1/models");
      assert.ok(init?.headers && "Authorization" in init.headers);
      return new Response(JSON.stringify({ data: [{ id: "gpt-4o" }] }), { status: 200 });
    };

    const res = await verifyAiSecret("openai", "sk-proj-dummytesttoken12345", {
      customFetch: mockFetch,
    });

    assert.strictEqual(res.status, "ACTIVE");
    assert.strictEqual(res.provider, "openai");
    assert.ok(res.details.includes("Live"));
  });

  it("executes non-destructive verification ping confirming revoked HuggingFace key", async () => {
    const mockFetch: typeof fetch = async () => {
      return new Response(JSON.stringify({ error: "Invalid token" }), { status: 401 });
    };

    const res = await verifyAiSecret("huggingface", "hf_dummytesttoken12345", {
      customFetch: mockFetch,
    });

    assert.strictEqual(res.status, "REVOKED");
    assert.strictEqual(res.provider, "huggingface");
  });

  it("executes non-destructive verification ping for Google Gemini API key", async () => {
    const mockFetch: typeof fetch = async (url) => {
      assert.ok(String(url).includes("generativelanguage.googleapis.com"));
      return new Response(JSON.stringify({ models: [{ name: "models/gemini-1.5-flash" }] }), {
        status: 200,
      });
    };

    const res = await verifyAiSecret("gemini", "AIzaSyDummyTestToken12345", {
      customFetch: mockFetch,
    });

    assert.strictEqual(res.status, "ACTIVE");
    assert.strictEqual(res.provider, "gemini");
  });
});
