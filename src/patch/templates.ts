export interface PatchReplacement {
  originalText: string;
  replacementText: string;
  explanation: string;
}

/**
 * Generate a safe defensive replacement for common code vulnerability patterns.
 */
export function generateRemediation(snippet: string, ruleId: string): PatchReplacement | undefined {
  const trimmed = snippet.trim();

  // 1. SQL Injection: Replace raw concatenation with parameterized query template
  if (ruleId === "SEC-INJ-SQLI") {
    // Matches: query = "SELECT ... " + req.body.param
    const concatMatch = trimmed.match(
      /^(.*["'`][^;\n]*?(?:SELECT|INSERT|UPDATE|DELETE)[^;\n]*?)['"`]\s*\+\s*([a-zA-Z0-9_.]+)(.*)$/i,
    );
    if (concatMatch) {
      let prefix = concatMatch[1].trim();
      const param = concatMatch[2].trim();
      const suffix = concatMatch[3].trim();

      // If query ended with opening single quote, e.g. "SELECT ... WHERE email = '", strip trailing quote
      if (prefix.endsWith("'")) {
        prefix = prefix.slice(0, -1).trim();
      }

      return {
        originalText: trimmed,
        replacementText: `${prefix} $1", [${param}]${suffix} /* Parameterized query auto-patch */`,
        explanation:
          "Converted raw string query concatenation into a parameterized query with bind variable ($1).",
      };
    }
  }

  // 2. Command Injection: Replace child_process.exec with child_process.execFile arguments array
  if (ruleId === "SEC-INJ-CMD") {
    const execMatch = trimmed.match(
      /(?:child_process\.)?exec\s*\(\s*["']([^"']+)["']\s*\+\s*([^)]+)\)/,
    );
    if (execMatch) {
      const cmd = execMatch[1].trim();
      const arg = execMatch[2].trim();
      return {
        originalText: trimmed,
        replacementText: `child_process.execFile("${cmd}", [String(${arg})]) /* Safe execFile without shell expansion */`,
        explanation:
          "Replaced shell-interpolated exec() with execFile() using an isolated arguments array without shell expansion.",
      };
    }
  }

  // 3. Path Traversal: Sanitize path with path.basename()
  if (ruleId === "SEC-INJ-PATH") {
    const pathMatch = trimmed.match(
      /^(.*(?:path|filePath|filename)\s*=\s*)(["'][^"']+["'])\s*\+\s*([^;]+)(;?)$/i,
    );
    if (pathMatch) {
      const left = pathMatch[1];
      const baseDir = pathMatch[2];
      const untrusted = pathMatch[3].trim();
      return {
        originalText: trimmed,
        replacementText: `${left}path.resolve(${baseDir}, path.basename(String(${untrusted}))); /* Path traversal guard */`,
        explanation:
          "Wrapped untrusted path input with path.basename() and resolved strictly against the base directory.",
      };
    }
  }

  // 4. DOM XSS: Replace innerHTML with textContent
  if (ruleId === "SEC-INJ-XSS") {
    if (trimmed.includes(".innerHTML")) {
      const replaced = trimmed.replace(".innerHTML", ".textContent");
      return {
        originalText: trimmed,
        replacementText: `${replaced} /* Use textContent to prevent script injection */`,
        explanation:
          "Replaced .innerHTML with .textContent to encode untrusted HTML entities and prevent script execution.",
      };
    }
  }

  // 5. Insecure TLS: Remove rejectUnauthorized: false
  if (ruleId === "SEC-CONF-DISABLE-TLS") {
    if (/rejectUnauthorized\s*:\s*false/i.test(trimmed)) {
      const replaced = trimmed.replace(
        /rejectUnauthorized\s*:\s*false/i,
        "rejectUnauthorized: true",
      );
      return {
        originalText: trimmed,
        replacementText: replaced,
        explanation: "Enforced TLS certificate chain verification (rejectUnauthorized: true).",
      };
    }
  }

  // 6. Hardcoded Secret Fallback: Throw error if env var is missing instead of default fallback
  if (ruleId === "SEC-CRYP-FALLBACK-SECRET") {
    const secretMatch = trimmed.match(
      /^(.*process\.env\.([A-Z0-9_]+))\s*\|\|\s*["'][^"']+["'](.*)$/,
    );
    if (secretMatch) {
      const envVar = secretMatch[2];
      return {
        originalText: trimmed,
        replacementText: `const ${envVar} = process.env.${envVar} || (() => { throw new Error("Missing required ${envVar} environment variable"); })();`,
        explanation:
          "Replaced hardcoded secret fallback with an explicit startup check requiring the environment variable.",
      };
    }
  }

  // 7. Prototype Pollution Guard
  if (ruleId === "SEC-INJ-PROTO-POLLUTION") {
    const assignMatch = trimmed.match(
      /^(.*)(\b(?:target|dest|obj|acc|result)\[(?:key|prop|k|p)\]\s*=\s*[^;]+)(;?)$/,
    );
    if (assignMatch) {
      return {
        originalText: trimmed,
        replacementText: `if (key !== "__proto__" && key !== "constructor" && key !== "prototype") { ${assignMatch[2]}; } /* Prototype pollution guard */`,
        explanation:
          "Added guard condition blocking __proto__, constructor, and prototype property modifications.",
      };
    }
  }

  // 8. NoSQL Injection: Sanitize query parameter with mongo-sanitize
  if (ruleId === "SEC-INJ-NOSQL") {
    const findMatch = trimmed.match(/^(.*)\.(find|findOne)\s*\(\s*(req\.(?:body|query))\s*\)(.*)$/);
    if (findMatch) {
      return {
        originalText: trimmed,
        replacementText: `${findMatch[1]}.${findMatch[2]}(sanitize(${findMatch[3]}))${findMatch[4]} /* Sanitize untrusted query payload */`,
        explanation:
          "Sanitized MongoDB query expression against operator injection ($where, $regex, $ne).",
      };
    }
  }

  return undefined;
}
