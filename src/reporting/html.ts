import type { GenerateSarifOptions } from "./sarif.js";

/**
 * Escapes HTML special characters for safe inline report rendering.
 */
function escapeHtml(text: string): string {
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

/**
 * Generates a self-contained, interactive HTML executive security dashboard.
 */
export function generateHtmlReport(options: GenerateSarifOptions): string {
  const now = new Date().toISOString();

  let criticalCount = 0;
  let highCount = 0;
  let mediumCount = 0;
  let lowCount = 0;

  if (options.sastReport) {
    criticalCount += options.sastReport.summary.critical;
    highCount += options.sastReport.summary.high;
    mediumCount += options.sastReport.summary.medium;
    lowCount += options.sastReport.summary.low;
  }
  if (options.secretReport) {
    criticalCount += options.secretReport.summary.critical;
    highCount += options.secretReport.summary.high;
    mediumCount += options.secretReport.summary.medium;
    lowCount += options.secretReport.summary.low;
  }
  if (options.scaReport) {
    criticalCount += options.scaReport.summary.critical;
    highCount += options.scaReport.summary.high;
    mediumCount += options.scaReport.summary.medium;
    lowCount += options.scaReport.summary.low;
  }
  if (options.dastReport) {
    criticalCount += options.dastReport.summary.critical;
    highCount += options.dastReport.summary.high;
    mediumCount += options.dastReport.summary.medium;
    lowCount += options.dastReport.summary.low;
  }

  const totalIssues = criticalCount + highCount + mediumCount + lowCount;

  // Grade calculation
  let grade = "A+";
  let gradeColor = "#10b981"; // emerald
  if (criticalCount > 0) {
    grade = "F";
    gradeColor = "#ef4444"; // red
  } else if (highCount > 2) {
    grade = "D";
    gradeColor = "#f97316"; // orange
  } else if (highCount > 0) {
    grade = "C";
    gradeColor = "#f59e0b"; // amber
  } else if (mediumCount > 3) {
    grade = "B";
    gradeColor = "#eab308"; // yellow
  }

  const sastRows = (options.sastReport?.findings || [])
    .map(
      (f) => `
    <tr class="finding-row sev-${f.severity.toLowerCase()}">
      <td><span class="badge sev-${f.severity.toLowerCase()}">${f.severity}</span></td>
      <td><strong>${escapeHtml(f.title)}</strong><br><small class="text-muted">${f.ruleId} | ${f.cwe || ""} | ${f.owasp || ""}</small></td>
      <td><code>${escapeHtml(f.file)}:${f.line}</code></td>
      <td>${f.cvssScore ? `<span class="badge cvss">CVSS ${f.cvssScore}</span>` : "-"}</td>
      <td>
        <pre class="snippet"><code>${escapeHtml(f.snippet)}</code></pre>
        ${f.patch?.diff ? `<details><summary class="patch-toggle">📝 View Unified Diff Patch</summary><pre class="diff-block"><code>${escapeHtml(f.patch.diff)}</code></pre></details>` : ""}
      </td>
      <td>${escapeHtml(f.remediation)}</td>
    </tr>`,
    )
    .join("");

  const secretRows = (options.secretReport?.findings || [])
    .map(
      (s) => `
    <tr class="finding-row sev-${s.severity.toLowerCase()}">
      <td><span class="badge sev-${s.severity.toLowerCase()}">${s.severity}</span></td>
      <td><strong>${escapeHtml(s.title)}</strong></td>
      <td><code>${escapeHtml(s.file)}:${s.line}</code></td>
      <td><code>${escapeHtml(s.maskedSecret)}</code></td>
      <td><span class="badge entropy">Entropy ${s.entropy}</span></td>
      <td>${escapeHtml(s.remediation)}</td>
    </tr>`,
    )
    .join("");

  const scaRows = (options.scaReport?.findings || [])
    .map(
      (d) => `
    <tr class="finding-row sev-${d.severity.toLowerCase()}">
      <td><span class="badge sev-${d.severity.toLowerCase()}">${d.severity}</span></td>
      <td><strong>${escapeHtml(d.packageName)}@${escapeHtml(d.currentVersion)}</strong></td>
      <td>${escapeHtml(d.title)}</td>
      <td>${d.cvssScore ? `<span class="badge cvss">CVSS ${d.cvssScore}</span>` : "-"}</td>
      <td>${d.patchedVersion ? `<span class="badge safe-ver">&gt;= ${escapeHtml(d.patchedVersion)}</span>` : "See advisory"}</td>
      <td><a href="${escapeHtml(d.advisoryUrl || "#")}" target="_blank" rel="noreferrer">Advisory ↗</a></td>
    </tr>`,
    )
    .join("");

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>WebSecAuditor - Executive Security Dashboard</title>
  <style>
    :root {
      --bg: #090d16;
      --card-bg: #111827;
      --border: #1f2937;
      --text: #f9fafb;
      --text-muted: #9ca3af;
      --critical: #ef4444;
      --high: #f97316;
      --medium: #f59e0b;
      --low: #3b82f6;
      --info: #6b7280;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: var(--bg); color: var(--text); padding: 32px 24px; line-height: 1.5; }
    .container { max-width: 1300px; margin: 0 auto; }
    header { display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border); padding-bottom: 24px; margin-bottom: 32px; }
    .brand h1 { font-size: 26px; font-weight: 700; display: flex; align-items: center; gap: 10px; }
    .meta-time { color: var(--text-muted); font-size: 13px; margin-top: 4px; }
    .grade-badge { font-size: 32px; font-weight: 800; padding: 8px 24px; border-radius: 8px; border: 2px solid; background: rgba(255,255,255,0.03); }
    .kpi-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin-bottom: 32px; }
    .kpi-card { background: var(--card-bg); border: 1px solid var(--border); border-radius: 8px; padding: 20px; }
    .kpi-title { font-size: 13px; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.5px; }
    .kpi-value { font-size: 32px; font-weight: 700; margin-top: 8px; }
    .crit-text { color: var(--critical); }
    .high-text { color: var(--high); }
    .med-text { color: var(--medium); }
    .low-text { color: var(--low); }
    .section-title { font-size: 20px; margin: 32px 0 16px 0; display: flex; align-items: center; justify-content: space-between; }
    .table-container { background: var(--card-bg); border: 1px solid var(--border); border-radius: 8px; overflow-x: auto; margin-bottom: 32px; }
    table { width: 100%; border-collapse: collapse; text-align: left; font-size: 14px; }
    th { background: #1f2937; padding: 12px 16px; font-weight: 600; color: #d1d5db; border-bottom: 1px solid var(--border); }
    td { padding: 14px 16px; border-bottom: 1px solid var(--border); vertical-align: top; }
    tr:last-child td { border-bottom: none; }
    .badge { display: inline-block; padding: 3px 8px; border-radius: 4px; font-size: 11px; font-weight: 700; text-transform: uppercase; }
    .badge.sev-critical { background: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid #ef4444; }
    .badge.sev-high { background: rgba(249, 115, 22, 0.2); color: #fb923c; border: 1px solid #f97316; }
    .badge.sev-medium { background: rgba(245, 158, 11, 0.2); color: #fbbf24; border: 1px solid #f59e0b; }
    .badge.sev-low { background: rgba(59, 130, 246, 0.2); color: #60a5fa; border: 1px solid #3b82f6; }
    .badge.cvss { background: #374151; color: #f3f4f6; }
    .badge.entropy { background: #4b5563; color: #e5e7eb; }
    .badge.safe-ver { background: #064e3b; color: #34d399; }
    pre.snippet { background: #030712; padding: 8px 12px; border-radius: 4px; border: 1px solid #1f2937; font-size: 12px; margin-top: 6px; overflow-x: auto; max-width: 480px; }
    details { margin-top: 8px; }
    summary.patch-toggle { cursor: pointer; color: #60a5fa; font-size: 12px; }
    pre.diff-block { background: #0f172a; padding: 8px 12px; border-radius: 4px; border: 1px solid #334155; font-size: 11px; margin-top: 6px; color: #94a3b8; }
    a { color: #60a5fa; text-decoration: none; }
    a:hover { text-decoration: underline; }
    footer { text-align: center; color: var(--text-muted); font-size: 13px; margin-top: 48px; border-top: 1px solid var(--border); padding-top: 24px; }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <div class="brand">
        <h1>🛡️ WebSecAuditor</h1>
        <div class="meta-time">Generated on ${escapeHtml(now)} | Enterprise Executive Security Report</div>
      </div>
      <div class="grade-badge" style="color: ${gradeColor}; border-color: ${gradeColor};">
        Grade ${escapeHtml(grade)}
      </div>
    </header>

    <div class="kpi-grid">
      <div class="kpi-card">
        <div class="kpi-title">Critical Vulnerabilities</div>
        <div class="kpi-value crit-text">${criticalCount}</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-title">High Severity</div>
        <div class="kpi-value high-text">${highCount}</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-title">Medium Severity</div>
        <div class="kpi-value med-text">${mediumCount}</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-title">Total Issues Audited</div>
        <div class="kpi-value">${totalIssues}</div>
      </div>
    </div>

    ${
      sastRows
        ? `
    <div class="section-title">🔍 Source Code Vulnerabilities (SAST & OWASP Top 10)</div>
    <div class="table-container">
      <table>
        <thead>
          <tr>
            <th>Severity</th>
            <th>Vulnerability</th>
            <th>Location</th>
            <th>CVSS v3.1</th>
            <th>Snippet & Auto-Patch</th>
            <th>Remediation</th>
          </tr>
        </thead>
        <tbody>
          ${sastRows}
        </tbody>
      </table>
    </div>`
        : ""
    }

    ${
      secretRows
        ? `
    <div class="section-title">🔑 Hardcoded Credentials & High-Entropy Secrets</div>
    <div class="table-container">
      <table>
        <thead>
          <tr>
            <th>Severity</th>
            <th>Secret Type</th>
            <th>Location</th>
            <th>Masked Secret</th>
            <th>Shannon Entropy</th>
            <th>Remediation</th>
          </tr>
        </thead>
        <tbody>
          ${secretRows}
        </tbody>
      </table>
    </div>`
        : ""
    }

    ${
      scaRows
        ? `
    <div class="section-title">📦 Vulnerable Dependencies (SCA via OSV)</div>
    <div class="table-container">
      <table>
        <thead>
          <tr>
            <th>Severity</th>
            <th>Package</th>
            <th>Advisory Title</th>
            <th>CVSS v3.1</th>
            <th>Patched Version</th>
            <th>Reference</th>
          </tr>
        </thead>
        <tbody>
          ${scaRows}
        </tbody>
      </table>
    </div>`
        : ""
    }

    <footer>
      WebSecAuditor v1.0.0 Enterprise Cybersecurity Auditor | MIT License &copy; RitualDev Lab
    </footer>
  </div>
</body>
</html>`;
}
