import * as http from "node:http";
import { GitHubClient } from "./client.js";
import { verifyWebhookSignature } from "./crypto.js";
import { parseUnifiedDiff } from "./diff.js";
import { PrPatcher } from "./patcher.js";
import { type DiffScanFile, PrDiffScanner } from "./scanner.js";
import type { BotConfig, GitHubPullRequestRef, GitHubWebhookPayload } from "./types.js";

export class BotServer {
  private config: BotConfig;
  private client: GitHubClient;
  private scanner: PrDiffScanner;
  private patcher: PrPatcher;
  private server: http.Server | null = null;

  constructor(config: BotConfig = {}) {
    this.config = {
      port: config.port ?? 3000,
      webhookSecret: config.webhookSecret,
      appId: config.appId,
      privateKey: config.privateKey,
      githubToken: config.githubToken,
      autoPatchOnCritical: config.autoPatchOnCritical ?? false,
      failOnSeverity: config.failOnSeverity ?? "HIGH",
      baseUrl: config.baseUrl,
    };

    this.client = new GitHubClient({
      githubToken: this.config.githubToken,
      appId: this.config.appId,
      privateKey: this.config.privateKey,
      baseUrl: this.config.baseUrl,
    });

    this.scanner = new PrDiffScanner();
    this.patcher = new PrPatcher();
  }

  /**
   * Starts the HTTP webhook server.
   */
  public async listen(port?: number): Promise<number> {
    const listenPort = port ?? this.config.port ?? 3000;

    return new Promise((resolve, reject) => {
      this.server = http.createServer(async (req, res) => {
        try {
          await this.handleRequest(req, res);
        } catch (err: unknown) {
          console.error("Unhandled bot server error:", err);
          if (!res.headersSent) {
            res.writeHead(500, { "Content-Type": "application/json" });
            res.end(JSON.stringify({ error: "Internal Server Error" }));
          }
        }
      });

      this.server.on("error", reject);
      this.server.listen(listenPort, () => {
        const addr = this.server?.address();
        const actualPort = typeof addr === "object" && addr ? addr.port : listenPort;
        resolve(actualPort);
      });
    });
  }

  /**
   * Stops the HTTP webhook server.
   */
  public async close(): Promise<void> {
    return new Promise((resolve) => {
      if (this.server) {
        this.server.close(() => resolve());
      } else {
        resolve();
      }
    });
  }

  /**
   * Handles incoming HTTP requests.
   */
  public async handleRequest(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
    const url = new URL(req.url ?? "/", `http://${req.headers.host || "localhost"}`);

    if (req.method === "GET" && url.pathname === "/health") {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(
        JSON.stringify({
          status: "ok",
          service: "web-sec-auditor-bot",
          version: "1.0.0",
        }),
      );
      return;
    }

    if (req.method === "POST" && (url.pathname === "/webhook" || url.pathname === "/")) {
      const chunks: Buffer[] = [];
      for await (const chunk of req) {
        chunks.push(typeof chunk === "string" ? Buffer.from(chunk) : chunk);
      }
      const rawBody = Buffer.concat(chunks);

      // Verify webhook HMAC signature if secret is configured
      if (this.config.webhookSecret) {
        const sigHeader = req.headers["x-hub-signature-256"] as string | undefined;
        const isValid = verifyWebhookSignature(rawBody, sigHeader, this.config.webhookSecret);

        if (!isValid) {
          res.writeHead(401, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: "Invalid HMAC signature" }));
          return;
        }
      }

      const event = req.headers["x-github-event"] as string | undefined;
      let payload: GitHubWebhookPayload;

      try {
        payload = JSON.parse(rawBody.toString("utf8"));
      } catch {
        res.writeHead(400, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "Invalid JSON payload" }));
        return;
      }

      // Respond immediately to GitHub with 202 Accepted
      res.writeHead(202, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ status: "processing", event }));

      // Dispatch event in background
      this.dispatchEvent(event, payload).catch((err) => {
        console.error(`Failed processing GitHub event '${event}':`, err);
      });
      return;
    }

    res.writeHead(404, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "Not Found" }));
  }

  /**
   * Dispatches and processes a GitHub webhook event.
   */
  public async dispatchEvent(
    event: string | undefined,
    payload: GitHubWebhookPayload,
  ): Promise<void> {
    if (!event || !payload.repository) {
      return;
    }

    const owner = payload.repository.owner.login;
    const repo = payload.repository.name;
    const installationId = payload.installation?.id;

    if (
      event === "pull_request" &&
      (payload.action === "opened" ||
        payload.action === "synchronize" ||
        payload.action === "reopened") &&
      payload.pull_request
    ) {
      await this.handlePullRequest(owner, repo, payload.pull_request, installationId);
    } else if (event === "issue_comment" && payload.action === "created") {
      await this.handleComment(owner, repo, payload, installationId);
    }
  }

  /**
   * Processes a pull_request event: creates check run, diff-scans files, posts comments.
   */
  public async handlePullRequest(
    owner: string,
    repo: string,
    pr: GitHubPullRequestRef,
    installationId?: number,
  ): Promise<void> {
    const headSha = pr.head.sha;
    const prNumber = pr.number;

    // 1. Create In-Progress Check Run
    let checkRunId: number | undefined;
    try {
      const cr = await this.client.createCheckRun(
        owner,
        repo,
        {
          name: "web-sec-auditor / Security Gate",
          head_sha: headSha,
          status: "in_progress",
          started_at: new Date().toISOString(),
          output: {
            title: "Security Audit Running",
            summary: "WebSecAuditor is inspecting modified lines and files in PR diff...",
          },
        },
        installationId,
      );
      checkRunId = cr.id;
    } catch (e) {
      console.warn("Could not create Check Run (permissions missing or disabled):", e);
    }

    // 2. Fetch diff and parse modified files
    const diffText = await this.client.getPullRequestDiff(owner, repo, prNumber, installationId);
    const parsedDiff = parseUnifiedDiff(diffText);

    // 3. Fetch file content for each touched file at headSha
    const diffFiles: DiffScanFile[] = [];
    for (const file of parsedDiff) {
      if (file.status === "deleted") continue;
      const targetPath = file.newPath || file.oldPath;
      try {
        const fileData = await this.client.getFileContent(
          owner,
          repo,
          targetPath,
          headSha,
          installationId,
        );
        diffFiles.push({ path: targetPath, content: fileData.content });
      } catch (err) {
        console.warn(`Could not fetch content for ${targetPath}:`, err);
      }
    }

    // 4. Run incremental PR audit
    const summary = await this.scanner.scanDiff(diffFiles, diffText, {
      owner,
      repo,
      prNumber,
      headSha,
      failOnSeverity: this.config.failOnSeverity,
    });

    const annotations = this.scanner.generateAnnotations(summary);
    const markdownReview = this.scanner.generateMarkdownReview(summary);

    // 5. Update Check Run
    if (checkRunId) {
      await this.client.updateCheckRun(
        owner,
        repo,
        checkRunId,
        {
          status: "completed",
          completed_at: new Date().toISOString(),
          conclusion: summary.passedGate ? "success" : "failure",
          output: {
            title: summary.passedGate
              ? "Security Gate Approved: 0 Blocking Vulnerabilities"
              : `Security Gate Failed: Found ${summary.findings.length} Issue(s)`,
            summary: `WebSecAuditor scanned ${summary.linesAnalyzed} modified lines across ${summary.filesScanned} files.`,
            annotations: annotations.slice(0, 50), // GitHub limits to 50 annotations per update
          },
        },
        installationId,
      );
    }

    // 6. Post Review Comment on PR
    await this.client.postIssueComment(owner, repo, prNumber, markdownReview, installationId);

    // 7. Auto-Patch Trigger if critical issues found and enabled
    if (
      this.config.autoPatchOnCritical &&
      summary.counts.critical > 0 &&
      summary.patchableCount > 0
    ) {
      await this.patcher.createFixPullRequest(
        this.client,
        owner,
        repo,
        prNumber,
        diffFiles,
        summary,
        installationId,
      );
    }
  }

  /**
   * Handles user comments on PRs looking for commands like '@web-sec-auditor fix'.
   */
  public async handleComment(
    owner: string,
    repo: string,
    payload: GitHubWebhookPayload,
    installationId?: number,
  ): Promise<void> {
    const commentBody = payload.comment?.body?.trim() ?? "";
    const isBotTrigger =
      /@web-sec-auditor\s+(?:fix|patch|apply-patch)/i.test(commentBody) ||
      /^\/(?:fix|patch)/i.test(commentBody);

    if (!isBotTrigger) {
      return;
    }

    // Ensure comment is on a PR
    const prDetails = payload.issue?.pull_request;
    const prNumber = payload.issue?.number;
    if (!prDetails || !prNumber) {
      return;
    }

    // Acknowledge receipt
    await this.client.postIssueComment(
      owner,
      repo,
      prNumber,
      "🤖 **WebSecAuditor Auto-Patch**: Analyzing vulnerabilities and generating defensive fix pull request...",
      installationId,
    );

    // Fetch PR diff and files
    const prInfo = await this.client.getPullRequest(owner, repo, prNumber, installationId);
    const diffText = await this.client.getPullRequestDiff(owner, repo, prNumber, installationId);
    const parsedDiff = parseUnifiedDiff(diffText);

    const diffFiles: DiffScanFile[] = [];
    for (const file of parsedDiff) {
      if (file.status === "deleted") continue;
      const targetPath = file.newPath || file.oldPath;
      try {
        const fileData = await this.client.getFileContent(
          owner,
          repo,
          targetPath,
          prInfo.head.sha,
          installationId,
        );
        diffFiles.push({ path: targetPath, content: fileData.content });
      } catch {
        // Skip
      }
    }

    const summary = await this.scanner.scanDiff(diffFiles, diffText, {
      owner,
      repo,
      prNumber,
      headSha: prInfo.head.sha,
    });

    const result = await this.patcher.createFixPullRequest(
      this.client,
      owner,
      repo,
      prNumber,
      diffFiles,
      summary,
      installationId,
    );

    if (!result.success) {
      await this.client.postIssueComment(
        owner,
        repo,
        prNumber,
        `⚠️ **Auto-Patch Failed**: ${result.error || "No patchable vulnerabilities found on modified lines."}`,
        installationId,
      );
    }
  }
}
