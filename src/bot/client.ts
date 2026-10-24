import { createGitHubAppJwt } from "./crypto.js";
import type { BotConfig, GitHubPullRequestRef } from "./types.js";

export interface GitHubClientOptions {
  githubToken?: string;
  appId?: string;
  privateKey?: string;
  baseUrl?: string;
}

export class GitHubClient {
  private githubToken?: string;
  private appId?: string;
  private privateKey?: string;
  private baseUrl: string;
  private tokenCache: Map<number, { token: string; expiresAt: number }> = new Map();

  constructor(options: GitHubClientOptions) {
    this.githubToken = options.githubToken;
    this.appId = options.appId;
    this.privateKey = options.privateKey;
    this.baseUrl = (options.baseUrl ?? "https://api.github.com").replace(/\/$/, "");
  }

  /**
   * Resolves a valid authorization header. If an installationId is supplied and
   * App credentials exist, retrieves or reuses an installation access token.
   */
  public async getAuthHeader(installationId?: number): Promise<string> {
    if (this.githubToken) {
      return `Bearer ${this.githubToken}`;
    }

    if (!this.appId || !this.privateKey) {
      throw new Error(
        "GitHub authentication failed: Neither githubToken nor appId + privateKey were provided.",
      );
    }

    if (!installationId) {
      // Return JWT for app-level endpoints
      return `Bearer ${createGitHubAppJwt(this.appId, this.privateKey)}`;
    }

    const cached = this.tokenCache.get(installationId);
    if (cached && cached.expiresAt > Date.now() + 60_000) {
      return `token ${cached.token}`;
    }

    const appJwt = createGitHubAppJwt(this.appId, this.privateKey);
    const res = await fetch(`${this.baseUrl}/app/installations/${installationId}/access_tokens`, {
      method: "POST",
      headers: {
        Accept: "application/vnd.github.v3+json",
        Authorization: `Bearer ${appJwt}`,
        "User-Agent": "WebSecAuditor-Bot/1.0.0",
      },
    });

    if (!res.ok) {
      const errText = await res.text();
      throw new Error(`Failed to exchange GitHub App installation token: ${res.status} ${errText}`);
    }

    const data = (await res.json()) as {
      token: string;
      expires_at: string;
    };
    const expiresAt = new Date(data.expires_at).getTime();
    this.tokenCache.set(installationId, { token: data.token, expiresAt });

    return `token ${data.token}`;
  }

  /**
   * Fetches raw unified diff string for a pull request.
   */
  public async getPullRequestDiff(
    owner: string,
    repo: string,
    prNumber: number,
    installationId?: number,
  ): Promise<string> {
    const auth = await this.getAuthHeader(installationId);
    const res = await fetch(`${this.baseUrl}/repos/${owner}/${repo}/pulls/${prNumber}`, {
      headers: {
        Accept: "application/vnd.github.v3.diff",
        Authorization: auth,
        "User-Agent": "WebSecAuditor-Bot/1.0.0",
      },
    });

    if (!res.ok) {
      throw new Error(
        `Failed to fetch PR diff for ${owner}/${repo}#${prNumber}: ${res.status} ${await res.text()}`,
      );
    }

    return await res.text();
  }

  /**
   * Retrieves pull request details including head SHA and branch info.
   */
  public async getPullRequest(
    owner: string,
    repo: string,
    prNumber: number,
    installationId?: number,
  ): Promise<GitHubPullRequestRef> {
    const auth = await this.getAuthHeader(installationId);
    const res = await fetch(`${this.baseUrl}/repos/${owner}/${repo}/pulls/${prNumber}`, {
      headers: {
        Accept: "application/vnd.github.v3+json",
        Authorization: auth,
        "User-Agent": "WebSecAuditor-Bot/1.0.0",
      },
    });

    if (!res.ok) {
      throw new Error(`Failed to fetch PR details for ${owner}/${repo}#${prNumber}: ${res.status}`);
    }

    return (await res.json()) as GitHubPullRequestRef;
  }

  /**
   * Creates a GitHub Check Run (e.g. "web-sec-auditor / Security Gate").
   */
  public async createCheckRun(
    owner: string,
    repo: string,
    payload: {
      name: string;
      head_sha: string;
      status: "queued" | "in_progress" | "completed";
      started_at?: string;
      conclusion?: "success" | "failure" | "neutral" | "cancelled" | "action_required";
      output?: {
        title: string;
        summary: string;
        text?: string;
        annotations?: Array<{
          path: string;
          start_line: number;
          end_line: number;
          annotation_level: "notice" | "warning" | "failure";
          title: string;
          message: string;
        }>;
      };
    },
    installationId?: number,
  ): Promise<{ id: number }> {
    const auth = await this.getAuthHeader(installationId);
    const res = await fetch(`${this.baseUrl}/repos/${owner}/${repo}/check-runs`, {
      method: "POST",
      headers: {
        Accept: "application/vnd.github.v3+json",
        Authorization: auth,
        "User-Agent": "WebSecAuditor-Bot/1.0.0",
        "Content-Type": "application/json",
      },
      body: JSON.stringify(payload),
    });

    if (!res.ok) {
      const err = await res.text();
      throw new Error(`Failed to create check run for ${owner}/${repo}: ${res.status} ${err}`);
    }

    return (await res.json()) as { id: number };
  }

  /**
   * Updates an existing GitHub Check Run with final status, conclusion, and annotations.
   */
  public async updateCheckRun(
    owner: string,
    repo: string,
    checkRunId: number,
    payload: Record<string, unknown>,
    installationId?: number,
  ): Promise<void> {
    const auth = await this.getAuthHeader(installationId);
    const res = await fetch(`${this.baseUrl}/repos/${owner}/${repo}/check-runs/${checkRunId}`, {
      method: "PATCH",
      headers: {
        Accept: "application/vnd.github.v3+json",
        Authorization: auth,
        "User-Agent": "WebSecAuditor-Bot/1.0.0",
        "Content-Type": "application/json",
      },
      body: JSON.stringify(payload),
    });

    if (!res.ok) {
      const err = await res.text();
      throw new Error(`Failed to update check run #${checkRunId}: ${res.status} ${err}`);
    }
  }

  /**
   * Posts a markdown comment on a pull request / issue thread.
   */
  public async postIssueComment(
    owner: string,
    repo: string,
    issueNumber: number,
    body: string,
    installationId?: number,
  ): Promise<void> {
    const auth = await this.getAuthHeader(installationId);
    const res = await fetch(
      `${this.baseUrl}/repos/${owner}/${repo}/issues/${issueNumber}/comments`,
      {
        method: "POST",
        headers: {
          Accept: "application/vnd.github.v3+json",
          Authorization: auth,
          "User-Agent": "WebSecAuditor-Bot/1.0.0",
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ body }),
      },
    );

    if (!res.ok) {
      const err = await res.text();
      throw new Error(
        `Failed to post comment to ${owner}/${repo}#${issueNumber}: ${res.status} ${err}`,
      );
    }
  }

  /**
   * Posts an official PR Review with comments.
   */
  public async createPrReview(
    owner: string,
    repo: string,
    prNumber: number,
    payload: {
      commit_id?: string;
      body: string;
      event: "APPROVE" | "REQUEST_CHANGES" | "COMMENT";
      comments?: Array<{
        path: string;
        line: number;
        body: string;
      }>;
    },
    installationId?: number,
  ): Promise<void> {
    const auth = await this.getAuthHeader(installationId);
    const res = await fetch(`${this.baseUrl}/repos/${owner}/${repo}/pulls/${prNumber}/reviews`, {
      method: "POST",
      headers: {
        Accept: "application/vnd.github.v3+json",
        Authorization: auth,
        "User-Agent": "WebSecAuditor-Bot/1.0.0",
        "Content-Type": "application/json",
      },
      body: JSON.stringify(payload),
    });

    if (!res.ok) {
      const err = await res.text();
      throw new Error(
        `Failed to submit PR review for ${owner}/${repo}#${prNumber}: ${res.status} ${err}`,
      );
    }
  }

  /**
   * Retrieves single file content at a given ref/commit.
   */
  public async getFileContent(
    owner: string,
    repo: string,
    filePath: string,
    ref: string,
    installationId?: number,
  ): Promise<{ content: string; sha: string }> {
    const auth = await this.getAuthHeader(installationId);
    const res = await fetch(
      `${this.baseUrl}/repos/${owner}/${repo}/contents/${filePath}?ref=${encodeURIComponent(ref)}`,
      {
        headers: {
          Accept: "application/vnd.github.v3+json",
          Authorization: auth,
          "User-Agent": "WebSecAuditor-Bot/1.0.0",
        },
      },
    );

    if (!res.ok) {
      throw new Error(`Failed to fetch file content for ${filePath} at ref ${ref}: ${res.status}`);
    }

    const data = (await res.json()) as { content: string; sha: string };
    const decoded = Buffer.from(data.content, "base64").toString("utf8");
    return { content: decoded, sha: data.sha };
  }

  /**
   * Creates a new Git branch reference.
   */
  public async createBranch(
    owner: string,
    repo: string,
    branchName: string,
    fromSha: string,
    installationId?: number,
  ): Promise<void> {
    const auth = await this.getAuthHeader(installationId);
    const res = await fetch(`${this.baseUrl}/repos/${owner}/${repo}/git/refs`, {
      method: "POST",
      headers: {
        Accept: "application/vnd.github.v3+json",
        Authorization: auth,
        "User-Agent": "WebSecAuditor-Bot/1.0.0",
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        ref: `refs/heads/${branchName}`,
        sha: fromSha,
      }),
    });

    if (!res.ok) {
      const err = await res.text();
      throw new Error(`Failed to create branch ${branchName}: ${res.status} ${err}`);
    }
  }

  /**
   * Updates/creates file content directly on a branch.
   */
  public async putFileContent(
    owner: string,
    repo: string,
    filePath: string,
    content: string,
    commitMessage: string,
    branch: string,
    fileSha?: string,
    installationId?: number,
  ): Promise<void> {
    const auth = await this.getAuthHeader(installationId);
    const res = await fetch(`${this.baseUrl}/repos/${owner}/${repo}/contents/${filePath}`, {
      method: "PUT",
      headers: {
        Accept: "application/vnd.github.v3+json",
        Authorization: auth,
        "User-Agent": "WebSecAuditor-Bot/1.0.0",
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        message: commitMessage,
        content: Buffer.from(content, "utf8").toString("base64"),
        branch,
        sha: fileSha,
      }),
    });

    if (!res.ok) {
      const err = await res.text();
      throw new Error(
        `Failed to commit file ${filePath} to branch ${branch}: ${res.status} ${err}`,
      );
    }
  }

  /**
   * Opens a new Pull Request.
   */
  public async openPullRequest(
    owner: string,
    repo: string,
    title: string,
    head: string,
    base: string,
    body: string,
    installationId?: number,
  ): Promise<{ number: number; html_url: string }> {
    const auth = await this.getAuthHeader(installationId);
    const res = await fetch(`${this.baseUrl}/repos/${owner}/${repo}/pulls`, {
      method: "POST",
      headers: {
        Accept: "application/vnd.github.v3+json",
        Authorization: auth,
        "User-Agent": "WebSecAuditor-Bot/1.0.0",
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        title,
        head,
        base,
        body,
      }),
    });

    if (!res.ok) {
      const err = await res.text();
      throw new Error(`Failed to open PR from ${head} into ${base}: ${res.status} ${err}`);
    }

    return (await res.json()) as { number: number; html_url: string };
  }
}
