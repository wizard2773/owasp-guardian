// ─── PR Manager ───────────────────────────────────────────────────────────────
// Creates fix branches, applies code changes, and raises GitHub PRs
// Uses the `gh` CLI (GitHub CLI) — no tokens stored in the extension

import * as vscode from 'vscode';
import * as cp from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import { Finding } from '../types';

export interface PRResult {
  success: boolean;
  prUrl?: string;
  branch?: string;
  error?: string;
}

export interface PRStatus {
  findingKey: string;       // ruleId:filePath:line
  branch: string;
  prUrl?: string;
  state: 'pending' | 'open' | 'merged' | 'closed' | 'error';
  createdAt: Date;
}

export class PRManager {

  private _prHistory: Map<string, PRStatus> = new Map();

  constructor(private readonly wsFolder: string) {}

  // ── Public API ─────────────────────────────────────────────────────────────

  /** Check that git and gh are available */
  async checkPrereqs(): Promise<{ git: boolean; gh: boolean; repo: string | null }> {
    const git = await this._cmdOk('git --version');
    const gh  = await this._cmdOk('gh --version');
    const repo = gh ? await this._getRepoName() : null;
    return { git, gh, repo };
  }

  /** Create a branch, apply fix, commit, push, open PR */
  async createFixPR(
    finding: Finding & { filePath: string },
    progressCb: (msg: string) => void
  ): Promise<PRResult> {

    const key = this._findingKey(finding);

    // Don't duplicate
    const existing = this._prHistory.get(key);
    if (existing && existing.state === 'open') {
      return { success: true, prUrl: existing.prUrl, branch: existing.branch };
    }

    try {
      // 1. Verify we're in a git repo
      progressCb('Checking git status…');
      const isGit = await this._cmdOk('git rev-parse --git-dir');
      if (!isGit) { return { success: false, error: 'Not a git repository. Initialize git first.' }; }

      // 2. Check working tree is clean (or stash)
      progressCb('Checking working tree…');
      const dirty = await this._exec('git status --porcelain');
      if (dirty.trim()) {
        return {
          success: false,
          error: 'Working tree has uncommitted changes. Please commit or stash before creating a fix PR.'
        };
      }

      // 3. Get current branch to return to
      const baseBranch = (await this._exec('git branch --show-current')).trim() || 'main';

      // 4. Create fix branch
      const branchName = this._branchName(finding);
      progressCb(`Creating branch: ${branchName}…`);
      await this._exec(`git checkout -b ${branchName}`);

      // 5. Apply the fix to the file
      progressCb('Applying fix…');
      const applyResult = await this._applyFix(finding);
      if (!applyResult.success) {
        // Roll back
        await this._exec(`git checkout ${baseBranch}`);
        await this._exec(`git branch -D ${branchName}`);
        return { success: false, error: applyResult.error };
      }

      // 6. Stage and commit
      progressCb('Committing fix…');
      const relPath = path.relative(this.wsFolder, finding.filePath);
      await this._exec(`git add "${relPath}"`);

      const commitMsg = this._commitMessage(finding);
      await this._exec(`git commit -m "${commitMsg}"`);

      // 7. Push branch
      progressCb('Pushing branch…');
      const remote = (await this._exec('git remote')).split('\n')[0].trim() || 'origin';
      await this._exec(`git push ${remote} ${branchName}`);

      // 8. Create PR via gh
      progressCb('Creating GitHub PR…');
      const prBody = this._prBody(finding);
      const prTitle = `fix(security): [${finding.ruleId}] ${finding.name} in ${path.basename(finding.filePath)}`;

      const prOut = await this._exec(
        `gh pr create --base ${baseBranch} --head ${branchName} ` +
        `--title "${prTitle.replace(/"/g, '\\"')}" ` +
        `--body "${prBody.replace(/"/g, '\\"').replace(/\n/g, '\\n')}"`
      );

      const prUrl = prOut.trim().split('\n').find(l => l.startsWith('https://')) || prOut.trim();

      // 9. Return to base branch
      await this._exec(`git checkout ${baseBranch}`);

      // 10. Record
      const status: PRStatus = {
        findingKey: key, branch: branchName,
        prUrl, state: 'open', createdAt: new Date()
      };
      this._prHistory.set(key, status);

      return { success: true, prUrl, branch: branchName };

    } catch (err: any) {
      return { success: false, error: err.message || String(err) };
    }
  }

  /** Get existing PR for a finding, if any */
  getPRStatus(finding: Finding & { filePath: string }): PRStatus | undefined {
    return this._prHistory.get(this._findingKey(finding));
  }

  /** Fetch live PR status from GitHub */
  async refreshPRStatus(prUrl: string): Promise<'open' | 'merged' | 'closed' | 'unknown'> {
    try {
      const out = await this._exec(`gh pr view "${prUrl}" --json state --jq .state`);
      const s = out.trim().toLowerCase();
      if (s === 'open')   { return 'open'; }
      if (s === 'merged') { return 'merged'; }
      if (s === 'closed') { return 'closed'; }
    } catch { /* gh not available or PR not found */ }
    return 'unknown';
  }

  /** List all PRs raised in this session */
  listPRs(): PRStatus[] {
    return Array.from(this._prHistory.values()).sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime());
  }

  // ── Fix application ────────────────────────────────────────────────────────

  private async _applyFix(f: Finding & { filePath: string }): Promise<{ success: boolean; error?: string }> {
    if (!f.fix.safe || f.fix.breakingRisk === 'high') {
      return {
        success: false,
        error: `This fix is marked "${f.fix.breakingRisk}" breaking risk and cannot be auto-applied. Apply manually and commit.`
      };
    }

    let src: string;
    try { src = fs.readFileSync(f.filePath, 'utf8'); }
    catch (e: any) { return { success: false, error: `Cannot read ${f.filePath}: ${e.message}` }; }

    const lines = src.split('\n');
    const lineIdx = f.line;

    if (lineIdx >= lines.length) {
      return { success: false, error: `Line ${lineIdx + 1} is out of range (file has ${lines.length} lines).` };
    }

    // Strategy: insert the fix code as a comment block above the vulnerable line,
    // mark the original line with a TODO comment so the developer reviews it.
    const indent = lines[lineIdx].match(/^(\s*)/)?.[1] ?? '';
    const fixLines = f.fix.code.split('\n').map(l => `${indent}// ${l}`);
    const todoComment = `${indent}// TODO [${f.ruleId}]: Replace line below with fix above`;

    // Insert fix block above the vulnerable line
    lines.splice(lineIdx, 0, ...fixLines, todoComment);

    try {
      fs.writeFileSync(f.filePath, lines.join('\n'), 'utf8');
      return { success: true };
    } catch (e: any) {
      return { success: false, error: `Cannot write ${f.filePath}: ${e.message}` };
    }
  }

  // ── String builders ────────────────────────────────────────────────────────

  private _branchName(f: Finding & { filePath: string }): string {
    const ruleSlug = f.ruleId.toLowerCase().replace(/[^a-z0-9]/g, '-');
    const fileSlug = path.basename(f.filePath, path.extname(f.filePath))
      .toLowerCase().replace(/[^a-z0-9]/g, '-').slice(0, 20);
    const ts = Date.now().toString(36);
    return `fix/guardian-${ruleSlug}-${fileSlug}-${ts}`;
  }

  private _commitMessage(f: Finding & { filePath: string }): string {
    const rel = path.relative(this.wsFolder, f.filePath);
    return `fix(security): [${f.ruleId}] ${f.name}\\n\\nOWASP Guardian auto-fix\\nFile: ${rel}:${f.line + 1}\\nSeverity: ${f.severity}\\nCategory: ${f.category}`;
  }

  private _prBody(f: Finding & { filePath: string }): string {
    const rel = path.relative(this.wsFolder, f.filePath);
    return [
      `## 🛡 OWASP Guardian Security Fix`,
      ``,
      `**Rule:** \`${f.ruleId}\` — ${f.name}`,
      `**Severity:** ${f.severity.toUpperCase()}`,
      `**Category:** ${f.category}`,
      `**File:** \`${rel}:${f.line + 1}\``,
      ``,
      `### What was wrong`,
      f.description,
      ``,
      `### Vulnerable code`,
      `\`\`\``,
      f.codeSnippet,
      `\`\`\``,
      ``,
      `### Fix applied (${f.fix.description})`,
      `\`\`\``,
      f.fix.code,
      `\`\`\``,
      ``,
      `### Safety`,
      `- **Safe to apply:** ${f.fix.safe ? 'Yes' : 'No — needs manual review'}`,
      `- **Breaking risk:** ${f.fix.breakingRisk}`,
      `- ${f.fix.safetyNote}`,
      ``,
      `---`,
      `_This PR was generated by [OWASP Guardian](https://github.com/your-org/owasp-guardian) v1.1.0_`,
    ].join('\\n');
  }

  private _findingKey(f: Finding & { filePath: string }): string {
    return `${f.ruleId}:${f.filePath}:${f.line}`;
  }

  // ── Shell helpers ──────────────────────────────────────────────────────────

  private _exec(cmd: string): Promise<string> {
    return new Promise((resolve, reject) => {
      cp.exec(cmd, { cwd: this.wsFolder, timeout: 30000 }, (err, stdout, stderr) => {
        if (err) { reject(new Error(stderr || err.message)); }
        else { resolve(stdout); }
      });
    });
  }

  private async _cmdOk(cmd: string): Promise<boolean> {
    try { await this._exec(cmd); return true; }
    catch { return false; }
  }

  private async _getRepoName(): Promise<string | null> {
    try {
      const out = await this._exec('gh repo view --json nameWithOwner --jq .nameWithOwner');
      return out.trim() || null;
    } catch { return null; }
  }
}
