// ─── OWASP Guardian – Analyzer ───────────────────────────────────────────────

import * as vscode from 'vscode';
import * as path from 'path';
import {
  Finding, Language, RuleContext, ScanResult, Severity, SEVERITY_RANK,
  WorkspaceScanResult, OwaspCategory,
} from './types';
import { ALL_RULES } from './rules/index';

const LANG_MAP: Record<string, Language> = {
  javascript: 'javascript', javascriptreact: 'javascriptreact',
  typescript: 'typescript', typescriptreact: 'typescriptreact',
  python: 'python', java: 'java', php: 'php',
  go: 'go', ruby: 'ruby', csharp: 'csharp',
};

const SUPPORTED_LANGS = new Set(Object.keys(LANG_MAP));

export function isSupported(langId: string): boolean {
  return SUPPORTED_LANGS.has(langId);
}

function getMinSeverityRank(): number {
  const cfg = vscode.workspace.getConfiguration('owaspGuardian');
  const min: Severity = cfg.get('minSeverity') ?? 'medium';
  return SEVERITY_RANK[min];
}

function shouldExclude(filePath: string): boolean {
  const cfg = vscode.workspace.getConfiguration('owaspGuardian');
  const patterns: string[] = cfg.get('excludePatterns') ?? [];
  const excludeTests: boolean = cfg.get('excludeTestFiles') ?? false;

  const normalised = filePath.replace(/\\/g, '/');

  if (excludeTests && /\.(test|spec)\.[jt]sx?$/.test(normalised)) { return true; }

  for (const pattern of patterns) {
    if (minimatch(normalised, pattern)) { return true; }
  }
  return false;
}

/** Very lightweight minimatch-like glob check (supports ** and *) */
function minimatch(str: string, pattern: string): boolean {
  const regexStr = pattern
    .replace(/\./g, '\\.')
    .replace(/\*\*/g, '§DOUBLE§')
    .replace(/\*/g, '[^/]*')
    .replace(/§DOUBLE§/g, '.*');
  return new RegExp(`(^|/)${regexStr}($|/)`).test(str);
}

export function analyzeDocument(document: vscode.TextDocument): ScanResult | null {
  const langId = document.languageId;
  if (!isSupported(langId)) { return null; }

  const filePath = document.uri.fsPath;
  if (shouldExclude(filePath)) { return null; }

  const language = LANG_MAP[langId];
  const text = document.getText();
  const lines = text.split('\n');
  const minRank = getMinSeverityRank();

  const ctx: RuleContext = { lines, filePath, language };
  const findings: Finding[] = [];

  for (const rule of ALL_RULES) {
    if (!rule.languages.includes(language)) { continue; }
    if (SEVERITY_RANK[rule.severity] < minRank) { continue; }
    try {
      const ruleFindings = rule.detect(ctx);
      findings.push(...ruleFindings);
    } catch (err) {
      // Rule should never crash the extension
      console.error(`[OWASP Guardian] Rule ${rule.id} threw:`, err);
    }
  }

  // Deduplicate across rules (same line + same rule id)
  const seen = new Set<string>();
  const deduped = findings.filter(f => {
    const key = `${f.ruleId}:${f.line}`;
    if (seen.has(key)) { return false; }
    seen.add(key);
    return true;
  });

  // Sort by severity desc, then line asc
  deduped.sort((a, b) => {
    const sevDiff = SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity];
    return sevDiff !== 0 ? sevDiff : a.line - b.line;
  });

  return { filePath, language, findings: deduped, scannedAt: new Date(), linesScanned: lines.length };
}

export function buildWorkspaceResult(results: ScanResult[]): WorkspaceScanResult {
  const bySeverity: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0 };
  const byCategory: Partial<Record<OwaspCategory, number>> = {};
  let total = 0;

  for (const r of results) {
    for (const f of r.findings) {
      bySeverity[f.severity]++;
      byCategory[f.category] = (byCategory[f.category] ?? 0) + 1;
      total++;
    }
  }

  return { results, totalFindings: total, bySeverity, byCategory, scannedAt: new Date() };
}
