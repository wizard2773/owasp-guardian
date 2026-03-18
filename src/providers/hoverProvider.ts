// ─── Hover Provider ────────────────────────────────────────────────────────────

import * as vscode from 'vscode';
import { Finding, Severity } from '../types';
import { DIAGNOSTIC_COLLECTION_NAME, getFindingFromDiagnostic } from './diagnosticProvider';

const SEVERITY_EMOJI: Record<Severity, string> = {
  critical: '🔴', high: '🟠', medium: '🟡', low: '🔵'
};

const BREAKING_ICON: Record<string, string> = {
  none: '✅ No breaking risk',
  low:  '⚡ Low breaking risk',
  medium: '⚠️ Medium breaking risk',
  high: '🚨 High breaking risk — requires careful migration',
};

export class OwaspHoverProvider implements vscode.HoverProvider {
  constructor(private diagnosticCollection: vscode.DiagnosticCollection) {}

  provideHover(document: vscode.TextDocument, position: vscode.Position): vscode.Hover | null {
    const diags = this.diagnosticCollection.get(document.uri);
    if (!diags) { return null; }

    for (const diag of diags) {
      if (!diag.range.contains(position)) { continue; }
      const finding: Finding | undefined = getFindingFromDiagnostic(diag);
      if (!finding) { continue; }

      return new vscode.Hover(this.buildMarkdown(finding));
    }
    return null;
  }

  private buildMarkdown(f: Finding): vscode.MarkdownString {
    const md = new vscode.MarkdownString('', true);
    md.isTrusted = true;
    md.supportHtml = false;

    md.appendMarkdown(`### ${SEVERITY_EMOJI[f.severity]} [${f.ruleId}] ${f.name}\n\n`);
    md.appendMarkdown(`**Category:** ${f.category}  \n`);
    md.appendMarkdown(`**Severity:** ${f.severity.toUpperCase()}\n\n`);
    md.appendMarkdown(`---\n\n`);
    md.appendMarkdown(`**What's wrong:**  \n${f.description}\n\n`);
    md.appendMarkdown(`---\n\n`);
    md.appendMarkdown(`**Suggested Fix:** ${f.fix.description}  \n\n`);
    md.appendCodeblock(f.fix.code, 'typescript');
    md.appendMarkdown(`\n**Safety:** ${f.fix.safetyNote}  \n`);
    md.appendMarkdown(`**Breaking risk:** ${BREAKING_ICON[f.fix.breakingRisk]}\n`);

    return md;
  }
}
