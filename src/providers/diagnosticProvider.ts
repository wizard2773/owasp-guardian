// ─── Diagnostic Provider ──────────────────────────────────────────────────────

import * as vscode from 'vscode';
import { Finding, ScanResult, Severity } from './types';

const SEVERITY_MAP: Record<Severity, vscode.DiagnosticSeverity> = {
  critical: vscode.DiagnosticSeverity.Error,
  high:     vscode.DiagnosticSeverity.Error,
  medium:   vscode.DiagnosticSeverity.Warning,
  low:      vscode.DiagnosticSeverity.Information,
};

export const DIAGNOSTIC_COLLECTION_NAME = 'owaspGuardian';

export function createDiagnosticCollection(): vscode.DiagnosticCollection {
  return vscode.languages.createDiagnosticCollection(DIAGNOSTIC_COLLECTION_NAME);
}

export function publishDiagnostics(
  collection: vscode.DiagnosticCollection,
  document: vscode.TextDocument,
  result: ScanResult
): void {
  const diagnostics: vscode.Diagnostic[] = result.findings.map(f => {
    const line = Math.min(f.line, document.lineCount - 1);
    const lineText = document.lineAt(line).text;
    const startChar = Math.min(f.column, lineText.length);
    const endChar   = Math.min(f.endColumn, lineText.length);

    const range = new vscode.Range(line, startChar, line, endChar);

    const diag = new vscode.Diagnostic(
      range,
      `[${f.ruleId}] ${f.name}: ${f.description}`,
      SEVERITY_MAP[f.severity]
    );
    diag.source = 'OWASP Guardian';
    diag.code = {
      value: f.ruleId,
      target: vscode.Uri.parse(`https://owasp.org/Top10/`),
    };

    // Attach finding to diagnostic for code action retrieval
    (diag as any)._owaspFinding = f;

    return diag;
  });

  collection.set(document.uri, diagnostics);
}

/** Retrieve the attached Finding from a diagnostic, if present */
export function getFindingFromDiagnostic(diag: vscode.Diagnostic): Finding | undefined {
  return (diag as any)._owaspFinding;
}
