// ─── Code Action Provider (Quick Fixes) ──────────────────────────────────────

import * as vscode from 'vscode';
import { Finding } from '../types';
import { getFindingFromDiagnostic, DIAGNOSTIC_COLLECTION_NAME } from './diagnosticProvider';

export class OwaspCodeActionProvider implements vscode.CodeActionProvider {
  constructor(private diagnosticCollection: vscode.DiagnosticCollection) {}

  provideCodeActions(
    document: vscode.TextDocument,
    range: vscode.Range,
    context: vscode.CodeActionContext
  ): vscode.CodeAction[] {
    const actions: vscode.CodeAction[] = [];

    const relevantDiags = context.diagnostics.filter(
      d => d.source === 'OWASP Guardian'
    );

    for (const diag of relevantDiags) {
      if (!diag.range.intersection(range)) { continue; }
      const finding = getFindingFromDiagnostic(diag);
      if (!finding) { continue; }

      // Always offer: Show details in a side panel
      const showAction = new vscode.CodeAction(
        `🔍 [${finding.ruleId}] View fix details`,
        vscode.CodeActionKind.QuickFix
      );
      showAction.command = {
        command: 'owaspGuardian.showFindingDetail',
        title: 'Show finding detail',
        arguments: [finding],
      };
      showAction.diagnostics = [diag];
      actions.push(showAction);

      // If the fix is "safe" and the fix is a single-line replacement, offer inline apply
      if (finding.fix.safe && finding.fix.breakingRisk === 'none') {
        const applyAction = new vscode.CodeAction(
          `✅ [${finding.ruleId}] Apply safe fix: ${finding.fix.description}`,
          vscode.CodeActionKind.QuickFix
        );
        applyAction.command = {
          command: 'owaspGuardian.applyFix',
          title: 'Apply fix',
          arguments: [document, diag.range, finding],
        };
        applyAction.diagnostics = [diag];
        applyAction.isPreferred = true;
        actions.push(applyAction);
      } else {
        // Offer to insert the fix as a comment above the line
        const commentAction = new vscode.CodeAction(
          `📋 [${finding.ruleId}] Insert fix as comment (⚠️ needs scrutiny)`,
          vscode.CodeActionKind.QuickFix
        );
        commentAction.command = {
          command: 'owaspGuardian.insertFixAsComment',
          title: 'Insert fix as comment',
          arguments: [document, diag.range, finding],
        };
        commentAction.diagnostics = [diag];
        actions.push(commentAction);
      }
    }

    return actions;
  }
}

/** Registers commands that the code actions invoke */
export function registerCodeActionCommands(
  context: vscode.ExtensionContext
): vscode.Disposable[] {
  return [
    vscode.commands.registerCommand(
      'owaspGuardian.applyFix',
      async (document: vscode.TextDocument, range: vscode.Range, finding: Finding) => {
        // Insert the fix code as a block comment above the vulnerable line for safe fixes
        const edit = new vscode.WorkspaceEdit();
        const insertPos = new vscode.Position(range.start.line, 0);
        const indent = document.lineAt(range.start.line).text.match(/^(\s*)/)?.[1] ?? '';
        const commentLines = finding.fix.code
          .split('\n')
          .map(l => `${indent}// ${l}`)
          .join('\n');
        const inserted = `${commentLines}\n${indent}// TODO: Replace the line below with the fix above\n`;
        edit.insert(document.uri, insertPos, inserted);
        await vscode.workspace.applyEdit(edit);
        vscode.window.showInformationMessage(
          `[OWASP Guardian] Fix for ${finding.ruleId} inserted as comments above line ${range.start.line + 1}.`
        );
      }
    ),

    vscode.commands.registerCommand(
      'owaspGuardian.insertFixAsComment',
      async (document: vscode.TextDocument, range: vscode.Range, finding: Finding) => {
        const edit = new vscode.WorkspaceEdit();
        const insertPos = new vscode.Position(range.start.line, 0);
        const indent = document.lineAt(range.start.line).text.match(/^(\s*)/)?.[1] ?? '';
        const header = `${indent}// ⚠️  OWASP Guardian [${finding.ruleId}] — NEEDS SCRUTINY\n${indent}// ${finding.fix.safetyNote}\n${indent}// Suggested fix (${finding.fix.description}):\n`;
        const codeComment = finding.fix.code
          .split('\n')
          .map(l => `${indent}// ${l}`)
          .join('\n');
        edit.insert(document.uri, insertPos, `${header}${codeComment}\n`);
        await vscode.workspace.applyEdit(edit);
        vscode.window.showWarningMessage(
          `[OWASP Guardian] Fix suggestion for ${finding.ruleId} inserted as comments. Review carefully before applying.`
        );
      }
    ),
  ];
}
