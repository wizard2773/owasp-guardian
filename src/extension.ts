// ─── OWASP Guardian – Extension Entry Point ──────────────────────────────────

import * as vscode from 'vscode';
import * as path from 'path';
import { analyzeDocument, buildWorkspaceResult, isSupported } from './analyzer';
import { ScanResult, WorkspaceScanResult } from './types';
import { createDiagnosticCollection, publishDiagnostics } from './providers/diagnosticProvider';
import { OwaspHoverProvider } from './providers/hoverProvider';
import { OwaspCodeActionProvider, registerCodeActionCommands } from './providers/codeActionProvider';
import { ReportPanel } from './webview/reportPanel';
import { GuardianChatProvider } from './providers/guardianChatProvider';

// ── State ─────────────────────────────────────────────────────────────────────

let diagnosticCollection: vscode.DiagnosticCollection;
let lastWorkspaceResult: WorkspaceScanResult | null = null;
let chatProvider: GuardianChatProvider;

const SUPPORTED_SELECTOR: vscode.DocumentSelector = [
  'javascript','typescript','javascriptreact','typescriptreact',
  'python','java','php','go','ruby','csharp',
].map(lang => ({ language: lang }));

// ── Activation ────────────────────────────────────────────────────────────────

export function activate(context: vscode.ExtensionContext): void {

  diagnosticCollection = createDiagnosticCollection();
  context.subscriptions.push(diagnosticCollection);

  // ── Chat Panel (Sidebar) ──────────────────────────────────────────────────

  chatProvider = new GuardianChatProvider(context.extensionUri);
  context.subscriptions.push(
    vscode.window.registerWebviewViewProvider(GuardianChatProvider.viewId, chatProvider, {
      webviewOptions: { retainContextWhenHidden: true }
    })
  );

  // ── Language Providers ────────────────────────────────────────────────────

  context.subscriptions.push(
    vscode.languages.registerHoverProvider(SUPPORTED_SELECTOR, new OwaspHoverProvider(diagnosticCollection))
  );

  context.subscriptions.push(
    vscode.languages.registerCodeActionsProvider(
      SUPPORTED_SELECTOR,
      new OwaspCodeActionProvider(diagnosticCollection),
      { providedCodeActionKinds: [vscode.CodeActionKind.QuickFix] }
    )
  );

  const cmdDisposables = registerCodeActionCommands(context);
  context.subscriptions.push(...cmdDisposables);

  // ── Commands ──────────────────────────────────────────────────────────────

  context.subscriptions.push(
    vscode.commands.registerCommand('owaspGuardian.scanFile', () => {
      const editor = vscode.window.activeTextEditor;
      if (!editor) { vscode.window.showWarningMessage('OWASP Guardian: No active editor.'); return; }
      runFileScan(editor.document);
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand('owaspGuardian.scanWorkspace', async () => {
      // Delegate to chat panel — open it and trigger scan command
      vscode.commands.executeCommand('owaspGuardian.chatView.focus');
      setTimeout(() => chatProvider.focusAndSend('scan .'), 400);
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand('owaspGuardian.showReport', () => {
      const panel = ReportPanel.createOrShow(context);
      panel.update(lastWorkspaceResult);
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand('owaspGuardian.clearDiagnostics', () => {
      diagnosticCollection.clear();
      lastWorkspaceResult = null;
      vscode.window.showInformationMessage('OWASP Guardian: Diagnostics cleared.');
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand('owaspGuardian.openChat', () => {
      vscode.commands.executeCommand('owaspGuardian.chatView.focus');
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand('owaspGuardian.runTieredWorkflow', () => {
      vscode.commands.executeCommand('owaspGuardian.chatView.focus');
      setTimeout(() => chatProvider.focusAndSend('tier2'), 400);
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand('owaspGuardian.showFindingDetail', (finding) => {
      const panel = ReportPanel.createOrShow(context);
      panel.update(lastWorkspaceResult);
    })
  );

  // ── Auto-scan on save ─────────────────────────────────────────────────────

  context.subscriptions.push(
    vscode.workspace.onDidSaveTextDocument(document => {
      const cfg = vscode.workspace.getConfiguration('owaspGuardian');
      if (cfg.get<boolean>('enableOnSave') && isSupported(document.languageId)) {
        const result = runFileScan(document);
        // Also post result to chat panel as a toast
        if (result && result.findings.length > 0) {
          chatProvider.postScanResult(result);
        }
      }
    })
  );

  // ── Auto-scan on file open ────────────────────────────────────────────────

  context.subscriptions.push(
    vscode.workspace.onDidOpenTextDocument(document => {
      if (isSupported(document.languageId)) { runFileScan(document); }
    })
  );

  // ── Status bar ────────────────────────────────────────────────────────────

  const statusItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
  statusItem.command = 'owaspGuardian.openChat';
  statusItem.text = '$(shield) Guardian';
  statusItem.tooltip = 'Open OWASP Guardian chat panel';
  statusItem.show();
  context.subscriptions.push(statusItem);

  // Scan open documents on activation
  vscode.workspace.textDocuments
    .filter(doc => isSupported(doc.languageId))
    .forEach(doc => runFileScan(doc));

  const out = vscode.window.createOutputChannel('OWASP Guardian');
  out.appendLine('[OWASP Guardian] Extension activated. 26 rules active. Click the shield icon in the sidebar to open the chat panel.');
  context.subscriptions.push(out);
}

// ── Scan helpers ──────────────────────────────────────────────────────────────

function runFileScan(document: vscode.TextDocument): ScanResult | null {
  const result = analyzeDocument(document);
  if (!result) { return null; }

  publishDiagnostics(diagnosticCollection, document, result);

  // Merge into workspace result
  if (!lastWorkspaceResult) {
    lastWorkspaceResult = buildWorkspaceResult([result]);
  } else {
    const others = lastWorkspaceResult.results.filter(r => r.filePath !== result.filePath);
    lastWorkspaceResult = buildWorkspaceResult([...others, result]);
  }

  return result;
}

export function deactivate(): void {
  diagnosticCollection?.dispose();
}
