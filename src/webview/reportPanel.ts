// ─── Report Panel (Webview) ───────────────────────────────────────────────────

import * as vscode from 'vscode';
import { Finding, OwaspCategory, Severity, WorkspaceScanResult } from '../types';

export class ReportPanel {
  private static currentPanel: ReportPanel | undefined;
  private readonly _panel: vscode.WebviewPanel;
  private _disposables: vscode.Disposable[] = [];

  private constructor(panel: vscode.WebviewPanel) {
    this._panel = panel;
    this._panel.onDidDispose(() => this.dispose(), null, this._disposables);
  }

  static createOrShow(context: vscode.ExtensionContext): ReportPanel {
    const column = vscode.window.activeTextEditor
      ? vscode.ViewColumn.Beside
      : vscode.ViewColumn.One;

    if (ReportPanel.currentPanel) {
      ReportPanel.currentPanel._panel.reveal(column);
      return ReportPanel.currentPanel;
    }

    const panel = vscode.window.createWebviewPanel(
      'owaspGuardianReport',
      'OWASP Guardian — Security Report',
      column,
      { enableScripts: true, retainContextWhenHidden: true }
    );

    ReportPanel.currentPanel = new ReportPanel(panel);
    return ReportPanel.currentPanel;
  }

  update(result: WorkspaceScanResult | null): void {
    this._panel.webview.html = result
      ? this._buildReportHtml(result)
      : this._buildEmptyHtml();
  }

  private dispose(): void {
    ReportPanel.currentPanel = undefined;
    this._panel.dispose();
    this._disposables.forEach(d => d.dispose());
    this._disposables = [];
  }

  // ── HTML Generation ──────────────────────────────────────────────────────────

  private _buildEmptyHtml(): string {
    return `<!DOCTYPE html><html><body style="font-family:monospace;padding:2rem;color:#ccc;">
      <h2>OWASP Guardian</h2><p>Run a scan first: <strong>Ctrl+Shift+P → OWASP Guardian: Scan Current File</strong></p>
    </body></html>`;
  }

  private _buildReportHtml(result: WorkspaceScanResult): string {
    const { bySeverity, byCategory, totalFindings, results, scannedAt } = result;
    const allFindings = results.flatMap(r => r.findings.map(f => ({ ...f, filePath: r.filePath })));
    const filesScanned = results.length;

    const sevBadge = (sev: Severity, count: number) => {
      const colors: Record<Severity, [string,string]> = {
        critical: ['#ff2d55','#fff'],
        high:     ['#ff6b35','#fff'],
        medium:   ['#f7c59f','#111'],
        low:      ['#4da6ff','#fff'],
      };
      const [bg, fg] = colors[sev];
      return `<div class="sev-card" style="background:${bg};color:${fg}">
        <span class="sev-num">${count}</span>
        <span class="sev-label">${sev.toUpperCase()}</span>
      </div>`;
    };

    const categoryRows = Object.entries(byCategory)
      .sort(([,a],[,b]) => b - a)
      .map(([cat, count]) => `
        <tr>
          <td class="cat-name">${cat}</td>
          <td class="cat-count"><span class="badge">${count}</span></td>
          <td class="cat-bar"><div class="bar" style="width:${Math.min(100, (count / totalFindings) * 100)}%"></div></td>
        </tr>
      `).join('');

    const findingCards = allFindings.map((f, idx) => {
      const sevColor: Record<Severity, string> = {
        critical: '#ff2d55', high: '#ff6b35', medium: '#f7c59f', low: '#4da6ff'
      };
      const safeLabel = f.fix.safe
        ? `<span class="safe-badge safe">✅ Safe to apply</span>`
        : `<span class="safe-badge scrutiny">⚠️ Needs scrutiny</span>`;
      const breakingColors: Record<string,string> = { none:'#2ecc71',low:'#f39c12',medium:'#e67e22',high:'#e74c3c' };

      return `
        <details class="finding-card" id="finding-${idx}">
          <summary class="finding-summary">
            <span class="severity-dot" style="background:${sevColor[f.severity]}"></span>
            <span class="rule-id">${(f as any).ruleId}</span>
            <span class="finding-name">${f.name}</span>
            <span class="finding-file">${shortPath((f as any).filePath)} <span class="line-num">:${f.line + 1}</span></span>
            <span class="sev-pill" style="background:${sevColor[f.severity]}">${f.severity.toUpperCase()}</span>
          </summary>
          <div class="finding-body">
            <div class="finding-meta">
              <span class="meta-tag">${f.category}</span>
              ${safeLabel}
              <span class="breaking-tag" style="color:${breakingColors[f.fix.breakingRisk]}">
                Breaking risk: ${f.fix.breakingRisk}
              </span>
            </div>

            <h4>🔍 What's wrong</h4>
            <p class="description">${f.description}</p>

            <h4>💣 Vulnerable code (line ${f.line + 1})</h4>
            <pre class="code-block vuln-code">${escHtml(f.codeSnippet)}</pre>

            <h4>🔧 Suggested fix — <em>${f.fix.description}</em></h4>
            <pre class="code-block fix-code">${escHtml(f.fix.code)}</pre>

            <div class="safety-box ${f.fix.safe ? 'safe-box' : 'scrutiny-box'}">
              <strong>Safety assessment:</strong> ${f.fix.safetyNote}
            </div>
          </div>
        </details>
      `;
    }).join('');

    return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>OWASP Guardian Report</title>
<style>
  :root {
    --bg: #0d1117; --surface: #161b22; --border: #30363d;
    --text: #e6edf3; --muted: #8b949e; --accent: #58a6ff;
    --red: #ff2d55; --orange: #ff6b35; --yellow: #f7c59f; --blue: #4da6ff;
    --green: #2ecc71;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: var(--bg); color: var(--text); font-family: 'Segoe UI', system-ui, sans-serif; font-size: 13px; line-height: 1.5; }
  .header { background: var(--surface); border-bottom: 1px solid var(--border); padding: 1.25rem 1.5rem; display:flex; align-items:center; gap:1rem; }
  .header h1 { font-size: 1.1rem; font-weight: 700; color: var(--accent); }
  .header .meta { color: var(--muted); font-size: 0.8rem; }
  .container { max-width: 1100px; margin: 0 auto; padding: 1.5rem; }

  /* Summary Cards */
  .summary-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 0.75rem; margin-bottom: 1.5rem; }
  .sev-card { border-radius: 8px; padding: 1rem; text-align: center; }
  .sev-num { display: block; font-size: 2rem; font-weight: 800; line-height: 1; }
  .sev-label { font-size: 0.7rem; font-weight: 600; letter-spacing: 0.1em; }
  .stat-card { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 1rem; text-align: center; }
  .stat-num { font-size: 1.8rem; font-weight: 800; color: var(--accent); }
  .stat-label { font-size: 0.75rem; color: var(--muted); }

  /* Category Table */
  .section { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; margin-bottom: 1.25rem; overflow: hidden; }
  .section-header { padding: 0.75rem 1rem; border-bottom: 1px solid var(--border); font-weight: 600; font-size: 0.85rem; color: var(--accent); display:flex; justify-content:space-between; align-items:center; }
  table { width: 100%; border-collapse: collapse; }
  td { padding: 0.6rem 1rem; border-bottom: 1px solid var(--border); }
  tr:last-child td { border-bottom: none; }
  .cat-name { color: var(--text); width: 55%; font-size: 0.8rem; }
  .cat-count { width: 8%; text-align: center; }
  .cat-bar { width: 37%; }
  .badge { background: var(--accent); color: #000; border-radius: 99px; padding: 1px 8px; font-size: 0.75rem; font-weight: 700; }
  .bar { height: 6px; background: var(--accent); border-radius: 3px; opacity: 0.7; }

  /* Filters */
  .filter-row { display: flex; gap: 0.5rem; margin-bottom: 1rem; flex-wrap: wrap; }
  .filter-btn { background: var(--surface); border: 1px solid var(--border); color: var(--muted); padding: 0.3rem 0.75rem; border-radius: 99px; cursor: pointer; font-size: 0.78rem; transition: all 0.15s; }
  .filter-btn:hover, .filter-btn.active { border-color: var(--accent); color: var(--accent); }
  .filter-btn.f-critical.active { border-color: var(--red); color: var(--red); }
  .filter-btn.f-high.active    { border-color: var(--orange); color: var(--orange); }
  .filter-btn.f-medium.active  { border-color: var(--yellow); color: var(--yellow); }
  .filter-btn.f-low.active     { border-color: var(--blue); color: var(--blue); }

  /* Finding Cards */
  .finding-card { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; margin-bottom: 0.6rem; overflow: hidden; transition: border-color 0.15s; }
  .finding-card:hover { border-color: var(--accent); }
  .finding-summary { padding: 0.75rem 1rem; cursor: pointer; display: flex; align-items: center; gap: 0.75rem; list-style: none; user-select: none; }
  .finding-summary::-webkit-details-marker { display: none; }
  .severity-dot { width: 9px; height: 9px; border-radius: 50%; flex-shrink: 0; }
  .rule-id { font-family: 'Consolas','Courier New',monospace; font-size: 0.75rem; color: var(--muted); width: 72px; flex-shrink: 0; }
  .finding-name { font-weight: 600; font-size: 0.83rem; flex: 1; }
  .finding-file { color: var(--muted); font-size: 0.75rem; font-family: monospace; max-width: 280px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .line-num { color: var(--accent); }
  .sev-pill { font-size: 0.65rem; font-weight: 700; padding: 2px 7px; border-radius: 99px; color: #000; flex-shrink: 0; }

  .finding-body { padding: 1rem 1.25rem 1.25rem; border-top: 1px solid var(--border); }
  .finding-meta { display: flex; gap: 0.75rem; align-items: center; flex-wrap: wrap; margin-bottom: 1rem; }
  .meta-tag { background: #21262d; border: 1px solid var(--border); border-radius: 4px; padding: 2px 8px; font-size: 0.73rem; color: var(--muted); }
  .safe-badge { padding: 2px 8px; border-radius: 4px; font-size: 0.75rem; font-weight: 600; }
  .safe-badge.safe { background: rgba(46,204,113,0.15); color: #2ecc71; border: 1px solid rgba(46,204,113,0.3); }
  .safe-badge.scrutiny { background: rgba(247,197,159,0.15); color: #f7c59f; border: 1px solid rgba(247,197,159,0.3); }
  .breaking-tag { font-size: 0.75rem; font-weight: 600; }

  h4 { font-size: 0.8rem; font-weight: 600; color: var(--muted); text-transform: uppercase; letter-spacing: 0.05em; margin: 0.9rem 0 0.4rem; }
  .description { color: var(--text); font-size: 0.83rem; line-height: 1.6; }
  .code-block { background: #0d1117; border: 1px solid var(--border); border-radius: 6px; padding: 0.8rem 1rem; font-family: 'Consolas','Courier New',monospace; font-size: 0.78rem; overflow-x: auto; white-space: pre; line-height: 1.5; }
  .vuln-code { border-left: 3px solid var(--red); }
  .fix-code  { border-left: 3px solid var(--green); }
  .safety-box { margin-top: 0.75rem; padding: 0.6rem 0.9rem; border-radius: 6px; font-size: 0.8rem; }
  .safe-box     { background: rgba(46,204,113,0.08); border: 1px solid rgba(46,204,113,0.25); }
  .scrutiny-box { background: rgba(247,197,159,0.08); border: 1px solid rgba(247,197,159,0.25); }

  .empty-state { text-align: center; padding: 3rem; color: var(--muted); }
  .empty-state .check { font-size: 3rem; }
</style>
</head>
<body>

<div class="header">
  <div>
    <h1>🛡️ OWASP Guardian — Security Report</h1>
    <div class="meta">Scanned ${filesScanned} file${filesScanned !== 1 ? 's' : ''} · ${allFindings.length} finding${allFindings.length !== 1 ? 's' : ''} · ${scannedAt.toLocaleString()}</div>
  </div>
</div>

<div class="container">

  <!-- Severity Summary -->
  <div class="summary-grid">
    ${sevBadge('critical', bySeverity.critical)}
    ${sevBadge('high',     bySeverity.high)}
    ${sevBadge('medium',   bySeverity.medium)}
    ${sevBadge('low',      bySeverity.low)}
  </div>

  <!-- Category Breakdown -->
  ${Object.keys(byCategory).length ? `
  <div class="section">
    <div class="section-header">📊 Findings by OWASP Category</div>
    <table>
      <tbody>${categoryRows}</tbody>
    </table>
  </div>` : ''}

  <!-- Findings List -->
  <div class="section-header" style="margin-bottom:0.75rem;background:none;border:none;padding:0;">
    📋 All Findings
    <div class="filter-row" id="filters">
      <button class="filter-btn f-all active" onclick="filterFindings('all')">All (${allFindings.length})</button>
      ${bySeverity.critical ? `<button class="filter-btn f-critical" onclick="filterFindings('critical')">Critical (${bySeverity.critical})</button>` : ''}
      ${bySeverity.high     ? `<button class="filter-btn f-high"     onclick="filterFindings('high')">High (${bySeverity.high})</button>` : ''}
      ${bySeverity.medium   ? `<button class="filter-btn f-medium"   onclick="filterFindings('medium')">Medium (${bySeverity.medium})</button>` : ''}
      ${bySeverity.low      ? `<button class="filter-btn f-low"      onclick="filterFindings('low')">Low (${bySeverity.low})</button>` : ''}
    </div>
  </div>

  <div id="findings-list">
    ${allFindings.length ? findingCards : `
      <div class="empty-state">
        <div class="check">✅</div>
        <p>No findings matched your severity filter. Great work!</p>
      </div>
    `}
  </div>

</div>

<script>
  function filterFindings(sev) {
    document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
    document.querySelector('.f-' + sev)?.classList.add('active');
    document.querySelectorAll('.finding-card').forEach(card => {
      const dot = card.querySelector('.severity-dot');
      if (!dot) return;
      const pill = card.querySelector('.sev-pill');
      const cardSev = pill ? pill.textContent.trim().toLowerCase() : '';
      card.style.display = (sev === 'all' || cardSev === sev) ? '' : 'none';
    });
  }
</script>

</body>
</html>`;
  }
}

function escHtml(s: string): string {
  return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function shortPath(p: string): string {
  const parts = p.replace(/\\/g, '/').split('/');
  return parts.slice(-2).join('/');
}
