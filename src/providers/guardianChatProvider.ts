// ─── Guardian Chat Panel (auto Tier-2 prompt + PR creation) ──────────────────
import * as vscode from 'vscode';
import * as path from 'path';
import * as fs from 'fs';
import * as cp from 'child_process';
import { analyzeDocument, buildWorkspaceResult, isSupported } from '../analyzer';
import { Finding, ScanResult, Severity, WorkspaceScanResult, SEVERITY_RANK } from '../types';
import { PRManager } from './prManager';

export class GuardianChatProvider implements vscode.WebviewViewProvider {
  public static readonly viewId = 'owaspGuardian.chatView';
  private _view?: vscode.WebviewView;
  private _lastWorkspaceScan?: WorkspaceScanResult;
  private _sessionFindings: Array<Finding & { filePath: string }> = [];
  private _prManager?: PRManager;

  constructor(private readonly _extensionUri: vscode.Uri) {}

  resolveWebviewView(webviewView: vscode.WebviewView, _: any, __: any): void {
    this._view = webviewView;
    webviewView.webview.options = { enableScripts: true, localResourceRoots: [this._extensionUri] };
    webviewView.webview.html = this._buildHtml();
    webviewView.webview.onDidReceiveMessage(msg => this._handle(msg));
    setTimeout(() => this._welcome(), 200);
    this._initPR();
  }

  public focusAndSend(text: string): void {
    vscode.commands.executeCommand('owaspGuardian.chatView.focus');
    setTimeout(() => this._handle({ type: 'userInput', text }), 300);
  }

  public postScanResult(result: ScanResult): void {
    if (!result.findings.length) return;
    this._mergeFindings([result]);
    this._post({ type: 'autoScanToast', file: path.basename(result.filePath), count: result.findings.length });
  }

  private async _handle(msg: any): Promise<void> {
    switch (msg.type) {
      case 'userInput':    this._echo(msg.text); await this._dispatch(msg.text); break;
      case 'quickAction':  await this._dispatch(msg.text); break;
      case 'showFinding':  this._showFinding(msg.idx); break;
      case 'openFile':     await this._openFile(msg.idx); break;
      case 'confirmTier2': await this._tier2(); break;
      case 'dismissTier2': this._bot(`<span style="color:var(--vscode-descriptionForeground);font-size:11px;">Skipped. Run <code>tier2</code> any time.</span>`); break;
      case 'createPR':     await this._createPR(msg.idx); break;
      case 'viewPR':       vscode.env.openExternal(vscode.Uri.parse(msg.url)); break;
      case 'listPRs':      this._listPRs(); break;
    }
  }

  private async _dispatch(raw: string): Promise<void> {
    const [cmd, ...args] = raw.trim().split(/\s+/);
    switch (cmd.toLowerCase()) {
      case 'scan':    return this._scan(args);
      case 'list':    return this._list(args[0] as Severity);
      case 'show':    return this._show(parseInt(args[0]));
      case 'explain': return this._explain(args[0]?.toUpperCase());
      case 'rules':   return this._rules(args[0]?.toUpperCase());
      case 'filter':  return this._filter(args[0] as Severity);
      case 'report':  return this._report(args[0]);
      case 'prs':     return this._listPRs();
      case 'clear':   return this._clear();
      case 'tier2':
      case 'claude':  return this._tier2();
      case 'help':    return this._help();
      default:        this._bot(`Unknown: <code>${cmd}</code>. Type <code>help</code>.`);
    }
  }

  // ── SCAN ────────────────────────────────────────────────────────────────────
  private async _scan(args: string[]): Promise<void> {
    const target = args[0];
    if (target && target !== '.' && target !== 'workspace') {
      const fp = path.resolve(vscode.workspace.workspaceFolders?.[0]?.uri.fsPath||'', target);
      if (!fs.existsSync(fp)) { this._bot(`File not found: <code>${target}</code>`); return; }
      const doc = await vscode.workspace.openTextDocument(vscode.Uri.file(fp));
      const r = analyzeDocument(doc);
      if (!r) { this._bot('Language not supported or file excluded.'); return; }
      this._mergeFindings([r]); this._summary([r]); this._autoTier2Prompt([r]);
      return;
    }
    this._bot(`<span class="sa">🔍 Scanning workspace…</span>`);
    const files = await vscode.workspace.findFiles('**/*.{js,ts,jsx,tsx,py,java,php,go,rb,cs}','{**/node_modules/**,**/dist/**,**/build/**,**/*.min.js}');
    const results: ScanResult[] = [];
    let done = 0;
    for (const uri of files) {
      try { const doc = await vscode.workspace.openTextDocument(uri); const r = analyzeDocument(doc); if(r) results.push(r); } catch {}
      done++; if(done%10===0) this._post({type:'prog',done,total:files.length});
    }
    this._lastWorkspaceScan = buildWorkspaceResult(results);
    this._mergeFindings(results); this._summary(results); this._autoTier2Prompt(results);
  }

  // ── AUTO TIER-2 PROMPT ──────────────────────────────────────────────────────
  private _autoTier2Prompt(results: ScanResult[]): void {
    const total = results.reduce((s,r)=>s+r.findings.length,0);
    if (!total) return;
    const crit = results.flatMap(r=>r.findings).filter(f=>f.severity==='critical').length;
    const high = results.flatMap(r=>r.findings).filter(f=>f.severity==='high').length;
    const col = crit>0?'#ff8080':high>0?'#f0a060':'#e8c060';
    const crLabel = crit ? ` · <span style="color:#ff8080;font-weight:600;">${crit} critical</span>` : '';
    setTimeout(() => {
      this._bot(`
        <div class="t2p">
          <div class="t2p-ico">🤖</div>
          <div class="t2p-body">
            <div class="t2p-title">Send to Claude Code for deep analysis?</div>
            <div class="t2p-sub">Guardian found <span style="color:${col};font-weight:600;">${total} finding${total!==1?'s':''}${crLabel}</span>.
              Claude Code will trace data flow, confirm findings, detect chains Guardian missed, and rate real exploitability.
            </div>
            <div class="t2p-acts">
              <button class="tp-yes" onclick="pm({type:'confirmTier2'})">✅ Yes — run Tier 2 now</button>
              <button class="tp-no"  onclick="pm({type:'dismissTier2'})">Not now</button>
            </div>
          </div>
        </div>`);
    }, 700);
  }

  // ── LIST ────────────────────────────────────────────────────────────────────
  private _list(sev?: Severity): void {
    let f = this._sessionFindings;
    if (!f.length) { this._bot('No findings. Run <code>scan .</code> first.'); return; }
    if (sev && ['critical','high','medium','low'].includes(sev)) f = f.filter(x=>x.severity===sev);
    if (!f.length) { this._bot(`No ${sev} findings.`); return; }
    const C: Record<string,[string,string]> = {critical:['#6b1313','#ff8080'],high:['#5c3200','#f0a060'],medium:['#4a3900','#e8c060'],low:['#1a3c1a','#80c880']};
    const rows = f.map((x,i)=>{
      const [bg,fg]=C[x.severity]||['#333','#ccc'];
      const pr = this._prManager?.getPRStatus(x);
      const prBadge = pr ? ` <span style="color:#4ec9b0;font-size:9px;">✔PR</span>` : '';
      return `<tr onclick="pm({type:'showFinding',idx:${i}})"><td style="color:#666;font-size:9px;width:14px;">${i+1}</td><td><span class="sp" style="background:${bg};color:${fg};">${x.severity.slice(0,4).toUpperCase()}</span></td><td style="font-family:monospace;font-size:9px;color:#858585;">${x.ruleId}</td><td>${x.name}${prBadge}</td><td style="font-family:monospace;font-size:9px;color:var(--vscode-textLink-foreground);">${path.basename(x.filePath)}:${x.line+1}</td></tr>`;
    }).join('');
    this._bot(`<div style="font-size:11px;color:var(--vscode-descriptionForeground);margin-bottom:4px;">${f.length} finding${f.length!==1?'s':''}${sev?` · ${sev}`:''} — click for detail + PR</div><table class="gt findings-t"><tbody>${rows}</tbody></table>`);
  }

  // ── SHOW ────────────────────────────────────────────────────────────────────
  private _show(n: number): void {
    if (!this._sessionFindings.length) { this._bot('No findings. Run <code>scan .</code> first.'); return; }
    if (isNaN(n)||n<1||n>this._sessionFindings.length) { this._bot(`Use 1–${this._sessionFindings.length}.`); return; }
    this._showFinding(n-1);
  }

  private _showFinding(idx: number): void {
    const f = this._sessionFindings[idx]; if(!f) return;
    const C: Record<string,[string,string]> = {critical:['#6b1313','#ff8080'],high:['#5c3200','#f0a060'],medium:['#4a3900','#e8c060'],low:['#1a3c1a','#80c880']};
    const [bg,fg]=C[f.severity]||['#333','#ccc'];
    const bc={none:'#4ec9b0',low:'#e8c060',medium:'#e8a202',high:'#f44747'}[f.fix.breakingRisk]||'#ccc';
    const prStatus = this._prManager?.getPRStatus(f);
    let prBtn = '';
    if (prStatus?.state==='open'&&prStatus.prUrl) {
      prBtn=`<button class="ab" onclick="pm({type:'viewPR',url:'${prStatus.prUrl}'})">View PR ↗</button>`;
    } else if (f.fix.breakingRisk==='high') {
      prBtn=`<button class="ab" disabled title="${f.fix.safetyNote}">⚠ Manual fix needed</button>`;
    } else if (!f.fix.safe) {
      prBtn=`<button class="ab" onclick="pm({type:'createPR',idx:${idx}})">🔀 Raise PR (needs review)</button>`;
    } else {
      prBtn=`<button class="ab pri" onclick="pm({type:'createPR',idx:${idx}})">🔀 Raise Fix PR</button>`;
    }
    this._bot(`<div class="fd"><div class="fd-h"><span class="sp" style="background:${bg};color:${fg};">${f.severity.toUpperCase()}</span><span style="font-family:monospace;font-size:10px;color:#858585;">[${f.ruleId}]</span><strong>${f.name}</strong></div>
      <div style="font-size:11px;color:var(--vscode-descriptionForeground);margin-bottom:6px;">${f.category} · <span style="color:var(--vscode-textLink-foreground);cursor:pointer;" onclick="pm({type:'openFile',idx:${idx}})">${path.basename(f.filePath)}:${f.line+1}</span></div>
      <div class="fl">What's wrong</div><div class="fb">${f.description}</div>
      <div class="fl">Vulnerable code (line ${f.line+1})</div><pre class="fc vc">${this._esc(f.codeSnippet)}</pre>
      <div class="fl">Fix — ${f.fix.description}</div><pre class="fc xc">${this._esc(f.fix.code)}</pre>
      <div class="fs"><span>${f.fix.safe?'✅':'⚠️'} ${f.fix.safetyNote}</span><span style="color:${bc}">Breaking risk: ${f.fix.breakingRisk}</span></div>
      <div class="fbtns"><button class="ab" onclick="pm({type:'openFile',idx:${idx}})">Jump to line</button>${prBtn}</div>
    </div>`);
  }

  // ── CREATE PR ───────────────────────────────────────────────────────────────
  private async _createPR(idx: number): Promise<void> {
    const f = this._sessionFindings[idx]; if(!f) return;
    const wsFolder = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath; if(!wsFolder) return;
    if (!this._prManager) this._prManager = new PRManager(wsFolder);

    const prereqs = await this._prManager.checkPrereqs();
    if (!prereqs.git) { this._bot(`<div class="pr-err"><div class="pr-err-t">❌ Git not found</div>Initialise a git repo first.</div>`); return; }
    if (!prereqs.gh) {
      this._bot(`<div class="pr-err"><div class="pr-err-t">❌ GitHub CLI not installed</div>
        <div style="margin-top:4px;">Install it to enable one-click PRs:</div>
        <div class="pr-cmd">brew install gh &amp;&amp; gh auth login</div>
        <div style="margin-top:4px;font-size:10px;">Or: <a href="https://cli.github.com" style="color:var(--vscode-textLink-foreground)">cli.github.com</a></div>
      </div>`); return;
    }
    if (f.fix.breakingRisk==='high') {
      this._bot(`<div class="pr-warn"><div class="pr-warn-t">⚠️ Manual review required</div>
        This fix has <strong>high breaking risk</strong> — cannot be auto-applied.<br>
        <span style="font-size:10px;margin-top:4px;display:block;">${f.fix.safetyNote}</span>
      </div>`); return;
    }

    const pid = `pr-p-${Date.now()}`;
    this._bot(`<div id="${pid}" class="pr-prog"><span class="spin">⚙</span> <span id="${pid}-t">Starting…</span></div>`);

    const result = await this._prManager.createFixPR(f, msg => {
      this._post({ type: 'updateMsg', id: `${pid}-t`, text: msg });
    });

    if (result.success && result.prUrl) {
      this._bot(`<div class="pr-ok">
        <div class="pr-ok-t">🎉 PR raised successfully</div>
        <div class="pr-row"><span class="pr-l">Rule:</span> <code>[${f.ruleId}]</code> ${f.name}</div>
        <div class="pr-row"><span class="pr-l">File:</span> <code>${path.basename(f.filePath)}:${f.line+1}</code></div>
        <div class="pr-row"><span class="pr-l">Branch:</span> <code style="font-size:10px;">${result.branch}</code></div>
        <div class="pr-row"><span class="pr-l">PR:</span> <a href="${result.prUrl}" style="color:var(--vscode-textLink-foreground);font-size:11px;" onclick="pm({type:'viewPR',url:'${result.prUrl}'});return false;">${result.prUrl.length>55?result.prUrl.slice(0,55)+'…':result.prUrl}</a></div>
        <div style="margin-top:6px;"><button class="ab pri" onclick="pm({type:'viewPR',url:'${result.prUrl}'})">Open PR on GitHub ↗</button></div>
      </div>`);
    } else {
      this._bot(`<div class="pr-err"><div class="pr-err-t">❌ PR creation failed</div><div style="font-size:11px;margin-top:4px;">${result.error}</div></div>`);
    }
  }

  // ── LIST PRs ────────────────────────────────────────────────────────────────
  private _listPRs(): void {
    if (!this._prManager) { this._bot('No PRs yet. Use <code>show N</code> then click <strong>Raise Fix PR</strong>.'); return; }
    const prs = this._prManager.listPRs();
    if (!prs.length) { this._bot('No PRs raised in this session.'); return; }
    const stC: Record<string,string> = {open:'#4ec9b0',merged:'#569cd6',closed:'#858585',error:'#f44747',pending:'#e8a202'};
    const rows = prs.map(p=>`<div class="pr-lr"><span style="color:${stC[p.state]||'#ccc'};font-weight:600;font-size:10px;width:45px;">${p.state}</span><code style="font-size:9px;flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${p.branch}</code>${p.prUrl?`<button class="ab" style="font-size:9px;padding:1px 5px;" onclick="pm({type:'viewPR',url:'${p.prUrl}'})">↗</button>`:''}</div>`).join('');
    this._bot(`<div style="font-size:11px;color:var(--vscode-descriptionForeground);margin-bottom:4px;">${prs.length} PR${prs.length!==1?'s':''} this session</div><div class="pr-list">${rows}</div>`);
  }

  // ── EXPLAIN / RULES / FILTER / REPORT / CLEAR / HELP / TIER2 ──────────────
  private _explain(id?: string): void {
    if (!id) { this._bot('Usage: <code>explain &lt;A0X&gt;</code>'); return; }
    const I: Record<string,[string,string,string]> = {
      'A01':['Broken Access Control','Users acting outside permissions. #1 since 2021.','IDOR, path traversal, CORS wildcard, missing auth checks.'],
      'A02':['Cryptographic Failures','Sensitive data exposed via weak crypto or key leakage.','Git history secrets, MITM on HTTP, MD5/SHA1 cracking.'],
      'A03':['Injection','Untrusted data sent to interpreter as command or query.','SQL injection, command injection, XSS, eval() abuse.'],
      'A04':['Insecure Design','Missing security controls in architecture.','Mass assignment, missing rate limiting, business logic flaws.'],
      'A05':['Security Misconfiguration','Insecure defaults, debug mode, exposed docs.','Stack trace disclosure, open Swagger, empty admin passwords.'],
      'A07':['Auth Failures','Weaknesses in authentication or session management.','JWT none algorithm, no lockout, session fixation.'],
      'A08':['Integrity Failures','Insecure deserialization, missing integrity checks.','pickle.loads RCE, PHP unserialize, Java ObjectInputStream.'],
      'A09':['Logging Failures','Insufficient logging = breaches go undetected.','Credentials logged, silent .catch() hiding security events.'],
      'A10':['SSRF','Server fetches attacker-controlled URL.','Access 169.254.169.254, internal services, Kubernetes API.'],
    };
    const p = id.slice(0,3); const e = I[p];
    if (!e) { this._bot(`Rule <code>${id}</code> not found.`); return; }
    this._bot(`<div class="ec"><div class="ec-t">${id} — ${e[0]}</div><div class="el">Why it matters</div><div>${e[1]}</div><div class="el">Attack vectors</div><div>${e[2]}</div><div style="font-size:10px;color:var(--vscode-textLink-foreground);margin-top:5px;">OWASP ${p}:2021</div></div>`);
  }

  private _rules(cat?: string): void {
    const ALL=[['A01-001','Path Traversal','high'],['A01-002','CORS Wildcard','medium'],['A01-003','IDOR','high'],['A02-001','Hardcoded Secret','critical'],['A02-002','Weak Hash','high'],['A02-003','Insecure Random','high'],['A02-004','Plaintext HTTP','medium'],['A02-005','ECB Mode','high'],['A03-001','SQL Injection','critical'],['A03-002','Command Injection','critical'],['A03-003','XSS','high'],['A03-004','eval() Injection','critical'],['A03-005','LDAP Injection','high'],['A04-001','Mass Assignment','high'],['A04-002','Missing Rate Limit','medium'],['A05-001','Debug Mode','high'],['A05-002','Default Credentials','critical'],['A05-003','Stack Trace','medium'],['A05-004','Missing Helmet','medium'],['A07-001','JWT None','critical'],['A07-002','Weak Password','medium'],['A07-003','Session Fixation','high'],['A08-001','Insecure Deserialize','critical'],['A09-001','Creds in Logs','high'],['A09-002','Silent Catch','low'],['A10-001','SSRF','high']];
    const fl = cat?ALL.filter(r=>r[0].startsWith(cat)):ALL;
    const SC: Record<string,string> = {critical:'#ff8080',high:'#f0a060',medium:'#e8c060',low:'#80c880'};
    const rows = fl.map(r=>`<tr><td style="font-family:monospace;color:#858585;font-size:10px;">${r[0]}</td><td>${r[1]}</td><td><span style="color:${SC[r[2]]};font-weight:600;font-size:10px;">${r[2].slice(0,4).toUpperCase()}</span></td></tr>`).join('');
    this._bot(`<div style="font-size:11px;color:var(--vscode-descriptionForeground);margin-bottom:4px;">${fl.length} rules${cat?` · ${cat}`:''}</div><table class="gt"><thead><tr><th>ID</th><th>Rule</th><th>Sev</th></tr></thead><tbody>${rows}</tbody></table>`);
  }

  private _filter(sev: Severity): void {
    if (!['critical','high','medium','low','off'].includes(sev)) { this._bot('Usage: <code>filter &lt;critical|high|medium|low|off&gt;</code>'); return; }
    vscode.workspace.getConfiguration('owaspGuardian').update('minSeverity',sev==='off'?'low':sev,vscode.ConfigurationTarget.Workspace);
    this._bot(`✅ Filter set to <strong>${sev==='off'?'all':sev}</strong>.`);
  }

  private async _report(fmt?: string): Promise<void> {
    if (!this._sessionFindings.length) { this._bot('No findings. Run <code>scan .</code> first.'); return; }
    const ws = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath; if(!ws) return;
    const dir = path.join(ws,'.guardian'); if(!fs.existsSync(dir)) fs.mkdirSync(dir,{recursive:true});
    const fmt2 = fmt||'md';
    const bySev = {critical:0,high:0,medium:0,low:0} as Record<Severity,number>;
    this._sessionFindings.forEach(f=>bySev[f.severity]++);
    let content='',outFile='';
    if(fmt2==='json'){content=JSON.stringify({scannedAt:new Date().toISOString(),total:this._sessionFindings.length,bySev,findings:this._sessionFindings},null,2);outFile=path.join(dir,'guardian-report.json');}
    else if(fmt2==='sarif'){content=JSON.stringify(this._sarif(),null,2);outFile=path.join(dir,'guardian-report.sarif');}
    else{content=this._md(bySev);outFile=path.join(dir,'guardian-report.md');}
    fs.writeFileSync(outFile,content,'utf8');
    const rel=path.relative(ws,outFile);
    this._bot(`✅ Report saved: <code>${rel}</code>`);
    vscode.workspace.openTextDocument(vscode.Uri.file(outFile)).then(d=>vscode.window.showTextDocument(d,vscode.ViewColumn.Beside));
  }

  private _clear(): void { this._sessionFindings=[];this._lastWorkspaceScan=undefined;this._post({type:'clearChat'});this._welcome(); }

  private _help(): void {
    this._bot(`<div class="hg2">
      <div class="hg"><div class="hgt">Scanning</div><div class="hr"><code>scan .</code><span>Workspace</span></div><div class="hr"><code>scan src/f.ts</code><span>One file</span></div><div class="hr"><code>filter high</code><span>Min severity</span></div></div>
      <div class="hg"><div class="hgt">Findings</div><div class="hr"><code>list</code><span>All findings</span></div><div class="hr"><code>list critical</code><span>Filter</span></div><div class="hr"><code>show 3</code><span>Detail + PR</span></div></div>
      <div class="hg"><div class="hgt">Rules</div><div class="hr"><code>rules</code><span>All 26 rules</span></div><div class="hr"><code>explain A03</code><span>Explanation</span></div></div>
      <div class="hg"><div class="hgt">Export & PRs</div><div class="hr"><code>report md</code><span>Markdown</span></div><div class="hr"><code>report sarif</code><span>GitHub scanning</span></div><div class="hr"><code>prs</code><span>List raised PRs</span></div></div>
      <div class="hg"><div class="hgt">Tier 2</div><div class="hr"><code>tier2</code><span>→ Claude Code</span></div><div style="font-size:10px;color:var(--vscode-descriptionForeground);margin-top:3px;">Auto-prompted after every scan</div></div>
      <div class="hg"><div class="hgt">Other</div><div class="hr"><code>clear</code><span>Reset session</span></div></div>
    </div>`);
  }

  private async _tier2(): Promise<void> {
    if (!this._sessionFindings.length) { this._bot('Run <code>scan .</code> first.'); return; }
    const ws=vscode.workspace.workspaceFolders?.[0]?.uri.fsPath; if(!ws) return;
    this._bot(`<span class="sa">🔗 Building Claude Code context…</span>`);
    const dir=path.join(ws,'.guardian'); if(!fs.existsSync(dir)) fs.mkdirSync(dir,{recursive:true});
    const jsonPath=path.join(dir,'guardian-output.json'); const ctxPath=path.join(dir,'claude-context.md');
    const bySev={critical:0,high:0,medium:0,low:0} as Record<Severity,number>;
    this._sessionFindings.forEach(f=>bySev[f.severity]++);
    fs.writeFileSync(jsonPath,JSON.stringify({meta:{scannedAt:new Date().toISOString(),total:this._sessionFindings.length,bySev},results:this._groupByFile()},null,2));
    const bp=path.join(this._extensionUri.fsPath,'cli','bridge.js');
    if(fs.existsSync(bp)){await new Promise<void>(res=>{cp.execFile('node',[bp,jsonPath,'--out',ctxPath,'--window','25'],()=>res());});}
    else{fs.writeFileSync(ctxPath,`# OWASP Guardian Context\n${this._sessionFindings.length} findings ready for Tier 2.`);}
    const claudeCmd=vscode.workspace.getConfiguration('owaspGuardian').get<string>('claudeCodePath','claude');
    const rel=path.relative(ws,ctxPath);
    this._bot(`<div class="t2r"><div class="t2r-t">✅ Context ready — Claude Code opening</div>
      <div class="t2r-r"><span class="t2r-l">Findings:</span><strong>${this._sessionFindings.length}</strong> (${bySev.critical} critical · ${bySev.high} high)</div>
      <div class="t2r-r"><span class="t2r-l">Context:</span><code style="font-family:monospace;font-size:10px;">${rel}</code></div>
      <div class="t2r-cmd">${claudeCmd} "${ctxPath}"</div>
      <div style="font-size:10px;color:var(--vscode-descriptionForeground);margin-top:4px;">Terminal opened. Type <code>/deep-scan</code> in Claude Code to begin deep analysis.</div>
    </div>`);
    const term=vscode.window.createTerminal({name:'Guardian → Claude Code',cwd:ws}); term.show(); term.sendText(`${claudeCmd} "${ctxPath}"`);
    vscode.workspace.openTextDocument(vscode.Uri.file(ctxPath)).then(d=>vscode.window.showTextDocument(d,vscode.ViewColumn.Beside));
  }

  // ── WELCOME ─────────────────────────────────────────────────────────────────
  private _welcome(): void {
    this._bot(`<div class="wlc"><div class="wl-ico">🛡</div><div class="wl-t">OWASP Guardian</div>
      <div class="wl-s">OWASP Top 10 · Auto Tier-2 prompt · One-click PRs</div>
      <div class="wl-qa">
        <button class="wqa-b" onclick="pm({type:'quickAction',text:'scan .'})">🔍 Scan workspace</button>
        <button class="wqa-b" onclick="pm({type:'quickAction',text:'rules'})">📋 View rules</button>
        <button class="wqa-b" onclick="pm({type:'quickAction',text:'help'})">❓ Help</button>
      </div>
    </div>`);
  }

  // ── Summary ─────────────────────────────────────────────────────────────────
  private _summary(results: ScanResult[]): void {
    const total = results.reduce((s,r)=>s+r.findings.length,0);
    if (!total) { this._bot(`<div style="color:var(--vscode-testing-iconPassed);">✅ No findings above configured threshold.</div>`); return; }
    const bySev={critical:0,high:0,medium:0,low:0} as Record<Severity,number>;
    results.flatMap(r=>r.findings).forEach(f=>bySev[f.severity]++);
    const C:Record<string,string>={critical:'#ff8080',high:'#f0a060',medium:'#e8c060',low:'#80c880'};
    const bars = (['critical','high','medium','low'] as Severity[]).filter(s=>bySev[s]>0)
      .map(s=>`<div class="sr"><span class="sl" style="color:${C[s]}">${s}</span><div class="st"><div class="sf" style="width:${Math.min(100,(bySev[s]/total)*100)}%;background:${C[s]}"></div></div><span class="sn" style="color:${C[s]}">${bySev[s]}</span></div>`).join('');
    const fileRows = results.filter(r=>r.findings.length>0).slice(0,5)
      .map(r=>`<div class="fr"><span class="fn" style="font-family:monospace;">${path.basename(r.filePath)}</span><span>${r.findings.length}${r.findings.filter(f=>f.severity==='critical').length>0?` <span style="color:#ff8080">(${r.findings.filter(f=>f.severity==='critical').length}cr)</span>`:''}</span></div>`).join('');
    this._bot(`<div class="ss"><div class="sh">Scan complete — <strong>${total}</strong> finding${total!==1?'s':''} in <strong>${results.filter(r=>r.findings.length>0).length}</strong> file${results.filter(r=>r.findings.length>0).length!==1?'s':''}</div>${bars}<div style="margin-top:6px;">${fileRows}</div><div class="sacts"><button class="ab" onclick="pm({type:'quickAction',text:'list'})">View all</button><button class="ab" onclick="pm({type:'quickAction',text:'list critical'})">Critical only</button><button class="ab pri" onclick="pm({type:'quickAction',text:'report md'})">Export report</button></div></div>`);
  }

  // ── Utils ────────────────────────────────────────────────────────────────────
  private async _initPR(): Promise<void> {
    const ws = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
    if (ws) this._prManager = new PRManager(ws);
  }
  private async _openFile(idx: number): Promise<void> {
    const f=this._sessionFindings[idx]; if(!f) return;
    const doc=await vscode.workspace.openTextDocument(vscode.Uri.file(f.filePath));
    const ed=await vscode.window.showTextDocument(doc);
    const pos=new vscode.Position(Math.min(f.line,doc.lineCount-1),0);
    ed.revealRange(new vscode.Range(pos,pos),vscode.TextEditorRevealType.InCenter);
    ed.selection=new vscode.Selection(pos,pos);
  }
  private _mergeFindings(results: ScanResult[]): void {
    const inc=results.flatMap(r=>r.findings.map(f=>({...f,filePath:r.filePath})));
    const paths=new Set(results.map(r=>r.filePath));
    this._sessionFindings=[...this._sessionFindings.filter(f=>!paths.has(f.filePath)),...inc]
      .sort((a,b)=>SEVERITY_RANK[b.severity]-SEVERITY_RANK[a.severity]||a.line-b.line);
  }
  private _groupByFile(){
    const m=new Map<string,typeof this._sessionFindings>();
    for(const f of this._sessionFindings){if(!m.has(f.filePath))m.set(f.filePath,[]);m.get(f.filePath)!.push(f);}
    return Array.from(m.entries()).map(([file,findings])=>({file,language:'unknown',findings}));
  }
  private _esc(s:string):string{return(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}
  private _md(bySev:Record<Severity,number>):string{return['# 🛡 OWASP Guardian',`Total: ${this._sessionFindings.length}  \nCritical: ${bySev.critical} · High: ${bySev.high}\n\n---\n`,...this._sessionFindings.map((f,i)=>`### ${i+1}. [${f.ruleId}] ${f.name}\n**File:** \`${path.basename(f.filePath)}:${f.line+1}\`\n${f.description}\n\`\`\`\n${f.codeSnippet}\n\`\`\`\n**Fix:** ${f.fix.description}\n\`\`\`\n${f.fix.code}\n\`\`\`\n---`)].join('\n');}
  private _sarif(){const rules=[...new Set(this._sessionFindings.map(f=>f.ruleId))].map(id=>{const f=this._sessionFindings.find(x=>x.ruleId===id)!;return{id,name:f.name,shortDescription:{text:f.name},helpUri:'https://owasp.org/Top10/'};});const sm:Record<Severity,string>={critical:'error',high:'error',medium:'warning',low:'note'};return{version:'2.1.0',runs:[{tool:{driver:{name:'OWASP Guardian',version:'1.1.0',rules}},results:this._sessionFindings.map(f=>({ruleId:f.ruleId,level:sm[f.severity],message:{text:f.description},locations:[{physicalLocation:{artifactLocation:{uri:f.filePath},region:{startLine:f.line+1}}}]}))}]};}
  private _post(m:object):void{this._view?.webview.postMessage(m);}
  private _echo(t:string):void{this._post({type:'userMessage',text:t});}
  private _bot(h:string):void{this._post({type:'assistantMessage',html:h});}

  // ── HTML ─────────────────────────────────────────────────────────────────────
  private _buildHtml():string{return`<!DOCTYPE html><html><head><meta charset="UTF-8"><meta http-equiv="Content-Security-Policy" content="default-src 'none';style-src 'unsafe-inline';script-src 'unsafe-inline';"><style>
*{box-sizing:border-box;margin:0;padding:0}body{font-family:var(--vscode-font-family);font-size:var(--vscode-font-size);color:var(--vscode-foreground);background:var(--vscode-sideBar-background);display:flex;flex-direction:column;height:100vh;overflow:hidden}
#chat{flex:1;overflow-y:auto;padding:8px 10px;display:flex;flex-direction:column;gap:5px}#chat::-webkit-scrollbar{width:4px}#chat::-webkit-scrollbar-thumb{background:var(--vscode-scrollbarSlider-background);border-radius:2px}
.msg{animation:fi .2s ease}@keyframes fi{from{opacity:0;transform:translateY(4px)}to{opacity:1;transform:translateY(0)}}
.msg-user{align-self:flex-end;background:var(--vscode-button-background);color:var(--vscode-button-foreground);padding:5px 9px;border-radius:10px 10px 2px 10px;font-size:12px;max-width:85%}
.msg-bot{align-self:flex-start;width:100%;font-size:12px;line-height:1.55}
#ib{background:var(--vscode-input-background);border-top:1px solid var(--vscode-panel-border);padding:6px 8px;display:flex;gap:5px;align-items:flex-end;flex-shrink:0}
#inp{flex:1;background:var(--vscode-input-background);border:1px solid var(--vscode-input-border);border-radius:5px;color:var(--vscode-input-foreground);font-family:var(--vscode-font-family);font-size:12px;padding:5px 8px;outline:none;resize:none;min-height:28px;max-height:100px;overflow-y:auto}
#inp:focus{border-color:var(--vscode-focusBorder)}
#sb{background:var(--vscode-button-background);color:var(--vscode-button-foreground);border:none;border-radius:5px;width:28px;height:28px;cursor:pointer;font-size:13px;display:flex;align-items:center;justify-content:center;flex-shrink:0}
#sb:hover{background:var(--vscode-button-hoverBackground)}
code{background:var(--vscode-textBlockQuote-background);padding:0 4px;border-radius:3px;font-family:monospace;font-size:11px}
.ab{background:var(--vscode-button-secondaryBackground);color:var(--vscode-button-secondaryForeground);border:1px solid var(--vscode-button-border,transparent);border-radius:4px;padding:3px 9px;cursor:pointer;font-size:11px}
.ab:hover{background:var(--vscode-button-secondaryHoverBackground)}.ab.pri{background:var(--vscode-button-background);color:var(--vscode-button-foreground)}.ab.pri:hover{background:var(--vscode-button-hoverBackground)}.ab:disabled{opacity:.45;cursor:not-allowed}
/* Scan summary */.ss{background:var(--vscode-editor-background);border:1px solid var(--vscode-panel-border);border-radius:6px;padding:9px 11px}.sh{font-weight:600;margin-bottom:6px}.sr{display:flex;align-items:center;gap:5px;margin-bottom:3px}.sl{width:52px;font-size:10px;font-weight:600}.st{flex:1;height:5px;background:var(--vscode-panel-border);border-radius:3px;overflow:hidden}.sf{height:100%;border-radius:3px;transition:width .5s}.sn{width:18px;text-align:right;font-weight:600;font-size:10px}.fr{display:flex;justify-content:space-between;font-size:11px;padding:2px 0;border-bottom:1px solid var(--vscode-panel-border)}.sacts{display:flex;flex-wrap:wrap;gap:4px;margin-top:7px}.sa{color:var(--vscode-descriptionForeground);font-style:italic;font-size:12px}
/* Tier2 prompt */.t2p{display:flex;gap:8px;background:var(--vscode-editor-background);border:1px solid var(--vscode-panel-border);border-left:3px solid #d97706;border-radius:0 6px 6px 0;padding:9px 11px}.t2p-ico{font-size:18px;flex-shrink:0}.t2p-title{font-weight:600;font-size:12px;margin-bottom:3px}.t2p-sub{font-size:11px;color:var(--vscode-descriptionForeground);line-height:1.5;margin-bottom:6px}.t2p-acts{display:flex;gap:5px;flex-wrap:wrap}.tp-yes{background:#d97706;color:#fff;border:none;border-radius:5px;padding:5px 12px;cursor:pointer;font-size:11px;font-weight:600}.tp-yes:hover{background:#b45309}.tp-no{background:none;border:1px solid var(--vscode-panel-border);color:var(--vscode-descriptionForeground);border-radius:5px;padding:5px 12px;cursor:pointer;font-size:11px}
/* Tier2 result */.t2r{background:var(--vscode-editor-background);border:1px solid var(--vscode-panel-border);border-radius:6px;padding:9px 11px}.t2r-t{font-weight:600;color:var(--vscode-testing-iconPassed);margin-bottom:6px}.t2r-r{display:flex;gap:5px;font-size:11px;margin-bottom:3px;flex-wrap:wrap}.t2r-l{color:var(--vscode-descriptionForeground);min-width:65px}.t2r-cmd{background:var(--vscode-textBlockQuote-background);border:1px solid var(--vscode-panel-border);border-radius:4px;padding:5px 8px;font-family:monospace;font-size:10px;margin:5px 0;overflow-x:auto;white-space:nowrap}
/* Findings */.gt{width:100%;border-collapse:collapse;font-size:11px}.gt th{text-align:left;padding:2px 4px;border-bottom:1px solid var(--vscode-panel-border);font-size:10px;color:var(--vscode-descriptionForeground);font-weight:500;text-transform:uppercase;letter-spacing:.04em}.gt td{padding:3px 4px;vertical-align:middle}.findings-t tr{border-bottom:1px solid var(--vscode-panel-border);cursor:pointer}.findings-t tr:hover td{background:var(--vscode-list-hoverBackground)}.sp{font-size:9px;font-weight:700;padding:1px 5px;border-radius:3px;white-space:nowrap}
/* Finding detail */.fd{background:var(--vscode-editor-background);border:1px solid var(--vscode-panel-border);border-radius:6px;padding:9px 11px}.fd-h{display:flex;align-items:center;gap:5px;margin-bottom:4px;flex-wrap:wrap}.fl{font-size:10px;font-weight:600;color:var(--vscode-descriptionForeground);text-transform:uppercase;letter-spacing:.04em;margin:7px 0 2px}.fb{font-size:11px;line-height:1.55}.fc{background:var(--vscode-textBlockQuote-background);border:1px solid var(--vscode-panel-border);border-radius:4px;padding:5px 7px;font-family:monospace;font-size:10px;overflow-x:auto;white-space:pre;line-height:1.5;margin:2px 0}.vc{border-left:2px solid #f44747}.xc{border-left:2px solid #4ec9b0}.fs{display:flex;gap:8px;flex-wrap:wrap;font-size:10px;margin-top:5px;color:var(--vscode-descriptionForeground)}.fbtns{display:flex;gap:5px;flex-wrap:wrap;margin-top:7px}
/* PR cards */.pr-ok{background:rgba(46,180,80,.07);border:1px solid rgba(46,180,80,.25);border-radius:6px;padding:9px 11px;font-size:11px}.pr-ok-t{font-weight:600;color:var(--vscode-testing-iconPassed);margin-bottom:5px}.pr-row{display:flex;gap:5px;margin-bottom:3px;flex-wrap:wrap}.pr-l{color:var(--vscode-descriptionForeground);min-width:50px}.pr-err{background:rgba(244,71,71,.07);border:1px solid rgba(244,71,71,.25);border-radius:6px;padding:9px 11px;font-size:11px}.pr-err-t{font-weight:600;color:#f44747;margin-bottom:4px}.pr-cmd{font-family:monospace;font-size:10px;background:var(--vscode-textBlockQuote-background);border:1px solid var(--vscode-panel-border);border-radius:4px;padding:4px 7px;margin-top:5px}.pr-warn{background:rgba(232,162,2,.07);border:1px solid rgba(232,162,2,.3);border-radius:6px;padding:9px 11px;font-size:11px}.pr-warn-t{font-weight:600;color:#e8a202;margin-bottom:4px}.pr-prog{display:flex;align-items:center;gap:6px;font-size:11px;color:var(--vscode-descriptionForeground);font-style:italic}.spin{animation:sp 1s linear infinite;display:inline-block}@keyframes sp{to{transform:rotate(360deg)}}.pr-list{display:flex;flex-direction:column;gap:4px}.pr-lr{display:flex;align-items:center;gap:5px;padding:4px 6px;background:var(--vscode-editor-background);border:1px solid var(--vscode-panel-border);border-radius:4px}
/* Help */.hg2{display:grid;grid-template-columns:1fr 1fr;gap:5px;font-size:11px}.hg{background:var(--vscode-editor-background);border:1px solid var(--vscode-panel-border);border-radius:5px;padding:6px 8px}.hgt{font-weight:600;margin-bottom:4px;font-size:11px}.hr{display:flex;gap:4px;margin-bottom:2px;align-items:baseline}.hr code{font-size:10px;white-space:nowrap}.hr span{color:var(--vscode-descriptionForeground);font-size:10px}
/* Explain */.ec{background:var(--vscode-editor-background);border:1px solid var(--vscode-panel-border);border-radius:6px;padding:9px 11px}.ec-t{font-weight:600;font-size:12px;margin-bottom:6px}.el{font-size:10px;font-weight:600;text-transform:uppercase;letter-spacing:.04em;color:var(--vscode-descriptionForeground);margin:5px 0 2px}
/* Welcome */.wlc{display:flex;flex-direction:column;align-items:center;padding:18px 10px;gap:5px;text-align:center}.wl-ico{font-size:26px}.wl-t{font-weight:600;font-size:13px}.wl-s{font-size:11px;color:var(--vscode-descriptionForeground);max-width:190px;line-height:1.5}.wl-qa{display:flex;flex-direction:column;gap:4px;width:100%;margin-top:5px}.wqa-b{background:var(--vscode-button-secondaryBackground);color:var(--vscode-button-secondaryForeground);border:1px solid var(--vscode-button-border,transparent);border-radius:4px;padding:5px 9px;cursor:pointer;font-size:11px;text-align:left}.wqa-b:hover{background:var(--vscode-button-secondaryHoverBackground)}
</style></head><body>
<div id="chat"></div>
<div id="ib"><textarea id="inp" placeholder="scan · list · show 1 · tier2 · prs · help" rows="1"></textarea><button id="sb">↑</button></div>
<script>
const vsc=acquireVsCodeApi();const chat=document.getElementById('chat');const inp=document.getElementById('inp');
function pm(m){vsc.postMessage(m);}
document.getElementById('sb').onclick=send;
inp.addEventListener('keydown',e=>{if(e.key==='Enter'&&!e.shiftKey){e.preventDefault();send();}});
inp.addEventListener('input',()=>{inp.style.height='auto';inp.style.height=Math.min(inp.scrollHeight,100)+'px';});
function send(){const t=inp.value.trim();if(!t)return;inp.value='';inp.style.height='auto';vsc.postMessage({type:'userInput',text:t});}
window.addEventListener('message',e=>{const m=e.data;
  if(m.type==='userMessage'){const d=document.createElement('div');d.className='msg msg-user';d.textContent=m.text;chat.appendChild(d);sc();}
  if(m.type==='assistantMessage'){const d=document.createElement('div');d.className='msg msg-bot';d.innerHTML=m.html;chat.appendChild(d);sc();}
  if(m.type==='clearChat')chat.innerHTML='';
  if(m.type==='prog'){const l=chat.lastElementChild;if(l){const a=l.querySelector('.sa');if(a)a.textContent='🔍 Scanning… '+m.done+'/'+m.total+' files';}}
  if(m.type==='updateMsg'){const e=document.getElementById(m.id);if(e)e.textContent=m.text;}
  if(m.type==='autoScanToast'){const d=document.createElement('div');d.className='msg msg-bot';d.innerHTML='<span style="font-size:11px;color:var(--vscode-descriptionForeground);">Auto-scan: <strong>'+m.file+'</strong> — <span style="color:#f0a060;font-weight:600;">'+m.count+' finding'+(m.count!==1?'s':'')+'</span> &nbsp;<button class="ab" onclick="pm({type:\'quickAction\',text:\'list\'})">View</button></span>';chat.appendChild(d);sc();}
});
function sc(){chat.scrollTop=chat.scrollHeight;}
</script></body></html>`;}
}
