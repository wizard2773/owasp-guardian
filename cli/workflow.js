#!/usr/bin/env node
// ─── OWASP Guardian Tiered Workflow Orchestrator ─────────────────────────────
// Runs Tier 1 (Guardian scan) then Tier 2 (Claude Code context prep) in one command
//
// Usage:
//   node cli/workflow.js [target-path] [options]
//
// Options:
//   --min-severity critical|high|medium|low   (default: medium)
//   --window N        lines of context around each finding (default: 25)
//   --out-dir DIR     where to write outputs (default: .guardian/)
//   --no-open         don't auto-open context file in Claude Code
//   --only-tier1      just scan, don't build Claude Code context
//   --dry-run         show what would be scanned, don't scan
'use strict';

const path  = require('path');
const fs    = require('fs');
const { scanDirectory, scanFile, summarise } = require('./scanner');
const { toJson } = require('./formatters');
const ui    = require('./ui');
const { SEV_RANK } = require('./engine');

const { c, bold, info, success, warn, error, muted, hr } = ui;

// ── Parse args ────────────────────────────────────────────────────────────────
const argv = process.argv.slice(2);

function flag(name, def) {
  const i = argv.indexOf(name);
  return i !== -1 ? argv[i + 1] : def;
}
function hasFlag(name) { return argv.includes(name); }

const target      = argv.find(a => !a.startsWith('--')) || '.';
const MIN_SEV     = flag('--min-severity', 'medium');
const WINDOW      = parseInt(flag('--window', '25'));
const OUT_DIR     = flag('--out-dir', '.guardian');
const ONLY_TIER1  = hasFlag('--only-tier1');
const DRY_RUN     = hasFlag('--dry-run');

// ── Setup ─────────────────────────────────────────────────────────────────────

function paint(col, text) { return `${col}${text}${c.reset}`; }

function printBanner() {
  console.log();
  console.log(paint(c.bold + c.white, '┌─────────────────────────────────────────────────┐'));
  console.log(paint(c.bold + c.white, '│') + paint(c.bold + c.yellow, '  🛡 OWASP Guardian — Tiered Workflow             ') + paint(c.bold + c.white, '│'));
  console.log(paint(c.bold + c.white, '│') + paint(c.gray, '  Tier 1: Pattern scan  →  Tier 2: Claude Code    ') + paint(c.bold + c.white, '│'));
  console.log(paint(c.bold + c.white, '└─────────────────────────────────────────────────┘'));
  console.log();
}

// ── Tier 1: Guardian scan ─────────────────────────────────────────────────────

async function runTier1(targetPath) {
  console.log(paint(c.bold + c.cyan, '── TIER 1: OWASP Guardian Pattern Scan'));
  console.log();

  const absTarget = path.resolve(targetPath);
  if (!fs.existsSync(absTarget)) {
    error(`Target not found: ${absTarget}`);
    process.exit(1);
  }

  if (DRY_RUN) {
    info(`[dry-run] Would scan: ${absTarget}`);
    return null;
  }

  const start = Date.now();
  info(`Scanning: ${paint(c.cyan, absTarget)}`);
  console.log();

  let results;
  const stat = fs.statSync(absTarget);

  if (stat.isDirectory()) {
    let done = 0;
    results = scanDirectory(absTarget, {}, (d, total, file) => {
      done = d;
      process.stdout.write(
        `\r  ${c.gray}[${Math.round((d/total)*100).toString().padStart(3)}%] ${d}/${total} — ${path.basename(file).slice(0,40).padEnd(40)}${c.reset}`
      );
    });
    process.stdout.write('\r' + ' '.repeat(70) + '\r');
  } else {
    const r = scanFile(absTarget);
    results = r ? [r] : [];
  }

  const elapsed = Date.now() - start;
  const summary = summarise(results);
  const minRank = SEV_RANK[MIN_SEV] || 2;

  // Filter by min severity
  const filtered = results.map(r => ({
    ...r,
    findings: r.findings.filter(f => SEV_RANK[f.severity] >= minRank)
  })).filter(r => r.findings.length > 0);

  const filteredSummary = summarise(filtered);

  // Print summary
  console.log(`  ${c.bold}${c.white}Tier 1 Results${c.reset}  ${c.gray}(${elapsed}ms · min-severity: ${MIN_SEV})${c.reset}\n`);

  const sevColors = [
    ['critical', c.red],
    ['high',     c.yellow],
    ['medium',   c.cyan],
    ['low',      c.blue],
  ];
  for (const [sev, col] of sevColors) {
    const n = summary.bySev[sev];
    if (!n) continue;
    const bar = '█'.repeat(Math.min(n, 35));
    const filtered_n = filteredSummary.bySev[sev] || 0;
    const suffix = filtered_n < n ? paint(c.gray, ` (${filtered_n} above threshold)`) : '';
    console.log(`  ${col}${sev.padEnd(9)}${c.reset} ${col}${bar}${c.reset} ${c.bold}${n}${c.reset}${suffix}`);
  }
  console.log();
  console.log(`  ${c.bold}Total:${c.reset} ${summary.total} findings in ${summary.filesScanned} files`);
  console.log(`  ${c.bold}Above threshold:${c.reset} ${filteredSummary.total} findings in ${filtered.length} files`);
  console.log();

  if (filteredSummary.total === 0) {
    success(`No findings above "${MIN_SEV}" severity. Nothing to escalate to Tier 2.`);
    return { results, filtered, summary, filteredSummary };
  }

  // Write Tier 1 JSON output
  if (!fs.existsSync(OUT_DIR)) fs.mkdirSync(OUT_DIR, { recursive: true });
  const jsonPath = path.join(OUT_DIR, 'guardian-output.json');
  const jsonContent = toJson(filtered, filteredSummary);
  fs.writeFileSync(jsonPath, jsonContent, 'utf8');
  success(`Tier 1 output saved: ${paint(c.cyan, jsonPath)}`);

  return { results, filtered, summary, filteredSummary, jsonPath };
}

// ── Tier 2: Build Claude Code context ────────────────────────────────────────

function runTier2(jsonPath, filteredSummary) {
  console.log();
  console.log(paint(c.bold + c.cyan, '── TIER 2: Claude Code Context Builder'));
  console.log();

  const { execSync } = require('child_process');
  const contextPath = path.join(OUT_DIR, 'claude-context.md');
  const bridgePath  = path.join(__dirname, 'bridge.js');

  info(`Building focused context for Claude Code...`);

  try {
    execSync(
      `node "${bridgePath}" "${jsonPath}" --out "${contextPath}" --window ${WINDOW} --min-severity ${MIN_SEV}`,
      { stdio: 'inherit' }
    );
  } catch (e) {
    error(`Bridge failed: ${e.message}`);
    return;
  }

  // Print what Claude Code should do with this
  console.log();
  console.log(paint(c.bold + c.white, `  ┌─ How to run Tier 2 ───────────────────────────`));

  const methods = [
    {
      label: 'Claude Code (recommended)',
      cmd: `claude "${contextPath}"`,
      note: 'Opens Claude Code with full context loaded',
    },
    {
      label: 'Claude Code with project',
      cmd: `cd <your-repo> && claude "${path.resolve(contextPath)}"`,
      note: 'Gives Claude Code access to the full codebase for cross-file tracing',
    },
    {
      label: 'Paste into Claude.ai',
      cmd: `cat "${contextPath}" | pbcopy  (macOS) / xclip (Linux)`,
      note: 'Paste the context file contents directly into claude.ai',
    },
  ];

  methods.forEach((m, i) => {
    console.log(paint(c.bold + c.white, `  │`));
    console.log(`  ${c.bold}${c.white}│${c.reset}  ${c.bold}${i+1}. ${m.label}${c.reset}`);
    console.log(`  ${c.bold}${c.white}│${c.reset}  ${c.cyan}${m.cmd}${c.reset}`);
    console.log(`  ${c.bold}${c.white}│${c.reset}  ${c.gray}${m.note}${c.reset}`);
  });

  console.log(paint(c.bold + c.white, `  └────────────────────────────────────────────────`));

  return contextPath;
}

// ── Print what Claude Code should focus on ───────────────────────────────────

function printClaudeCodeInstructions(filteredSummary) {
  console.log();
  console.log(paint(c.bold + c.cyan, '── What Claude Code will do that Guardian cannot'));
  console.log();

  const capabilities = [
    ['Data flow tracing',    'Follows tainted input across files, functions, and await chains'],
    ['False positive check', 'Confirms if middleware/guards elsewhere actually protect the flagged code'],
    ['Chain discovery',      'Finds vulnerabilities that require 2+ steps (SSRF→IDOR, XSS→session theft)'],
    ['Business logic flaws', 'Detects auth bypass, price manipulation, race conditions — no pattern needed'],
    ['Cross-file IDOR',      'Traces object ownership checks across controller → service → repository layers'],
    ['Exploitability rating','Rates by actual attacker reach, not just pattern severity'],
  ];

  for (const [cap, desc] of capabilities) {
    console.log(`  ${c.green}▸${c.reset} ${c.bold}${cap.padEnd(22)}${c.reset} ${c.gray}${desc}${c.reset}`);
  }
  console.log();
}

// ── Write CLAUDE.md for the project ──────────────────────────────────────────

function writeClaudeMd(contextPath, summary) {
  const claudeMdPath = path.join(OUT_DIR, 'CLAUDE.md');
  const content = [
    '# OWASP Guardian Security Context',
    '',
    '## What this is',
    '',
    'This repository has been pre-scanned by OWASP Guardian (Tier 1 static analysis).',
    'Your job as Tier 2 is to perform deep semantic security analysis on the flagged locations.',
    '',
    '## Guardian scan summary',
    '',
    `- Total findings: ${summary.total}`,
    `- Files flagged: ${summary.filesScanned}`,
    `- Critical: ${summary.bySev.critical} · High: ${summary.bySev.high} · Medium: ${summary.bySev.medium} · Low: ${summary.bySev.low}`,
    '',
    '## Your analysis priorities',
    '',
    '1. **Data flow** — trace every flagged value from HTTP input to its sink. Cross file boundaries.',
    '2. **Auth coverage** — Guardian flags missing auth in ±8 lines. Check if middleware registered elsewhere actually covers it.',
    '3. **Confirm or dismiss** — Guardian has no data flow awareness. Many findings may be false positives.',
    '4. **Find chained vulns** — a SSRF + an IDOR in the same codebase can be combined. Look for chains.',
    '5. **Business logic** — look for price manipulation, role bypass, race conditions near flagged code.',
    '',
    '## What Guardian already checked',
    '',
    '- A01: Path traversal, CORS wildcard, IDOR (pattern-only)',
    '- A02: Hardcoded secrets, weak hashes, insecure random, HTTP URLs, ECB mode',
    '- A03: SQL injection, command injection, XSS, eval(), LDAP injection',
    '- A04: Mass assignment, missing rate limiting',
    '- A05: Debug mode, default credentials, stack traces, missing helmet',
    '- A07: JWT none algorithm, weak password policy, session fixation',
    '- A08: Insecure deserialization',
    '- A09: Credentials in logs, silent error handlers',
    '- A10: SSRF',
    '',
    '## What Guardian cannot check (your job)',
    '',
    '- Cross-file data flow',
    '- Auth middleware registered in a different file',
    '- Business logic vulnerabilities',
    '- Chained vulnerabilities',
    '- Exploitability in context',
    '- Race conditions',
    '- Second-order injection (stored then later executed)',
    '',
    `## Context file`,
    '',
    `The full annotated context is in: \`${contextPath}\``,
  ].join('\n');

  fs.writeFileSync(claudeMdPath, content, 'utf8');
  success(`CLAUDE.md written: ${paint(c.cyan, claudeMdPath)}`);
  return claudeMdPath;
}

// ── Main ──────────────────────────────────────────────────────────────────────

async function main() {
  printBanner();

  info(`Target:        ${paint(c.cyan, path.resolve(target))}`);
  info(`Min severity:  ${paint(c.bold, MIN_SEV)}`);
  info(`Context window: ±${WINDOW} lines`);
  info(`Output dir:    ${paint(c.cyan, path.resolve(OUT_DIR))}`);
  console.log();

  // Tier 1
  const tier1 = await runTier1(target);
  if (!tier1 || DRY_RUN) return;

  if (tier1.filteredSummary.total === 0) return;

  if (ONLY_TIER1) {
    info('--only-tier1 set. Skipping Tier 2 context build.');
    return;
  }

  // Tier 2
  const contextPath = runTier2(tier1.jsonPath, tier1.filteredSummary);
  writeClaudeMd(contextPath, tier1.filteredSummary);
  printClaudeCodeInstructions(tier1.filteredSummary);

  // Final summary
  console.log();
  console.log(hr('═', c.cyan));
  console.log();
  success(`Workflow complete.`);
  console.log();
  console.log(`  ${c.bold}${c.white}Tier 1 found:${c.reset}  ${tier1.filteredSummary.total} findings in ${tier1.filtered.length} files`);
  console.log(`  ${c.bold}${c.white}Sent to Tier 2:${c.reset} ${paint(c.cyan, path.resolve(contextPath))}`);
  console.log();
  console.log(`  ${c.bold}Run Claude Code now:${c.reset}`);
  console.log(`  ${c.cyan}  claude "${path.resolve(contextPath)}"${c.reset}`);
  console.log();
}

main().catch(e => { error(e.message); process.exit(1); });
