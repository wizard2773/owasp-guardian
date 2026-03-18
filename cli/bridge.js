#!/usr/bin/env node
// ─── OWASP Guardian → Claude Code Bridge ─────────────────────────────────────
// Tier 1 output (Guardian JSON) → Tier 2 input (focused Claude Code context)
// Usage: node cli/bridge.js [guardian-output.json] [--out context.md] [--window 20]
'use strict';

const fs   = require('fs');
const path = require('path');

// ── Parse args ────────────────────────────────────────────────────────────────
const args = process.argv.slice(2);
const inputFile  = args.find(a => !a.startsWith('--')) || 'guardian-output.json';
const outFlag    = args.indexOf('--out');
const outFile    = outFlag !== -1 ? args[outFlag + 1] : 'claude-context.md';
const winFlag    = args.indexOf('--window');
const WINDOW     = winFlag !== -1 ? parseInt(args[winFlag + 1]) : 25;
const minSevFlag = args.indexOf('--min-severity');
const MIN_SEV    = minSevFlag !== -1 ? args[minSevFlag + 1] : 'medium';

const SEV_RANK = { critical: 4, high: 3, medium: 2, low: 1 };

// ── Load Guardian output ──────────────────────────────────────────────────────
if (!fs.existsSync(inputFile)) {
  console.error(`[bridge] Error: ${inputFile} not found. Run 'guardian scan . --format json --out guardian-output.json' first.`);
  process.exit(1);
}

const raw = JSON.parse(fs.readFileSync(inputFile, 'utf8'));
const results = raw.results || [];

// Filter by minimum severity
const minRank = SEV_RANK[MIN_SEV] || 2;
const filtered = results
  .map(r => ({
    ...r,
    findings: (r.findings || []).filter(f => SEV_RANK[f.severity] >= minRank)
  }))
  .filter(r => r.findings.length > 0);

if (!filtered.length) {
  console.log(`[bridge] No findings above "${MIN_SEV}" severity. Nothing to send to Claude Code.`);
  process.exit(0);
}

// ── Build focused context per file ───────────────────────────────────────────
function extractContext(filePath, findings) {
  let fileLines = [];
  try {
    fileLines = fs.readFileSync(filePath, 'utf8').split('\n');
  } catch {
    return null; // file may have moved since scan
  }

  // Collect all line ranges needed (finding line ± WINDOW), merge overlaps
  const ranges = findings.map(f => ({
    start: Math.max(0, f.line - WINDOW),
    end:   Math.min(fileLines.length - 1, f.line + WINDOW),
    finding: f,
  }));

  // Sort and merge overlapping windows
  ranges.sort((a, b) => a.start - b.start);
  const merged = [];
  for (const r of ranges) {
    if (merged.length && r.start <= merged[merged.length - 1].end + 2) {
      merged[merged.length - 1].end = Math.max(merged[merged.length - 1].end, r.end);
      merged[merged.length - 1].findings.push(r.finding);
    } else {
      merged.push({ start: r.start, end: r.end, findings: [r.finding] });
    }
  }

  // Render each window as annotated code
  const sections = merged.map(window => {
    const header = window.findings.map(f =>
      `  [${f.ruleId}] ${f.severity.toUpperCase()} — ${f.name}: ${f.description}`
    ).join('\n');

    const codeLines = fileLines
      .slice(window.start, window.end + 1)
      .map((line, i) => {
        const absLine = window.start + i;
        const hit = window.findings.find(f => f.line === absLine);
        const marker = hit
          ? ` ◄ [${hit.ruleId}] ${hit.severity.toUpperCase()}`
          : '';
        return `${String(absLine + 1).padStart(4)} │ ${line}${marker}`;
      })
      .join('\n');

    return `<!-- Guardian flags in this window:\n${header}\n-->\n\`\`\`\n${codeLines}\n\`\`\``;
  });

  return sections.join('\n\n');
}

// ── Build the full Claude Code prompt ────────────────────────────────────────
const totalFindings = filtered.reduce((s, r) => s + r.findings.length, 0);
const bySev = { critical: 0, high: 0, medium: 0, low: 0 };
filtered.forEach(r => r.findings.forEach(f => bySev[f.severity]++));

const lines = [
  '# OWASP Guardian → Claude Code — Tiered Security Analysis',
  '',
  '## Context',
  '',
  `OWASP Guardian (Tier 1) scanned this repository and found **${totalFindings} findings** ` +
  `above "${MIN_SEV}" severity across **${filtered.length} files**.`,
  '',
  `| Severity | Count |`,
  `|----------|-------|`,
  ...Object.entries(bySev).filter(([,n]) => n > 0).map(([s, n]) => `| ${s.toUpperCase()} | ${n} |`),
  '',
  '## Your Task (Tier 2 — Deep Analysis)',
  '',
  'For each flagged location below, perform a **semantic security analysis** that Guardian cannot do:',
  '',
  '1. **Confirm or dismiss** — is this a real vulnerability or a false positive? Explain why.',
  '2. **Trace data flow** — follow the tainted value from its source across files/functions. Where does it land?',
  '3. **Assess exploitability** — what does an attacker actually need to exploit this? Is it reachable from an unauthenticated path?',
  '4. **Find what Guardian missed** — look at the surrounding code for chained vulnerabilities, missing auth checks, business logic flaws, or insecure patterns Guardian\'s rules cannot detect.',
  '5. **Rate actual risk** — Guardian rates by pattern severity; you should rate by actual exploitability in this specific codebase.',
  '6. **Write a precise fix** — a concrete, safe, tested code change specific to this codebase (not a generic template).',
  '',
  '> Be skeptical of Guardian\'s findings — it has no data flow awareness. A finding on line N may be protected by middleware you can see; say so.',
  '',
  '---',
  '',
  '## Flagged Files & Code Sections',
  '',
];

// Per-file sections
for (const result of filtered) {
  const relPath = path.relative(process.cwd(), result.file || result.filePath || '');
  const lang = result.language || 'unknown';

  lines.push(`### \`${relPath}\` (${lang})`);
  lines.push('');

  // Summary table for this file
  lines.push('| # | Rule | Severity | Finding |');
  lines.push('|---|------|----------|---------|');
  result.findings.forEach((f, i) => {
    lines.push(`| ${i+1} | ${f.ruleId} | ${f.severity.toUpperCase()} | ${f.name} — line ${f.line + 1} |`);
  });
  lines.push('');

  // Annotated code context
  const ctx = extractContext(result.file || result.filePath, result.findings);
  if (ctx) {
    lines.push(ctx);
  } else {
    lines.push(`> ⚠ Could not read file — it may have moved or been deleted since the scan.`);
    lines.push('');
    lines.push('**Guardian reported these snippets:**');
    result.findings.forEach(f => {
      lines.push('');
      lines.push(`**Line ${f.line + 1} — [${f.ruleId}] ${f.name}**`);
      lines.push('```');
      lines.push(f.codeSnippet || '(no snippet)');
      lines.push('```');
      lines.push(`> Guardian fix suggestion: ${f.fix?.description || 'n/a'}`);
    });
  }

  lines.push('');
  lines.push('---');
  lines.push('');
}

// Closing instructions
lines.push('## Output Format Expected');
lines.push('');
lines.push('For each finding, respond with:');
lines.push('');
lines.push('```');
lines.push('[FILE:LINE] RULE-ID — Finding Name');
lines.push('Status:      CONFIRMED | FALSE POSITIVE | NEEDS MORE CONTEXT');
lines.push('Real Risk:   CRITICAL | HIGH | MEDIUM | LOW | NONE');
lines.push('Data Flow:   <trace the value from source to sink across files>');
lines.push('Reachable:   <is this reachable by an attacker? what auth is required?>');
lines.push('Chained:     <any vulnerabilities Guardian missed in this area?>');
lines.push('Fix:         <precise, codebase-specific fix>');
lines.push('```');
lines.push('');
lines.push('End with a **prioritised action list** ordered by actual exploitability, not pattern severity.');

// ── Write output ──────────────────────────────────────────────────────────────
fs.writeFileSync(outFile, lines.join('\n'), 'utf8');

console.log(`[bridge] Context file written: ${outFile}`);
console.log(`[bridge] ${totalFindings} findings across ${filtered.length} files`);
console.log(`[bridge] Next step: claude ${outFile}`);
