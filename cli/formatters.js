// ─── Output Formatters ────────────────────────────────────────────────────────
'use strict';

const { c, SEV_COLOR, SEV_DOT, SAFE_BADGE, BREAK_COLOR, hr, bold, dim, codeBlock, muted } = require('./ui');
const { SEV_RANK } = require('./engine');

// ── Terminal ──────────────────────────────────────────────────────────────────

function printFinding(f, idx, filePath, showFix = true) {
  const sevLabel = SEV_COLOR[f.severity]?.(f.severity.toUpperCase()) ?? f.severity;
  const lineRef  = `${c.gray}${filePath}${c.reset}${c.gray}:${c.reset}${c.cyan}${f.line + 1}${c.reset}`;

  console.log(`\n  ${c.bold}${idx}. ${sevLabel} ${c.white}[${f.ruleId}] ${f.name}${c.reset}`);
  console.log(`     ${lineRef}`);
  console.log(`     ${c.gray}Category: ${c.reset}${f.category}`);
  console.log(`     ${c.gray}What:     ${c.reset}${f.description}`);

  // Vulnerable code
  console.log(`\n     ${c.red}● Vulnerable code${c.reset}`);
  const snippet = (f.codeSnippet || '').slice(0, 200);
  console.log(`     ${c.bgGray || c.gray}${c.white} line ${f.line+1} ${c.reset} ${c.red}${snippet}${c.reset}`);

  if (showFix) {
    console.log(`\n     ${c.green}● Suggested fix — ${f.fix.description}${c.reset}`);
    const codeLines = f.fix.code.split('\n');
    for (const ln of codeLines) {
      console.log(`     ${c.green}│${c.reset} ${c.cyan}${ln}${c.reset}`);
    }

    const safeStr  = f.fix.safe ? `${c.green}✔ Safe to apply${c.reset}` : `${c.yellow}⚠ Needs scrutiny${c.reset}`;
    const breakStr = BREAK_COLOR[f.fix.breakingRisk](`Breaking risk: ${f.fix.breakingRisk}`);
    console.log(`\n     ${safeStr}   ${breakStr}`);
    console.log(`     ${c.dim}${f.fix.safetyNote}${c.reset}`);
  }

  console.log(`\n     ${hr('·')}`);
}

function printSummary(summary, elapsed) {
  const { total, bySev, byCat, filesScanned } = summary;
  console.log();
  if (total === 0) {
    console.log(`  ${c.green}${c.bold}✔ No findings above configured severity.${c.reset}`);
    return;
  }

  console.log(`  ${c.bold}${c.white}SUMMARY${c.reset}  ${c.gray}(${filesScanned} files · ${elapsed}ms)${c.reset}\n`);

  // Severity bar
  const bars = [
    ['critical', c.red],
    ['high',     c.yellow],
    ['medium',   c.cyan],
    ['low',      c.blue],
  ];
  for (const [sev, col] of bars) {
    const n = bySev[sev];
    if (!n) continue;
    const bar = '█'.repeat(Math.min(n, 40));
    console.log(`  ${col}${sev.padEnd(8)}${c.reset}  ${col}${bar}${c.reset} ${c.bold}${n}${c.reset}`);
  }

  console.log();
  for (const [cat, n] of Object.entries(byCat).sort(([,a],[,b]) => b-a)) {
    console.log(`  ${c.gray}•${c.reset} ${cat.padEnd(50)} ${c.bold}${n}${c.reset}`);
  }
  console.log();
  console.log(`  ${c.bold}Total: ${total} finding${total !== 1 ? 's' : ''}${c.reset}`);
}

// ── JSON ──────────────────────────────────────────────────────────────────────

function toJson(results, summary) {
  return JSON.stringify({
    meta: { scannedAt: new Date().toISOString(), ...summary },
    results: results.map(r => ({
      file: r.filePath,
      language: r.lang,
      linesScanned: r.lines,
      findings: r.findings,
    })),
  }, null, 2);
}

// ── Markdown ──────────────────────────────────────────────────────────────────

function toMarkdown(results, summary) {
  const lines = [
    '# 🛡️ OWASP Guardian — Security Report',
    ``,
    `**Scanned:** ${new Date().toLocaleString()}  `,
    `**Files:** ${summary.filesScanned}  `,
    `**Total findings:** ${summary.total}  `,
    ``,
    '## Summary',
    '',
    '| Severity | Count |',
    '|----------|-------|',
    ...Object.entries(summary.bySev).filter(([,n])=>n).map(([s,n]) => `| ${s.toUpperCase()} | ${n} |`),
    '',
    '## Findings by Category',
    '',
    '| Category | Count |',
    '|----------|-------|',
    ...Object.entries(summary.byCat).sort(([,a],[,b])=>b-a).map(([c,n]) => `| ${c} | ${n} |`),
    '',
    '---',
    '',
    '## All Findings',
    '',
  ];

  let idx = 1;
  for (const r of results) {
    if (!r.findings.length) continue;
    const shortPath = r.filePath.split('/').slice(-2).join('/');
    lines.push(`### \`${shortPath}\``);
    for (const f of r.findings) {
      lines.push(
        ``,
        `#### ${idx}. [${f.ruleId}] ${f.name} — \`${f.severity.toUpperCase()}\``,
        ``,
        `- **Category:** ${f.category}`,
        `- **File:** \`${shortPath}:${f.line + 1}\``,
        ``,
        `**What's wrong:**  `,
        f.description,
        ``,
        `**Vulnerable code:**`,
        `\`\`\``,
        f.codeSnippet,
        `\`\`\``,
        ``,
        `**Suggested fix — ${f.fix.description}:**`,
        `\`\`\``,
        f.fix.code,
        `\`\`\``,
        ``,
        `**Safety:** ${f.fix.safetyNote}  `,
        `**Breaking risk:** ${f.fix.breakingRisk}`,
        ``,
        `---`,
      );
      idx++;
    }
  }

  return lines.join('\n');
}

// ── SARIF (GitHub Code Scanning compatible) ───────────────────────────────────

function toSarif(results) {
  const runs = [{
    tool: {
      driver: {
        name: 'OWASP Guardian',
        version: '1.0.0',
        rules: [],
      }
    },
    results: [],
  }];

  const rulesSeen = new Set();

  for (const r of results) {
    for (const f of r.findings) {
      if (!rulesSeen.has(f.ruleId)) {
        rulesSeen.add(f.ruleId);
        runs[0].tool.driver.rules.push({
          id: f.ruleId,
          name: f.name,
          shortDescription: { text: f.name },
          fullDescription: { text: f.description },
          helpUri: 'https://owasp.org/Top10/',
          properties: { tags: [f.category] },
        });
      }

      const sevMap = { critical: 'error', high: 'error', medium: 'warning', low: 'note' };
      runs[0].results.push({
        ruleId: f.ruleId,
        level: sevMap[f.severity],
        message: { text: f.description },
        locations: [{
          physicalLocation: {
            artifactLocation: { uri: r.filePath },
            region: {
              startLine: f.line + 1,
              startColumn: f.column + 1,
              endColumn: f.endColumn + 1,
            }
          }
        }],
        fixes: [{
          description: { text: f.fix.description },
        }],
      });
    }
  }

  return JSON.stringify({ version: '2.1.0', runs }, null, 2);
}

module.exports = { printFinding, printSummary, toJson, toMarkdown, toSarif };
