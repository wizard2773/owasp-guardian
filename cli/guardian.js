#!/usr/bin/env node
// ─── OWASP Guardian – Interactive CLI ────────────────────────────────────────
'use strict';

const readline = require('readline');
const fs       = require('fs');
const path     = require('path');

const ui         = require('./ui');
const { scanFile, scanDirectory, summarise } = require('./scanner');
const { RULES, SEV_RANK }                    = require('./engine');
const { printFinding, printSummary, toJson, toMarkdown, toSarif } = require('./formatters');

const { c, bold, dim, hr, header, subheader, info, success, warn, error, muted, prompt } = ui;

// ── Session State ─────────────────────────────────────────────────────────────

const state = {
  cwd:      process.cwd(),
  results:  [],         // ScanResult[]
  findings: [],         // flattened Finding[] with filePath
  filter:   null,       // severity filter
  history:  [],         // command history
};

function flatFindings(results) {
  return results.flatMap(r => r.findings.map(f => ({ ...f, filePath: r.filePath })));
}

// ── Splash ────────────────────────────────────────────────────────────────────

function splash() {
  console.clear();
  console.log();
  console.log(paint(c.cyan + c.bold,
`   ██████╗ ██╗    ██╗ █████╗ ███████╗██████╗
  ██╔═══██╗██║    ██║██╔══██╗██╔════╝██╔══██╗
  ██║   ██║██║ █╗ ██║███████║███████╗██████╔╝
  ██║   ██║██║███╗██║██╔══██║╚════██║██╔═══╝
  ╚██████╔╝╚███╔███╔╝██║  ██║███████║██║
   ╚═════╝  ╚══╝╚══╝ ╚═╝  ╚═╝╚══════╝╚═╝`));

  console.log(`  ${c.bold}${c.white}G U A R D I A N${c.reset}   ${c.gray}OWASP Top 10 · Static Analysis · Zero Dependencies${c.reset}`);
  console.log();
  console.log(paint(c.gray, `  Type ${c.white}help${c.gray} to see all commands.  Type ${c.white}scan .${c.gray} to scan the current directory.`));
  console.log();
}

function paint(col, text) { return `${col}${text}${c.reset}`; }

// ── Command Definitions ───────────────────────────────────────────────────────

const COMMANDS = {

  // ── scan ──────────────────────────────────────────────────────────────────
  scan: {
    usage: 'scan [path]',
    short: 'Scan a file or directory (default: current directory)',
    examples: ['scan .', 'scan src/', 'scan app.js', 'scan /path/to/repo'],
    run(args) {
      const target = args[0] ? path.resolve(state.cwd, args[0]) : state.cwd;

      if (!fs.existsSync(target)) {
        error(`Path not found: ${target}`);
        return;
      }

      const stat = fs.statSync(target);
      const isDir = stat.isDirectory();

      console.log();
      info(`Scanning ${paint(c.cyan, target)}…\n`);

      const start = Date.now();
      let results;

      if (isDir) {
        let filesDone = 0;
        results = scanDirectory(target, {}, (done, total, file) => {
          filesDone = done;
          const pct = Math.round((done / total) * 100);
          process.stdout.write(`\r  ${c.gray}[${pct.toString().padStart(3)}%] ${done}/${total} files — ${path.basename(file).slice(0,40).padEnd(40)}${c.reset}`);
        });
        process.stdout.write('\r' + ' '.repeat(80) + '\r');
      } else {
        const r = scanFile(target);
        results = r ? [r] : [];
      }

      const elapsed = Date.now() - start;
      state.results = results;
      state.findings = flatFindings(results);

      const summary = summarise(results);
      printSummary(summary, elapsed);

      if (summary.total > 0) {
        console.log();
        info(`Run ${paint(c.white, 'list')} to see all findings.`);
        info(`Run ${paint(c.white, 'show <n>')} to inspect a specific finding.`);
        info(`Run ${paint(c.white, 'report md')} or ${paint(c.white, 'report json')} to export.`);
      }
    },
  },

  // ── list ──────────────────────────────────────────────────────────────────
  list: {
    usage: 'list [severity]',
    short: 'List all findings (optionally filter by severity)',
    examples: ['list', 'list critical', 'list high', 'list medium'],
    run(args) {
      let findings = state.findings;

      if (!findings.length) {
        warn('No findings. Run a scan first.');
        return;
      }

      const sevFilter = args[0]?.toLowerCase();
      if (sevFilter && ['critical','high','medium','low'].includes(sevFilter)) {
        findings = findings.filter(f => f.severity === sevFilter);
      }

      if (!findings.length) {
        info(`No ${sevFilter} findings.`);
        return;
      }

      console.log();
      const cols = [
        { label: '#',         width: 4  },
        { label: 'SEV',       width: 10 },
        { label: 'RULE',      width: 10 },
        { label: 'NAME',      width: 30 },
        { label: 'FILE',      width: 28 },
        { label: 'LINE',      width: 5  },
      ];

      console.log(`  ${c.bold}${cols.map(col => col.label.padEnd(col.width)).join('  ')}${c.reset}`);
      console.log(`  ${c.gray}${cols.map(col => '─'.repeat(col.width)).join('  ')}${c.reset}`);

      findings.forEach((f, i) => {
        const sevStr = ui.SEV_COLOR[f.severity]?.(f.severity.slice(0,4).toUpperCase()) ?? f.severity;
        const file = f.filePath.split('/').slice(-2).join('/');
        const name = f.name.length > 29 ? f.name.slice(0,28) + '…' : f.name;
        console.log([
          `  ${String(i + 1).padEnd(4)}`,
          `${sevStr.padEnd?.(10) ?? sevStr}  `,
          `${c.gray}${f.ruleId.padEnd(10)}${c.reset}  `,
          `${name.padEnd(30)}  `,
          `${c.cyan}${file.padEnd(28)}${c.reset}  `,
          `${c.cyan}${String(f.line + 1).padEnd(5)}${c.reset}`,
        ].join(''));
      });

      console.log();
      muted(`${findings.length} findings shown. Use 'show <n>' for details.`);
    },
  },

  // ── show ──────────────────────────────────────────────────────────────────
  show: {
    usage: 'show <n>',
    short: 'Show full details + fix for finding number <n>',
    examples: ['show 1', 'show 3'],
    run(args) {
      if (!state.findings.length) { warn('No findings. Run a scan first.'); return; }

      const n = parseInt(args[0]);
      if (isNaN(n) || n < 1 || n > state.findings.length) {
        error(`Invalid finding number. Use 1–${state.findings.length}.`);
        return;
      }

      const f = state.findings[n - 1];
      const file = f.filePath.split('/').slice(-2).join('/');
      printFinding(f, n, file, true);
    },
  },

  // ── explain ───────────────────────────────────────────────────────────────
  explain: {
    usage: 'explain <rule-id>',
    short: 'Explain what a rule detects and why it matters',
    examples: ['explain A03-001', 'explain A02-001', 'explain A07-001'],
    run(args) {
      const ruleId = args[0]?.toUpperCase();
      if (!ruleId) { error('Usage: explain <rule-id>  e.g. explain A03-001'); return; }

      const rule = RULES.find(r => r.id.toUpperCase() === ruleId);
      if (!rule) {
        error(`Rule ${ruleId} not found. Run 'rules' to list all rules.`);
        return;
      }

      console.log();
      console.log(`  ${c.bold}${c.white}[${rule.id}] ${rule.name}${c.reset}`);
      console.log(`  ${c.gray}Category: ${c.reset}${rule.category}`);
      console.log(`  ${c.gray}Severity: ${c.reset}${ui.SEV_COLOR[rule.severity]?.(rule.severity.toUpperCase()) ?? rule.severity}`);
      console.log(`  ${c.gray}Languages: ${c.reset}${rule.langs.join(', ')}`);
      console.log();

      const owasp = {
        'A01': `Broken Access Control — occurs when users can act outside their intended permissions. Include path traversal, IDOR, and CORS misconfiguration.`,
        'A02': `Cryptographic Failures — sensitive data exposed due to weak or missing encryption, bad hash algorithms, or insecure key storage.`,
        'A03': `Injection — untrusted data sent to an interpreter as part of a command or query. Includes SQL, command, XSS, and eval injection.`,
        'A04': `Insecure Design — missing or ineffective security controls baked into the architecture. Includes mass assignment and missing rate limiting.`,
        'A05': `Security Misconfiguration — insecure default configs, debug mode enabled, unneeded features, missing security headers.`,
        'A07': `Identification & Authentication Failures — weaknesses in authentication logic, session management, or credential handling.`,
        'A08': `Software & Data Integrity Failures — insecure deserialization, missing integrity checks on data or pipelines.`,
        'A09': `Security Logging & Monitoring Failures — insufficient logging, sensitive data in logs, or silent error handling.`,
        'A10': `Server-Side Request Forgery — server fetches a URL controlled by the attacker, allowing access to internal services.`,
      };

      const prefix = ruleId.slice(0,3);
      const owaspDesc = owasp[prefix];
      if (owaspDesc) {
        console.log(`  ${c.bold}OWASP Context${c.reset}`);
        console.log(`  ${owaspDesc}`);
        console.log();
      }

      console.log(`  ${c.bold}Reference${c.reset}`);
      console.log(`  ${c.cyan}https://owasp.org/Top10/${c.reset}`);
    },
  },

  // ── rules ─────────────────────────────────────────────────────────────────
  rules: {
    usage: 'rules [category]',
    short: 'List all detection rules',
    examples: ['rules', 'rules A03', 'rules A02'],
    run(args) {
      const filter = args[0]?.toUpperCase();
      let rules = RULES;
      if (filter) rules = rules.filter(r => r.id.startsWith(filter));

      if (!rules.length) { warn(`No rules match "${filter}"`); return; }

      console.log();
      console.log(`  ${c.bold}${c.white}${'ID'.padEnd(12)} ${'SEVERITY'.padEnd(10)} ${'RULE NAME'.padEnd(36)} LANGUAGES${c.reset}`);
      console.log(`  ${c.gray}${'─'.repeat(80)}${c.reset}`);

      let lastCat = '';
      for (const r of rules) {
        const cat = r.id.slice(0,3);
        if (cat !== lastCat) {
          lastCat = cat;
          const catNames = { A01:'Broken Access Control', A02:'Cryptographic Failures', A03:'Injection', A04:'Insecure Design', A05:'Security Misconfiguration', A07:'Auth Failures', A08:'Integrity Failures', A09:'Logging Failures', A10:'SSRF' };
          console.log(`\n  ${c.bold}${c.cyan}── ${cat}: ${catNames[cat] || cat}${c.reset}`);
        }
        const sevStr = ui.SEV_COLOR[r.severity]?.(r.severity.slice(0,4).toUpperCase()) ?? r.severity;
        const langs = r.langs.map(l => l.slice(0,2)).join(' ');
        console.log(`  ${c.gray}${r.id.padEnd(12)}${c.reset} ${sevStr.padEnd?.(10) ?? sevStr}  ${r.name.slice(0,35).padEnd(36)} ${c.gray}${langs}${c.reset}`);
      }
      console.log();
      muted(`${rules.length} rules. Use 'explain <id>' for details on any rule.`);
    },
  },

  // ── report ────────────────────────────────────────────────────────────────
  report: {
    usage: 'report <format> [output-file]',
    short: 'Export findings as json | md | sarif',
    examples: ['report md', 'report json findings.json', 'report sarif results.sarif'],
    run(args) {
      if (!state.findings.length && !state.results.length) {
        warn('No scan results. Run a scan first.');
        return;
      }

      const fmt = (args[0] || 'md').toLowerCase();
      const outFile = args[1];
      const summary = summarise(state.results);

      let content;
      let defaultExt;

      if (fmt === 'json') {
        content = toJson(state.results, summary);
        defaultExt = 'owasp-report.json';
      } else if (fmt === 'md' || fmt === 'markdown') {
        content = toMarkdown(state.results, summary);
        defaultExt = 'owasp-report.md';
      } else if (fmt === 'sarif') {
        content = toSarif(state.results);
        defaultExt = 'owasp-report.sarif';
      } else {
        error(`Unknown format "${fmt}". Use: json | md | sarif`);
        return;
      }

      const outPath = outFile ? path.resolve(state.cwd, outFile) : path.join(state.cwd, defaultExt);
      fs.writeFileSync(outPath, content, 'utf8');
      success(`Report saved: ${paint(c.cyan, outPath)}`);
      info(`${summary.total} findings exported in ${fmt.toUpperCase()} format.`);
    },
  },

  // ── filter ────────────────────────────────────────────────────────────────
  filter: {
    usage: 'filter <severity>',
    short: 'Set minimum severity filter for future scans',
    examples: ['filter critical', 'filter high', 'filter medium', 'filter low'],
    run(args) {
      const sev = args[0]?.toLowerCase();
      if (!['critical','high','medium','low','off'].includes(sev)) {
        error('Usage: filter <critical|high|medium|low|off>');
        return;
      }
      state.filter = sev === 'off' ? null : sev;
      success(`Filter set to: ${paint(c.bold, sev === 'off' ? 'none (show all)' : sev)}`);
    },
  },

  // ── cd ────────────────────────────────────────────────────────────────────
  cd: {
    usage: 'cd <path>',
    short: 'Change working directory',
    examples: ['cd ..', 'cd ~/projects/myapp', 'cd /srv/app'],
    run(args) {
      const target = args[0] ? path.resolve(state.cwd, args[0].replace(/^~/, process.env.HOME || '')) : process.env.HOME || '/';
      if (!fs.existsSync(target)) { error(`Directory not found: ${target}`); return; }
      if (!fs.statSync(target).isDirectory()) { error(`Not a directory: ${target}`); return; }
      state.cwd = target;
      success(`Working directory: ${paint(c.cyan, state.cwd)}`);
    },
  },

  // ── pwd ───────────────────────────────────────────────────────────────────
  pwd: {
    usage: 'pwd',
    short: 'Show current working directory',
    examples: ['pwd'],
    run() {
      info(`Current directory: ${paint(c.cyan, state.cwd)}`);
    },
  },

  // ── clear ─────────────────────────────────────────────────────────────────
  clear: {
    usage: 'clear',
    short: 'Clear the terminal',
    examples: ['clear'],
    run() { console.clear(); splash(); },
  },

  // ── reset ─────────────────────────────────────────────────────────────────
  reset: {
    usage: 'reset',
    short: 'Clear session findings and results',
    examples: ['reset'],
    run() {
      state.results  = [];
      state.findings = [];
      success('Session cleared.');
    },
  },

  // ── stats ─────────────────────────────────────────────────────────────────
  stats: {
    usage: 'stats',
    short: 'Show summary statistics for the last scan',
    examples: ['stats'],
    run() {
      if (!state.results.length) { warn('No scan results. Run a scan first.'); return; }
      const summary = summarise(state.results);
      printSummary(summary, 0);
    },
  },

  // ── help ──────────────────────────────────────────────────────────────────
  help: {
    usage: 'help [command]',
    short: 'Show help',
    examples: ['help', 'help scan', 'help report'],
    run(args) {
      const cmd = args[0];
      if (cmd && COMMANDS[cmd]) {
        const def = COMMANDS[cmd];
        console.log();
        console.log(`  ${c.bold}${c.white}${def.usage}${c.reset}`);
        console.log(`  ${def.short}`);
        if (def.examples?.length) {
          console.log();
          console.log(`  ${c.gray}Examples:${c.reset}`);
          for (const ex of def.examples) console.log(`    ${c.cyan}${ex}${c.reset}`);
        }
        console.log();
        return;
      }

      console.log();
      console.log(`  ${c.bold}${c.white}OWASP Guardian CLI${c.reset}  ${c.gray}— OWASP Top 10 static analysis${c.reset}\n`);

      const groups = [
        { label: 'Scanning',   cmds: ['scan', 'stats', 'reset'] },
        { label: 'Findings',   cmds: ['list', 'show', 'filter'] },
        { label: 'Rules',      cmds: ['rules', 'explain'] },
        { label: 'Export',     cmds: ['report'] },
        { label: 'Navigation', cmds: ['cd', 'pwd'] },
        { label: 'Other',      cmds: ['help', 'clear', 'exit'] },
      ];

      for (const g of groups) {
        console.log(`  ${c.bold}${c.cyan}${g.label}${c.reset}`);
        for (const name of g.cmds) {
          const def = COMMANDS[name];
          if (!def) continue;
          console.log(`    ${c.white}${def.usage.padEnd(30)}${c.reset}  ${c.gray}${def.short}${c.reset}`);
        }
        console.log();
      }

      muted('Use "help <command>" for detailed usage of any command.');
    },
  },

  // ── exit ──────────────────────────────────────────────────────────────────
  exit: {
    usage: 'exit',
    short: 'Exit OWASP Guardian',
    examples: ['exit'],
    run() {
      console.log();
      muted('Goodbye.');
      console.log();
      process.exit(0);
    },
  },
};

// Aliases
COMMANDS.quit = COMMANDS.exit;
COMMANDS.ls   = COMMANDS.list;
COMMANDS.q    = COMMANDS.exit;
COMMANDS.h    = COMMANDS.help;

// ── Input Parser ──────────────────────────────────────────────────────────────

function dispatch(input) {
  const trimmed = input.trim();
  if (!trimmed) return;

  state.history.push(trimmed);

  const [cmdName, ...args] = trimmed.split(/\s+/);
  const def = COMMANDS[cmdName.toLowerCase()];

  if (!def) {
    error(`Unknown command: ${cmdName}. Type 'help' to see available commands.`);
    return;
  }

  try {
    def.run(args);
  } catch(e) {
    error(`Command failed: ${e.message}`);
  }
}

// ── Non-interactive / single-command mode (CLI args) ─────────────────────────

function runCli(argv) {
  if (argv.length === 0) return false;  // start interactive

  // guardian scan .
  // guardian scan ./src --format json --out report.json
  // guardian --help
  if (argv[0] === '--help' || argv[0] === '-h') {
    COMMANDS.help.run([]);
    process.exit(0);
  }

  if (argv[0] === '--version' || argv[0] === '-v') {
    console.log('OWASP Guardian v1.0.0');
    process.exit(0);
  }

  // Parse: guardian <cmd> [args...] [--format fmt] [--out file] [--severity sev]
  const cmdName = argv[0];
  const def = COMMANDS[cmdName];
  if (!def) {
    error(`Unknown command: ${cmdName}`);
    process.exit(1);
  }

  // Parse flags
  const flagArgs = [];
  for (let i = 1; i < argv.length; i++) {
    if (argv[i] === '--format' || argv[i] === '-f') { i++; continue; }
    if (argv[i] === '--out' || argv[i] === '-o')    { i++; continue; }
    if (argv[i] === '--severity' || argv[i] === '-s') { i++; continue; }
    flagArgs.push(argv[i]);
  }

  const fmtIdx = argv.indexOf('--format');
  const outIdx = argv.indexOf('--out');
  const sevIdx = argv.indexOf('--severity');

  if (sevIdx !== -1 && argv[sevIdx+1]) {
    COMMANDS.filter.run([argv[sevIdx+1]]);
  }

  def.run(flagArgs);

  // Auto-export if --format given
  if (fmtIdx !== -1 && argv[fmtIdx+1]) {
    const outFile = outIdx !== -1 ? argv[outIdx+1] : undefined;
    COMMANDS.report.run([argv[fmtIdx+1], outFile].filter(Boolean));
  }

  return true;
}

// ── REPL ──────────────────────────────────────────────────────────────────────

function startRepl() {
  splash();

  const rl = readline.createInterface({
    input:  process.stdin,
    output: process.stdout,
    terminal: true,
    historySize: 100,
    completer(line) {
      const completions = Object.keys(COMMANDS);
      const hits = completions.filter(c => c.startsWith(line));
      return [hits.length ? hits : completions, line];
    },
  });

  rl.on('close', () => { console.log(); muted('Goodbye.'); console.log(); process.exit(0); });

  // Show working dir in prompt
  function ask() {
    const cwdShort = state.cwd.replace(process.env.HOME || '', '~');
    process.stdout.write(`\n${c.bold}${c.cyan}guardian${c.reset} ${c.gray}(${cwdShort.slice(-35)})›${c.reset} `);
  }

  function loop() {
    ask();
    rl.once('line', (input) => {
      dispatch(input);
      loop();
    });
  }

  loop();
}

// ── Entry Point ───────────────────────────────────────────────────────────────

const argv = process.argv.slice(2);
const ranCli = runCli(argv);
if (!ranCli) startRepl();
