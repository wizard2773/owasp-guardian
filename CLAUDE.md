# OWASP Guardian — Claude Code Project Context

## What this project is

A tiered security analysis system:

- **Tier 1 (OWASP Guardian)**: Fast, offline, regex-based OWASP Top 10 scanner. Zero dependencies. Works on JS/TS/Python/Java/PHP/Go/Ruby/C#. Produces JSON, Markdown, and SARIF output.
- **Tier 2 (Claude Code)**: Deep semantic analysis of files Guardian flagged. Performs data flow tracing, false positive triage, chain discovery, and business logic analysis.

## Project structure

```
owasp-guardian/
├── cli/
│   ├── guardian.js     ← Interactive CLI REPL (the main entry point)
│   ├── engine.js       ← All 24 detection rules (pure regex, no deps)
│   ├── scanner.js      ← File walker and per-file scan runner
│   ├── formatters.js   ← JSON, Markdown, SARIF output
│   ├── bridge.js       ← Tier 1 → Tier 2 context builder
│   ├── workflow.js     ← Tiered workflow orchestrator
│   └── ui.js           ← ANSI terminal UI utilities
├── src/                ← TypeScript source for the VS Code extension
│   ├── extension.ts    ← Extension entry point
│   ├── analyzer.ts     ← Orchestrates rules per document
│   ├── types.ts        ← Shared interfaces
│   ├── ruleHelpers.ts  ← scanLines(), scanLinesWithContext() helpers
│   ├── rules/          ← One file per OWASP category
│   │   ├── A01_access_control.ts
│   │   ├── A02_cryptographic.ts
│   │   ├── A03_injection.ts
│   │   ├── A04_A10_rules.ts
│   │   └── index.ts
│   ├── providers/
│   │   ├── diagnosticProvider.ts
│   │   ├── hoverProvider.ts
│   │   └── codeActionProvider.ts
│   └── webview/
│       └── reportPanel.ts
├── .claude/
│   └── commands/
│       └── deep-scan.md   ← /deep-scan slash command for Tier 2 analysis
├── .guardian/             ← Generated output directory
│   ├── guardian-output.json
│   ├── claude-context.md
│   └── CLAUDE.md
└── test/
    └── fixtures/
        └── vulnerable.js  ← Intentionally vulnerable test fixture
```

## Tiered workflow commands

```bash
# Full workflow: Tier 1 scan → build Claude Code context → open
node cli/workflow.js [target] [--min-severity high] [--window 25]

# Tier 1 only
node cli/guardian.js scan [target]
node cli/guardian.js scan . --format json --out .guardian/guardian-output.json

# Build Tier 2 context from existing Tier 1 output
node cli/bridge.js .guardian/guardian-output.json --out .guardian/claude-context.md

# Tier 2: open context in Claude Code
claude .guardian/claude-context.md

# Use the slash command inside Claude Code
/deep-scan .guardian/claude-context.md
```

## Adding a new rule

1. Open `cli/engine.js`
2. Add a rule object to the `RULES` array:

```javascript
{
  id: 'A03-006',
  category: 'A03 – Injection',
  name: 'My New Rule',
  severity: 'high',
  langs: ['javascript', 'typescript'],
  run(lines, lang) {
    return scanLines(lines, lang,
      /my-dangerous-pattern/i,
      (match) => `Description of what's wrong`,
      (match) => ({
        description: 'How to fix it',
        code: '// Safe replacement',
        safe: true,
        safetyNote: '✔ Safe to apply',
        breakingRisk: 'none'
      }),
      this.id, this.category, this.name, this.severity
    );
  }
}
```

3. Mirror the rule in `src/rules/` for the VS Code extension.

## What Guardian can and cannot detect

### Can detect (pattern-based)
- Hardcoded secrets, weak hashes, ECB mode, plaintext HTTP
- SQL/command/LDAP injection via string concatenation or template literals
- XSS via innerHTML/dangerouslySetInnerHTML
- eval() with dynamic arguments
- CORS wildcard, missing helmet, debug mode
- IDOR (pattern only — DB lookup with user-supplied ID, no visible ownership check in ±8 lines)
- JWT none algorithm, weak password policies
- Insecure deserialization (pickle, PHP unserialize, Java ObjectInputStream)
- SSRF (user-controlled URL fed to http client, no visible validation)

### Cannot detect (needs Claude Code Tier 2)
- Cross-file data flow (tainted value tracked across modules)
- Auth middleware registered in a different file
- Business logic vulnerabilities (price manipulation, role bypass, race conditions)
- Chained vulnerabilities
- Second-order injection (stored, then later executed)
- Exploitability in context (a finding may be unreachable due to upstream auth)
- Custom guard names not in Guardian's keyword list

## Guardian's false positive patterns

Be aware of these when reviewing Guardian findings:

- **Insecure random**: Only fires when a security-context word (token, secret, session, etc.) appears within ±3 lines. Can still fire on non-security uses.
- **IDOR**: Only fires when no ownership check appears in ±8 lines. Middleware registered in app.module.ts will not be seen.
- **Hardcoded secret**: Skips `process.env` reads and common placeholder values, but can fire on test fixtures.
- **SSRF**: Looks for HTTP client calls with a variable URL. Can fire on API clients that always call a fixed service.
- **SQL injection**: Template literal with SQL keyword + `${...}` always fires. Can fire on safe parameterized queries that happen to use template literals for the query string itself (not the values).
