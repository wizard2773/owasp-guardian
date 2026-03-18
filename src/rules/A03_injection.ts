// ─── A03: Injection ────────────────────────────────────────────────────────────

import { Finding, Language, OwaspCategory, RuleContext, SecurityRule } from '../types';
import { isCommentLine, makeFinding, scanLines, stripInlineComment } from '../ruleHelpers';

const ALL: Language[] = ['javascript','typescript','javascriptreact','typescriptreact','python','java','php','go','ruby','csharp'];

// ── A03-001: SQL Injection ────────────────────────────────────────────────────
export const sqlInjection: SecurityRule = {
  id: 'A03-001',
  category: OwaspCategory.A03,
  name: 'SQL Injection',
  severity: 'critical',
  languages: ALL,
  detect(ctx: RuleContext): Finding[] {
    const findings: Finding[] = [];

    // Trigger: a SQL keyword appears in a string with concatenation / f-string / template literal
    const sqlConcat = [
      // JS/TS template literal with SQL
      /(?:SELECT|INSERT|UPDATE|DELETE|WHERE|FROM)\s+.*`[^`]*\$\{/i,
      // JS/TS string concatenation
      /(?:SELECT|INSERT|UPDATE|DELETE|WHERE|FROM)\s+['"][^'"]*['"]\s*\+\s*(?:req\.|request\.|params\.|query\.|body\.|\w+Id|\w+Name)/i,
      // Python f-string with SQL
      /f['"].*(?:SELECT|INSERT|UPDATE|DELETE|WHERE|FROM).*\{/i,
      // Python % formatting with SQL
      /(?:SELECT|INSERT|UPDATE|DELETE|WHERE|FROM).*%\s*(?:\(|req\.|request\.|\w+\[)/i,
      // Python .format() with SQL
      /(?:SELECT|INSERT|UPDATE|DELETE|WHERE|FROM).*\.format\(/i,
      // PHP string concat with SQL
      /\$(?:sql|query)\s*=\s*.*(?:SELECT|INSERT|UPDATE|DELETE|WHERE).*\.\s*\$/i,
      // Java string concat with SQL
      /(?:SELECT|INSERT|UPDATE|DELETE|WHERE|FROM).*"\s*\+\s*\w+/i,
    ];

    for (const pattern of sqlConcat) {
      findings.push(...scanLines(ctx, this, pattern,
        () => `SQL Injection: user-controlled data is concatenated directly into a SQL query. An attacker can inject arbitrary SQL, bypassing authentication, exfiltrating data, or deleting records.`,
        (_, line) => ({
          description: 'Use parameterized queries or a prepared statement',
          code: `// Node.js (pg/mysql2/better-sqlite3 — parameterized):\nconst result = await db.query(\n  'SELECT * FROM users WHERE id = $1 AND email = $2',\n  [userId, email]  // values bound safely\n);\n\n// Python (psycopg2):\ncursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))\n\n// Java (JDBC PreparedStatement):\nPreparedStatement ps = conn.prepareStatement(\n  "SELECT * FROM users WHERE id = ? AND email = ?"\n);\nps.setInt(1, userId);\nps.setString(2, email);`,
          safe: false,
          safetyNote: '⚠️ Needs scrutiny — parameterization changes query structure. Verify column names and data types match.',
          breakingRisk: 'low',
        })
      ));
    }

    // Deduplicate by line
    const seen = new Set<number>();
    return findings.filter(f => { if (seen.has(f.line)) return false; seen.add(f.line); return true; });
  }
};

// ── A03-002: Command Injection ────────────────────────────────────────────────
export const commandInjection: SecurityRule = {
  id: 'A03-002',
  category: OwaspCategory.A03,
  name: 'Command Injection',
  severity: 'critical',
  languages: ALL,
  detect(ctx: RuleContext): Finding[] {
    const findings: Finding[] = [];
    // exec / system / spawn / shell calls with string concatenation or template literals containing user input
    const patterns = [
      /(?:exec|execSync|spawnSync|child_process\.exec)\s*\(\s*[`'"].*\$\{/,
      /(?:exec|execSync)\s*\(\s*['"].*['"]\s*\+/,
      /(?:os\.system|subprocess\.(?:call|run|Popen))\s*\(.*(?:f'|f"|format\(|\+\s*(?:request|req)\.|%\s*(?:request|req)\.)/i,
      /Runtime\.getRuntime\(\)\.exec\s*\(\s*(?:.*\+|new String\[\]\{)/,
      /shell_exec\s*\(\s*(?:\$_(?:GET|POST|REQUEST)|.*\.\s*\$)/i,
      /\bsystem\s*\(\s*(?:\$_(?:GET|POST|REQUEST)|.*\$\w)/i,
    ];
    for (const pattern of patterns) {
      findings.push(...scanLines(ctx, this, pattern,
        () => `Command Injection: shell command is built with user-controlled data. An attacker can inject additional commands using shell metacharacters (; & | ` + '`' + ` $()).`,
        () => ({
          description: 'Avoid shell expansion — pass arguments as an array',
          code: `// Node.js — use spawn with an argument array (no shell)\nconst { spawn } = require('child_process');\nconst child = spawn('ffmpeg', ['-i', sanitizedFilename, '-o', outputFile], {\n  shell: false  // CRITICAL: never set shell: true with user input\n});\n\n// Python — pass list, not string\nimport subprocess\nsubprocess.run(['ls', '-la', safe_path], shell=False)  # shell=False is default\n\n// If you must use shell: whitelist the allowed values\nconst ALLOWED = ['report', 'export'];\nif (!ALLOWED.includes(userInput)) throw new Error('Invalid option');`,
          safe: false,
          safetyNote: '⚠️ Needs scrutiny — refactoring from shell string to argument array requires understanding the full command.',
          breakingRisk: 'medium',
        })
      ));
    }
    const seen = new Set<number>();
    return findings.filter(f => { if (seen.has(f.line)) return false; seen.add(f.line); return true; });
  }
};

// ── A03-003: XSS (Cross-Site Scripting) ──────────────────────────────────────
export const xss: SecurityRule = {
  id: 'A03-003',
  category: OwaspCategory.A03,
  name: 'Cross-Site Scripting (XSS)',
  severity: 'high',
  languages: ['javascript','typescript','javascriptreact','typescriptreact','php','ruby'],
  detect(ctx: RuleContext): Finding[] {
    const findings: Finding[] = [];
    const patterns = [
      // innerHTML / outerHTML with a non-literal value
      /\.(?:innerHTML|outerHTML)\s*=\s*(?!['"`]<[a-zA-Z])/,
      // document.write with a variable
      /document\.write\s*\(\s*(?!\s*['"`][^'"` +$]*['"`]\s*\))/,
      // dangerouslySetInnerHTML without sanitization nearby
      /dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:/,
    ];
    for (const pattern of patterns) {
      findings.push(...scanLines(ctx, this, pattern,
        (match) => `XSS: DOM is written with potentially untrusted HTML. If user input reaches this assignment, attackers can inject scripts that run in the victim's browser.`,
        () => ({
          description: 'Sanitize HTML before insertion, or use textContent for plain text',
          code: `// For plain text — never use innerHTML:\nelement.textContent = userInput;  // Safe: no HTML parsing\n\n// For trusted HTML — sanitize with DOMPurify:\nimport DOMPurify from 'dompurify';\nelement.innerHTML = DOMPurify.sanitize(userHtml, {\n  ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'a'],\n  ALLOWED_ATTR: ['href']\n});\n\n// React — avoid dangerouslySetInnerHTML; use a component:\n// import parse from 'html-react-parser';  (sanitize first)`,
          safe: false,
          safetyNote: '⚠️ Needs scrutiny — confirm whether the content is truly user-controlled. Use textContent for plain text; add DOMPurify for HTML.',
          breakingRisk: 'low',
        })
      ));
    }
    const seen = new Set<number>();
    return findings.filter(f => { if (seen.has(f.line)) return false; seen.add(f.line); return true; });
  }
};

// ── A03-004: eval() with Dynamic Input ───────────────────────────────────────
export const evalInjection: SecurityRule = {
  id: 'A03-004',
  category: OwaspCategory.A03,
  name: 'eval() / exec() Code Injection',
  severity: 'critical',
  languages: ['javascript','typescript','javascriptreact','typescriptreact','python','ruby','php'],
  detect(ctx: RuleContext): Finding[] {
    const findings: Finding[] = [];
    const evalPattern = /\beval\s*\(\s*(?!['"`][^'"` +$]*['"`]\s*\))/;
    const pyExec = /\bexec\s*\(\s*(?!['"`][a-zA-Z_][^'"` +$]*['"`]\s*\))/;

    for (let i = 0; i < ctx.lines.length; i++) {
      const raw = ctx.lines[i];
      if (isCommentLine(raw, ctx.language)) { continue; }
      const line = stripInlineComment(raw, ctx.language);
      const isJs = ['javascript','typescript','javascriptreact','typescriptreact'].includes(ctx.language);
      const isPy = ctx.language === 'python';

      let match: RegExpMatchArray | null = null;
      if (isJs && (match = line.match(evalPattern))) { /* ok */ }
      else if ((isPy || !isJs) && (match = line.match(pyExec))) { /* ok */ }
      else { continue; }

      // Skip if it's clearly a literal string eval (no variables)
      if (/eval\s*\(\s*['"`][^'"` +${]*['"`]\s*\)/.test(line)) { continue; }

      const col = line.indexOf(match[0]);
      findings.push(makeFinding(this, i, col, col + match[0].length, raw,
        `eval() called with a potentially dynamic argument. If user input reaches eval(), an attacker can execute arbitrary code on the server or in the browser.`,
        {
          description: 'Remove eval() — parse data with safe alternatives',
          code: `// For JSON: use JSON.parse() — never eval()\nconst data = JSON.parse(userInput);  // Throws on invalid JSON\n\n// For math expressions: use a safe parser library\n// import { evaluate } from 'mathjs';\n// const result = evaluate('2 + 3 * x', { x: 4 });\n\n// For configuration: use structured data formats (JSON/YAML)\n// Never accept code from users — redesign the feature instead.`,
          safe: false,
          safetyNote: '⚠️ Needs scrutiny — removing eval() requires understanding what it currently evaluates. The replacement depends on the use case.',
          breakingRisk: 'high',
        },
        [ctx.lines[i - 1] ?? '', ctx.lines[i + 1] ?? '']
      ));
    }
    return findings;
  }
};

// ── A03-005: LDAP Injection ───────────────────────────────────────────────────
export const ldapInjection: SecurityRule = {
  id: 'A03-005',
  category: OwaspCategory.A03,
  name: 'LDAP Injection',
  severity: 'high',
  languages: ['javascript','typescript','python','java','php','csharp'],
  detect(ctx: RuleContext): Finding[] {
    return scanLines(ctx, this,
      /ldap(?:search|query|filter|bind).*(?:\+|f['"]|\$\{|format\().*(?:req\.|request\.|params\.|query\.|input|user)/i,
      () => `LDAP Injection: user input is inserted into an LDAP filter without escaping. Attackers can bypass authentication or access unauthorized directory entries.`,
      () => ({
        description: 'Escape LDAP special characters in user input',
        code: `// Escape LDAP filter special chars before inserting user input\nfunction escapeLdap(input: string): string {\n  return input\n    .replace(/\\\\/g, '\\\\\\\\')\n    .replace(/\\*/g, '\\\\*')\n    .replace(/\\(/g, '\\\\(')\n    .replace(/\\)/g, '\\\\)')\n    .replace(/\\0/g, '\\\\00');\n}\nconst safeFilter = \`(uid=\${escapeLdap(req.body.username)})\`;`,
        safe: true,
        safetyNote: '✅ Safe to apply — pure escaping with no functional change.',
        breakingRisk: 'none',
      })
    );
  }
};
