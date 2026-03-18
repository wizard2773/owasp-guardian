// ─── OWASP Guardian – Rules Engine (pure JS, no deps) ─────────────────────────
'use strict';

// ── Helpers ──────────────────────────────────────────────────────────────────

const SINGLE_LINE_COMMENT = {
  javascript: /^\s*(\/\/|\/\*|\*)/,
  typescript: /^\s*(\/\/|\/\*|\*)/,
  python:     /^\s*#/,
  java:       /^\s*(\/\/|\/\*|\*)/,
  php:        /^\s*(\/\/|#|\/\*|\*)/,
  go:         /^\s*(\/\/|\/\*|\*)/,
  ruby:       /^\s*#/,
  csharp:     /^\s*(\/\/|\/\*|\*)/,
};

function isComment(line, lang) {
  const re = SINGLE_LINE_COMMENT[lang];
  return re ? re.test(line) : false;
}

function stripComment(line, lang) {
  if (['javascript','typescript','java','csharp','go'].includes(lang)) {
    const idx = line.indexOf('//');
    if (idx !== -1) {
      const before = line.slice(0, idx);
      if ((before.match(/'/g)||[]).length % 2 === 0 && (before.match(/"/g)||[]).length % 2 === 0) {
        return before;
      }
    }
  }
  return line;
}

function scanLines(lines, lang, pattern, descFn, fixFn, ruleId, category, name, severity) {
  const findings = [];
  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i];
    if (isComment(raw, lang)) continue;
    const stripped = stripComment(raw, lang);
    const match = stripped.match(pattern);
    if (!match) continue;
    const col = stripped.indexOf(match[0]);
    findings.push({
      ruleId, category, name, severity,
      line: i, column: col, endColumn: col + match[0].length,
      codeSnippet: raw.trim(),
      description: descFn(match, raw),
      fix: fixFn(match, raw),
      context: [lines[i-1] || '', lines[i+1] || ''],
    });
  }
  return findings;
}

function dedup(findings) {
  const seen = new Set();
  return findings.filter(f => {
    const k = `${f.ruleId}:${f.line}`;
    if (seen.has(k)) return false;
    seen.add(k); return true;
  });
}

// ── Rule Definitions ─────────────────────────────────────────────────────────

const RULES = [

  // ── A01 ───────────────────────────────────────────────────────────────────

  {
    id: 'A01-001', category: 'A01 – Broken Access Control', name: 'Path Traversal', severity: 'high',
    langs: ['javascript','typescript','python','java','php','go','ruby','csharp'],
    run(lines, lang) {
      return scanLines(lines, lang,
        /(?:open|readFile|readFileSync|path\.join|os\.path\.join|File\(|fopen|include|require)\s*\(.*(?:req\.|request\.|params\.|query\.|body\.|args\[|\$_GET|\$_POST)/i,
        () => 'User-controlled input flows directly into a file-system call. An attacker can supply "../../../etc/passwd" to read arbitrary files.',
        () => ({ description: 'Validate and jail path to a base directory', code: `const BASE = path.resolve('./safe-files');\nconst target = path.resolve(BASE, userInput);\nif (!target.startsWith(BASE)) throw new Error('Path traversal blocked');`, safe: false, safetyNote: '⚠ Confirm BASE_DIR matches your structure', breakingRisk: 'low' }),
        this.id, this.category, this.name, this.severity);
    }
  },

  {
    id: 'A01-002', category: 'A01 – Broken Access Control', name: 'CORS Wildcard', severity: 'medium',
    langs: ['javascript','typescript','python','java','php','go','ruby','csharp'],
    run(lines, lang) {
      return scanLines(lines, lang,
        /(?:Access-Control-Allow-Origin['"\s:,]+\*|origin\s*[:=]\s*['"`]\*['"`]|cors\(\s*\{[^}]*origin\s*:\s*['"`]\*['"`])/i,
        () => 'CORS allows all origins (*). Any website can make credentialed cross-origin requests to your API.',
        () => ({ description: 'Restrict to an explicit allowlist of trusted origins', code: `app.use(cors({\n  origin: ['https://app.yourdomain.com'],\n  credentials: true,\n}));`, safe: false, safetyNote: '⚠ Replace with your real origin list', breakingRisk: 'medium' }),
        this.id, this.category, this.name, this.severity);
    }
  },

  {
    id: 'A01-003', category: 'A01 – Broken Access Control', name: 'IDOR – No Ownership Check', severity: 'high',
    langs: ['javascript','typescript','python','java','php','ruby','csharp'],
    run(lines, lang) {
      const findings = [];
      const idPat = /(?:findById|findOne|getById|find_by_id|where.*id\s*=)\s*\(?\s*(?:req\.|request\.|params\.|query\.|body\.)(?:id|userId|account_id|user_id)/i;
      const authPat = /(?:req\.user|currentUser|session\.user|isAuthorized|checkOwnership|authorize|hasPermission|userId\s*===)/i;
      for (let i = 0; i < lines.length; i++) {
        const raw = lines[i];
        if (isComment(raw, lang)) continue;
        if (!idPat.test(stripComment(raw, lang))) continue;
        const window = lines.slice(Math.max(0,i-8), Math.min(lines.length, i+8)).join('\n');
        if (authPat.test(window)) continue;
        const col = raw.search(idPat);
        findings.push({ ruleId: this.id, category: this.category, name: this.name, severity: this.severity, line: i, column: Math.max(0,col), endColumn: Math.max(0,col)+20, codeSnippet: raw.trim(),
          description: 'DB record fetched by user-supplied ID with no visible ownership check. Attackers can enumerate other users\' data.',
          fix: { description: 'Add ownership check after fetch', code: `const record = await Model.findById(req.params.id);\nif (!record) return res.status(404).end();\nif (String(record.userId) !== String(req.user.id))\n  return res.status(403).json({ error: 'Forbidden' });`, safe: false, safetyNote: '⚠ Confirm ownership field name matches your schema', breakingRisk: 'low' },
          context: [lines[i-1]||'', lines[i+1]||''] });
      }
      return findings;
    }
  },

  // ── A02 ───────────────────────────────────────────────────────────────────

  {
    id: 'A02-001', category: 'A02 – Cryptographic Failures', name: 'Hardcoded Secret', severity: 'critical',
    langs: ['javascript','typescript','python','java','php','go','ruby','csharp'],
    run(lines, lang) {
      const pat = /(?:password|passwd|secret|api_?key|apikey|auth_?token|access_?token|client_?secret|private_?key|jwt_?secret|db_?pass)\s*(?:=|:)\s*['"`]([^'"`\s]{4,})['"`]/i;
      const skip = /^(your[_-]|change|replace|example|placeholder|todo|xxx|<|CHANGE|INSERT|fill|dummy|fake|test|sample|demo)/i;
      const findings = [];
      for (let i = 0; i < lines.length; i++) {
        const raw = lines[i];
        if (isComment(raw, lang)) continue;
        const line = stripComment(raw, lang);
        const m = line.match(pat);
        if (!m || skip.test(m[1])) continue;
        if (/process\.env|os\.environ|getenv/.test(line)) continue;
        const col = line.indexOf(m[0]);
        findings.push({ ruleId: this.id, category: this.category, name: this.name, severity: this.severity, line: i, column: col, endColumn: col+m[0].length, codeSnippet: raw.trim(),
          description: `Credential hardcoded in source: "${m[0].slice(0,50)}". Readable from git history even after removal.`,
          fix: { description: 'Load from environment variable', code: `const secret = process.env.MY_SECRET;\nif (!secret) throw new Error('MY_SECRET not set');`, safe: true, safetyNote: '✔ Safe — standard practice. Rotate the exposed secret immediately.', breakingRisk: 'none' },
          context: [lines[i-1]||'', lines[i+1]||''] });
      }
      return findings;
    }
  },

  {
    id: 'A02-002', category: 'A02 – Cryptographic Failures', name: 'Weak Hash (MD5/SHA-1)', severity: 'high',
    langs: ['javascript','typescript','python','java','php','go','ruby','csharp'],
    run(lines, lang) {
      return scanLines(lines, lang,
        /(?:createHash|hashlib\.new|MessageDigest\.getInstance)\s*\(?\s*['"`](md5|sha1|sha-1)['"`]/i,
        (m) => `${m[1].toUpperCase()} is cryptographically broken — vulnerable to collision attacks.`,
        (m) => ({ description: `Replace with SHA-256 or bcrypt (passwords)`, code: `// Integrity check:\ncrypto.createHash('sha256').update(data).digest('hex');\n// Passwords:\nawait bcrypt.hash(password, 12);`, safe: true, safetyNote: '✔ Safe for new code. Existing stored hashes need migration.', breakingRisk: 'medium' }),
        this.id, this.category, this.name, this.severity);
    }
  },

  {
    id: 'A02-003', category: 'A02 – Cryptographic Failures', name: 'Insecure Randomness', severity: 'high',
    langs: ['javascript','typescript','python','ruby','php'],
    run(lines, lang) {
      const findings = [];
      const trigPat = /Math\.random\(\)|random\.random\(\)|rand\(\)/;
      const secPat = /(?:token|secret|session|csrf|nonce|otp|password|salt|key|auth)/i;
      for (let i = 0; i < lines.length; i++) {
        const raw = lines[i];
        if (isComment(raw, lang)) continue;
        if (!trigPat.test(raw)) continue;
        const window = lines.slice(Math.max(0,i-3), Math.min(lines.length,i+3)).join(' ');
        if (!secPat.test(window) && !secPat.test(raw)) continue;
        const m = raw.match(trigPat);
        const col = raw.indexOf(m[0]);
        findings.push({ ruleId: this.id, category: this.category, name: this.name, severity: this.severity, line: i, column: col, endColumn: col+m[0].length, codeSnippet: raw.trim(),
          description: 'Math.random() is not cryptographically secure and can be predicted.',
          fix: { description: 'Use CSPRNG', code: `// Node.js:\nconst token = crypto.randomBytes(32).toString('hex');\n// Python:\nimport secrets; token = secrets.token_hex(32)`, safe: true, safetyNote: '✔ Safe — direct drop-in.', breakingRisk: 'none' },
          context: [lines[i-1]||'', lines[i+1]||''] });
      }
      return findings;
    }
  },

  {
    id: 'A02-004', category: 'A02 – Cryptographic Failures', name: 'Plaintext HTTP URL', severity: 'medium',
    langs: ['javascript','typescript','python','java','php','go','ruby','csharp'],
    run(lines, lang) {
      return scanLines(lines, lang,
        /['"`]http:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0|::1)([a-zA-Z0-9.\-]+)/,
        (m) => `Plaintext HTTP URL "${m[0]}" — traffic can be intercepted by a MITM attacker.`,
        (m) => ({ description: 'Upgrade to HTTPS', code: m[0].replace('http://', 'https://'), safe: true, safetyNote: '✔ Safe if the server supports HTTPS.', breakingRisk: 'low' }),
        this.id, this.category, this.name, this.severity);
    }
  },

  // ── A03 ───────────────────────────────────────────────────────────────────

  {
    id: 'A03-001', category: 'A03 – Injection', name: 'SQL Injection', severity: 'critical',
    langs: ['javascript','typescript','python','java','php','go','ruby','csharp'],
    run(lines, lang) {
      const pats = [
        /(?:SELECT|INSERT|UPDATE|DELETE|WHERE|FROM)\s+.*`[^`]*\$\{/i,
        /(?:SELECT|INSERT|UPDATE|DELETE|WHERE|FROM)\s+['"][^'"]*['"]\s*\+\s*(?:req\.|request\.|params\.|query\.|body\.|\w+Id)/i,
        /f['"].*(?:SELECT|INSERT|UPDATE|DELETE|WHERE|FROM).*\{/i,
        /(?:SELECT|INSERT|UPDATE|DELETE|WHERE|FROM).*\.format\(/i,
        /(?:SELECT|INSERT|UPDATE|DELETE|WHERE|FROM).*"\s*\+\s*\w+/i,
      ];
      const all = [];
      for (const pat of pats) all.push(...scanLines(lines, lang, pat,
        () => 'User-controlled data concatenated into SQL query. Attacker can inject arbitrary SQL.',
        () => ({ description: 'Use parameterized queries', code: `// Node.js (pg):\nawait db.query('SELECT * FROM users WHERE id = $1', [userId]);\n// Python:\ncursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))`, safe: false, safetyNote: '⚠ Review column names and types before applying', breakingRisk: 'low' }),
        this.id, this.category, this.name, this.severity));
      return dedup(all);
    }
  },

  {
    id: 'A03-002', category: 'A03 – Injection', name: 'Command Injection', severity: 'critical',
    langs: ['javascript','typescript','python','java','php','go','ruby','csharp'],
    run(lines, lang) {
      const pats = [
        /(?:exec|execSync|spawnSync)\s*\(\s*[`'"].*\$\{/,
        /(?:exec|execSync)\s*\(\s*['"].*['"]\s*\+/,
        /(?:os\.system|subprocess\.(?:call|run|Popen))\s*\(.*(?:f'|\.format\(|\+\s*(?:request|req)\.)/i,
        /shell_exec\s*\(\s*(?:\$_(?:GET|POST|REQUEST))/i,
      ];
      const all = [];
      for (const pat of pats) all.push(...scanLines(lines, lang, pat,
        () => 'Shell command built with user input. Attacker can inject commands using ; & | $() metacharacters.',
        () => ({ description: 'Pass arguments as an array with shell:false', code: `const { spawn } = require('child_process');\nspawn('cmd', [arg1, arg2], { shell: false });`, safe: false, safetyNote: '⚠ Refactoring string→array requires understanding the full command', breakingRisk: 'medium' }),
        this.id, this.category, this.name, this.severity));
      return dedup(all);
    }
  },

  {
    id: 'A03-003', category: 'A03 – Injection', name: 'XSS – Unsafe DOM Write', severity: 'high',
    langs: ['javascript','typescript'],
    run(lines, lang) {
      const pats = [
        /\.(?:innerHTML|outerHTML)\s*=\s*(?!['"`]<[a-zA-Z])/,
        /document\.write\s*\(\s*(?!\s*['"`][^'"` +$]*['"`]\s*\))/,
        /dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:/,
      ];
      const all = [];
      for (const pat of pats) all.push(...scanLines(lines, lang, pat,
        () => 'DOM written with potentially untrusted HTML. Attacker can inject scripts into the victim\'s browser.',
        () => ({ description: 'Use textContent for plain text, or DOMPurify for HTML', code: `element.textContent = userInput; // plain text\n// OR:\nelement.innerHTML = DOMPurify.sanitize(userHtml);`, safe: false, safetyNote: '⚠ Confirm whether content is user-controlled', breakingRisk: 'low' }),
        this.id, this.category, this.name, this.severity));
      return dedup(all);
    }
  },

  {
    id: 'A03-004', category: 'A03 – Injection', name: 'eval() Code Injection', severity: 'critical',
    langs: ['javascript','typescript','python','ruby','php'],
    run(lines, lang) {
      const findings = [];
      const isJs = ['javascript','typescript'].includes(lang);
      const isPy = lang === 'python';
      for (let i = 0; i < lines.length; i++) {
        const raw = lines[i];
        if (isComment(raw, lang)) continue;
        const line = stripComment(raw, lang);
        const jsMatch = isJs && /\beval\s*\(\s*(?!['"`][^'"` +$]*['"`]\s*\))/.test(line);
        const pyMatch = isPy && /\bexec\s*\(\s*(?!['"`][a-zA-Z_][^'"` +$]*['"`]\s*\))/.test(line);
        if (!jsMatch && !pyMatch) continue;
        if (/eval\s*\(\s*['"`][^'"` +${]*['"`]\s*\)/.test(line)) continue;
        const col = line.search(/\beval\s*\(|\bexec\s*\(/);
        findings.push({ ruleId: this.id, category: this.category, name: this.name, severity: this.severity, line: i, column: Math.max(0,col), endColumn: Math.max(0,col)+4, codeSnippet: raw.trim(),
          description: 'eval() with dynamic argument. User input reaching eval() = arbitrary code execution.',
          fix: { description: 'Remove eval() — use JSON.parse() or a safe math parser', code: `const data = JSON.parse(userInput); // for JSON\n// For math: use mathjs.evaluate()`, safe: false, safetyNote: '⚠ Replacement depends on use case', breakingRisk: 'high' },
          context: [lines[i-1]||'', lines[i+1]||''] });
      }
      return findings;
    }
  },

  // ── A04 ───────────────────────────────────────────────────────────────────

  {
    id: 'A04-001', category: 'A04 – Insecure Design', name: 'Mass Assignment', severity: 'high',
    langs: ['javascript','typescript','python','ruby'],
    run(lines, lang) {
      return scanLines(lines, lang,
        /(?:Object\.assign|\.update\(|\.create\(|Model\.create\()\s*\(?\s*\w*,?\s*(?:req\.body|request\.body)/i,
        () => 'Entire request body passed to model. Attacker can set privileged fields (isAdmin, role, balance).',
        () => ({ description: 'Whitelist only safe fields', code: `const { name, email } = req.body; // destructure known fields\nawait User.create({ name, email });`, safe: false, safetyNote: '⚠ You must identify which fields are safe', breakingRisk: 'medium' }),
        this.id, this.category, this.name, this.severity);
    }
  },

  // ── A05 ───────────────────────────────────────────────────────────────────

  {
    id: 'A05-001', category: 'A05 – Security Misconfiguration', name: 'Debug Mode Enabled', severity: 'high',
    langs: ['javascript','typescript','python','java','php','go','ruby','csharp'],
    run(lines, lang) {
      return scanLines(lines, lang,
        /(?:DEBUG\s*=\s*True|debug\s*:\s*true|app\.run\s*\([^)]*debug\s*=\s*True|NODE_ENV\s*=\s*['"`]development['"`])/i,
        () => 'Debug mode enabled. Exposes stack traces, paths, and env vars to end users.',
        () => ({ description: 'Use NODE_ENV / environment variable', code: `const isDev = process.env.NODE_ENV === 'development';`, safe: true, safetyNote: '✔ Safe to apply.', breakingRisk: 'none' }),
        this.id, this.category, this.name, this.severity);
    }
  },

  {
    id: 'A05-003', category: 'A05 – Security Misconfiguration', name: 'Stack Trace in Response', severity: 'medium',
    langs: ['javascript','typescript'],
    run(lines, lang) {
      return scanLines(lines, lang,
        /res\.(?:send|json|status\(\d+\)\.json)\s*\(\s*(?:\{[^}]*stack|err\.stack|error\.stack|e\.stack)/i,
        () => 'Stack trace sent to client. Reveals file paths, library versions, and code structure.',
        () => ({ description: 'Log internally; return generic message to client', code: `console.error(err.stack);\nres.status(500).json({ error: 'Internal server error' });`, safe: true, safetyNote: '✔ Safe — hides internals from clients.', breakingRisk: 'none' }),
        this.id, this.category, this.name, this.severity);
    }
  },

  // ── A07 ───────────────────────────────────────────────────────────────────

  {
    id: 'A07-001', category: 'A07 – Auth Failures', name: 'JWT "none" Algorithm', severity: 'critical',
    langs: ['javascript','typescript','python','java','php','go','ruby','csharp'],
    run(lines, lang) {
      const pats = [
        /algorithms?\s*[:=]\s*\[?\s*['"`]none['"`]/i,
        /verify\s*[:=]\s*false/i,
      ];
      const all = [];
      for (const pat of pats) all.push(...scanLines(lines, lang, pat,
        () => 'JWT "none" algorithm or disabled verification lets attackers forge tokens without knowing the secret.',
        () => ({ description: 'Always verify with an explicit algorithm', code: `jwt.verify(token, process.env.JWT_SECRET, {\n  algorithms: ['HS256'],\n});`, safe: true, safetyNote: '✔ Safe — stricter verification. Existing valid tokens remain valid.', breakingRisk: 'none' }),
        this.id, this.category, this.name, this.severity));
      return dedup(all);
    }
  },

  {
    id: 'A07-002', category: 'A07 – Auth Failures', name: 'Weak Password Policy', severity: 'medium',
    langs: ['javascript','typescript','python','java','php','go','ruby','csharp'],
    run(lines, lang) {
      return scanLines(lines, lang,
        /(?:password|pass|pwd).*\.length\s*[<>]=?\s*[1-7](?!\d)/i,
        (m) => `Weak password length check: "${m[0].trim()}". NIST recommends 12+ chars minimum.`,
        () => ({ description: 'Enforce minimum 12 characters + strength check', code: `if (password.length < 12) throw new Error('Password too short');`, safe: true, safetyNote: '✔ Safe for new registrations. Existing passwords unaffected.', breakingRisk: 'none' }),
        this.id, this.category, this.name, this.severity);
    }
  },

  // ── A08 ───────────────────────────────────────────────────────────────────

  {
    id: 'A08-001', category: 'A08 – Integrity Failures', name: 'Insecure Deserialization', severity: 'critical',
    langs: ['python','php','java','ruby','csharp'],
    run(lines, lang) {
      return scanLines(lines, lang,
        /(?:pickle\.loads|pickle\.load\s*\(|yaml\.load\s*\([^)]*(?!safe_load)|unserialize\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)|ObjectInputStream|readObject\(\)|Marshal\.load)/i,
        (m) => `Insecure deserialization of untrusted data. Equivalent to remote code execution with pickle/PHP unserialize/Java ObjectInputStream.`,
        () => ({ description: 'Use JSON or safe YAML', code: `# Python:\nimport json\ndata = json.loads(user_input)\n# YAML if needed:\ndata = yaml.safe_load(user_input) # not yaml.load()`, safe: false, safetyNote: '⚠ Migrating format requires changing stored data. Plan migration.', breakingRisk: 'high' }),
        this.id, this.category, this.name, this.severity);
    }
  },

  // ── A09 ───────────────────────────────────────────────────────────────────

  {
    id: 'A09-001', category: 'A09 – Logging Failures', name: 'Sensitive Data Logged', severity: 'high',
    langs: ['javascript','typescript','python','java','php','go','ruby','csharp'],
    run(lines, lang) {
      return scanLines(lines, lang,
        /(?:console\.log|print\s*\(|logger\.\w+)\s*\(.*(?:password|passwd|secret|token|credit_?card|api_?key|auth)/i,
        () => 'Credential or token in a log statement. Log files are often accessible to staff or third-party log services.',
        () => ({ description: 'Redact sensitive fields before logging', code: `const safe = { ...req.body, password: '[REDACTED]' };\nlogger.info('Login', safe);`, safe: true, safetyNote: '✔ Safe — adds redaction only.', breakingRisk: 'none' }),
        this.id, this.category, this.name, this.severity);
    }
  },

  // ── A10 ───────────────────────────────────────────────────────────────────

  {
    id: 'A10-001', category: 'A10 – SSRF', name: 'Server-Side Request Forgery', severity: 'high',
    langs: ['javascript','typescript','python','java','php','go','ruby','csharp'],
    run(lines, lang) {
      const findings = [];
      const fetchPat = /(?:fetch|axios\.(?:get|post)|requests\.(?:get|post)|http\.get|https\.get|got\s*\()\s*\(\s*(?:req\.|request\.|params\.|query\.|body\.|\w+Url|\w+URL|\w+url)/i;
      const validPat = /(?:new URL|validateUrl|allowedHosts|ALLOWED_HOSTS|url\.startsWith)/i;
      for (let i = 0; i < lines.length; i++) {
        const raw = lines[i];
        if (isComment(raw, lang)) continue;
        if (!fetchPat.test(raw)) continue;
        const window = lines.slice(Math.max(0,i-10), Math.min(lines.length,i+5)).join('\n');
        if (validPat.test(window)) continue;
        const m = raw.match(fetchPat);
        const col = raw.indexOf(m[0]);
        findings.push({ ruleId: this.id, category: this.category, name: this.name, severity: this.severity, line: i, column: col, endColumn: col+m[0].length, codeSnippet: raw.trim(),
          description: 'User-controlled URL fetched server-side. Attacker can reach internal services (169.254.169.254, localhost).',
          fix: { description: 'Validate URL against allowlist + block private IP ranges', code: `const parsed = new URL(rawUrl);\nconst ALLOWED = ['api.trusted.com'];\nif (!ALLOWED.includes(parsed.hostname)) throw new Error('Host not allowed');`, safe: false, safetyNote: '⚠ Populate ALLOWED_HOSTS with your real external services', breakingRisk: 'medium' },
          context: [lines[i-1]||'', lines[i+1]||''] });
      }
      return findings;
    }
  },
];

// ── Severity order ────────────────────────────────────────────────────────────

const SEV_RANK = { critical: 4, high: 3, medium: 2, low: 1 };

function runRules(lines, lang) {
  const findings = [];
  for (const rule of RULES) {
    if (!rule.langs.includes(lang)) continue;
    try {
      findings.push(...rule.run(lines, lang));
    } catch(e) { /* rule should never crash scanner */ }
  }
  // Dedup + sort
  const seen = new Set();
  const unique = findings.filter(f => {
    const k = `${f.ruleId}:${f.line}`;
    if (seen.has(k)) return false;
    seen.add(k); return true;
  });
  return unique.sort((a,b) => SEV_RANK[b.severity] - SEV_RANK[a.severity] || a.line - b.line);
}

module.exports = { RULES, runRules, SEV_RANK };
