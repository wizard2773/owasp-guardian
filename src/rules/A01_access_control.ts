// ─── A01: Broken Access Control ──────────────────────────────────────────────

import { Finding, Language, OwaspCategory, RuleContext, SecurityRule } from '../types';
import { isCommentLine, makeFinding, scanLines, stripInlineComment } from '../ruleHelpers';

const ALL_WEB: Language[] = ['javascript','typescript','javascriptreact','typescriptreact','python','java','php','ruby','csharp','go'];

// ── A01-001: Path Traversal ───────────────────────────────────────────────────
export const pathTraversal: SecurityRule = {
  id: 'A01-001',
  category: OwaspCategory.A01,
  name: 'Path Traversal',
  severity: 'high',
  languages: ALL_WEB,
  detect(ctx: RuleContext): Finding[] {
    const findings: Finding[] = [];
    // Patterns: joining user input into file paths, or direct ../ usage in open/readFile
    const patterns = [
      /(?:open|readFile|readFileSync|path\.join|os\.path\.join|File\(|fopen|include|require)\s*\(.*(?:req\.|request\.|params\.|query\.|body\.|args\[|\$_GET|\$_POST|\$_REQUEST)/i,
      /(?:open|readFile|readFileSync)\s*\(\s*(?:req|request|params|query|body)\s*[\.\[]/i,
    ];
    for (const pattern of patterns) {
      findings.push(...scanLines(ctx, this, pattern,
        (_, line) => `Path traversal risk: user-controlled input flows directly into a file-system operation. An attacker can supply "../../../etc/passwd" to read arbitrary files.`,
        (_, line) => ({
          description: 'Sanitize and validate the filename before use',
          code: `// Validate and restrict to allowed directory\nimport path from 'path';\nconst BASE_DIR = path.resolve('./safe-files');\nconst requested = path.resolve(BASE_DIR, userInput);\nif (!requested.startsWith(BASE_DIR)) {\n  throw new Error('Path traversal detected');\n}\n// Now safe to use: fs.readFile(requested, ...)`,
          safe: false,
          safetyNote: '⚠️ Needs scrutiny — you must confirm BASE_DIR matches your application structure before applying.',
          breakingRisk: 'low',
        })
      ));
    }
    return dedup(findings);
  }
};

// ── A01-002: CORS Wildcard ────────────────────────────────────────────────────
export const corsWildcard: SecurityRule = {
  id: 'A01-002',
  category: OwaspCategory.A01,
  name: 'CORS Wildcard (Access-Control-Allow-Origin: *)',
  severity: 'medium',
  languages: ['javascript','typescript','javascriptreact','typescriptreact','python','java','php','go','ruby','csharp'],
  detect(ctx: RuleContext): Finding[] {
    return scanLines(ctx, this,
      /(?:Access-Control-Allow-Origin['"\s:,]+\*|origin\s*[:=]\s*['"`]\*['"`]|cors\(\s*\{[^}]*origin\s*:\s*['"`]\*['"`])/i,
      () => `CORS is configured to allow all origins ("*"). This lets any website make credentialed cross-origin requests to your API, bypassing same-origin protections.`,
      () => ({
        description: 'Restrict CORS to known origins',
        code: `// Explicitly allow only trusted origins\nconst allowedOrigins = ['https://app.yourdomain.com'];\napp.use(cors({\n  origin: (origin, cb) => {\n    if (!origin || allowedOrigins.includes(origin)) cb(null, true);\n    else cb(new Error('Not allowed by CORS'));\n  },\n  credentials: true,\n}));`,
        safe: false,
        safetyNote: '⚠️ Needs scrutiny — replace with your actual allowed origins list.',
        breakingRisk: 'medium',
      })
    );
  }
};

// ── A01-003: Insecure Direct Object Reference ─────────────────────────────────
export const idor: SecurityRule = {
  id: 'A01-003',
  category: OwaspCategory.A01,
  name: 'Insecure Direct Object Reference (IDOR)',
  severity: 'high',
  languages: ['javascript','typescript','javascriptreact','typescriptreact','python','java','php','ruby','csharp'],
  detect(ctx: RuleContext): Finding[] {
    const findings: Finding[] = [];
    for (let i = 0; i < ctx.lines.length; i++) {
      const raw = ctx.lines[i];
      if (isCommentLine(raw, ctx.language)) { continue; }
      const line = stripInlineComment(raw, ctx.language);

      // Pattern: DB lookup using params.id / query.id / req.body.id without visible auth guard
      const idPattern = /(?:findById|findOne|getById|find_by_id|where.*id\s*=)\s*\(?\s*(?:req\.|request\.|params\.|query\.|body\.)(?:id|userId|account_id|user_id)/i;
      if (!idPattern.test(line)) { continue; }

      // Look in the surrounding 15 lines for an auth/ownership check
      const windowStart = Math.max(0, i - 8);
      const windowEnd = Math.min(ctx.lines.length - 1, i + 8);
      const surroundingBlock = ctx.lines.slice(windowStart, windowEnd + 1).join('\n');
      const hasAuthCheck = /(?:req\.user|currentUser|session\.user|isAuthorized|checkOwnership|authorize|hasPermission|userId\s*===|userId\s*==\s*req|\.userId\s*!==)/i.test(surroundingBlock);

      if (hasAuthCheck) { continue; }

      const col = line.search(idPattern);
      findings.push(makeFinding(this, i, col, col + 20, raw,
        `IDOR: a database object is fetched using a user-supplied ID without a visible ownership or authorization check. An attacker can enumerate other users' records by modifying the ID.`,
        {
          description: 'Add ownership verification after fetching the record',
          code: `const record = await Model.findById(req.params.id);\nif (!record) return res.status(404).json({ error: 'Not found' });\n\n// Ownership check — adjust field name to match your schema\nif (String(record.userId) !== String(req.user.id)) {\n  return res.status(403).json({ error: 'Forbidden' });\n}`,
          safe: false,
          safetyNote: '⚠️ Needs scrutiny — confirm the ownership field name (record.userId) matches your data model.',
          breakingRisk: 'low',
        },
        [ctx.lines[i - 1] ?? '', ctx.lines[i + 1] ?? '']
      ));
    }
    return findings;
  }
};

function dedup(findings: Finding[]): Finding[] {
  const seen = new Set<string>();
  return findings.filter(f => {
    const key = `${f.line}:${f.ruleId}`;
    if (seen.has(key)) { return false; }
    seen.add(key);
    return true;
  });
}
