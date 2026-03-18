// ─── A04–A10: Remaining OWASP Categories ─────────────────────────────────────

import { Finding, Language, OwaspCategory, RuleContext, SecurityRule } from '../types';
import { isCommentLine, makeFinding, scanLines, stripInlineComment } from '../ruleHelpers';

const ALL: Language[] = ['javascript','typescript','javascriptreact','typescriptreact','python','java','php','go','ruby','csharp'];
const WEB_JS: Language[] = ['javascript','typescript','javascriptreact','typescriptreact'];

// ═══════════════════════════════════════════════════════════════════════════════
// A04 – Insecure Design
// ═══════════════════════════════════════════════════════════════════════════════

export const massAssignment: SecurityRule = {
  id: 'A04-001',
  category: OwaspCategory.A04,
  name: 'Mass Assignment',
  severity: 'high',
  languages: ['javascript','typescript','javascriptreact','typescriptreact','python','ruby'],
  detect(ctx: RuleContext): Finding[] {
    return scanLines(ctx, this,
      /(?:Object\.assign|spread|\.update\(|\.create\(|Model\.create\()\s*\(?\s*\w*,?\s*(?:req\.body|request\.body|params\.all|request\.params)/i,
      () => `Mass Assignment: the entire request body is passed directly to a model constructor or update call. An attacker can set privileged fields (isAdmin, role, balance) that were not intended to be user-settable.`,
      () => ({
        description: 'Whitelist only the fields the user is allowed to set',
        code: `// Pick only allowed fields from req.body\nconst { name, email, bio } = req.body;  // destructure known-safe fields\nconst user = await User.create({ name, email, bio });\n\n// Or use a validation library (zod/joi) to define the schema:\nimport { z } from 'zod';\nconst schema = z.object({\n  name: z.string().max(100),\n  email: z.string().email(),\n});\nconst data = schema.parse(req.body);  // strips unknown fields\nawait User.create(data);`,
        safe: false,
        safetyNote: '⚠️ Needs scrutiny — you must identify which fields are safe to accept. Review the model schema carefully.',
        breakingRisk: 'medium',
      })
    );
  }
};

export const missingRateLimit: SecurityRule = {
  id: 'A04-002',
  category: OwaspCategory.A04,
  name: 'Missing Rate Limiting on Sensitive Endpoint',
  severity: 'medium',
  languages: WEB_JS,
  detect(ctx: RuleContext): Finding[] {
    const findings: Finding[] = [];
    // Detect route handlers for login/auth/reset that lack rateLimit middleware nearby
    const routePattern = /(?:app|router)\.\s*(?:post|put)\s*\(\s*['"`][^'"` ]*(?:login|signin|auth|reset.?password|forgot.?password|verify|otp)[^'"` ]*['"`]/i;
    const rateLimitCheck = /(?:rateLimit|rateLimiter|throttle|express-rate-limit|slowDown|limiter)/i;

    for (let i = 0; i < ctx.lines.length; i++) {
      const raw = ctx.lines[i];
      if (isCommentLine(raw, ctx.language)) { continue; }
      const line = stripInlineComment(raw, ctx.language);
      if (!routePattern.test(line)) { continue; }

      const window = ctx.lines.slice(Math.max(0, i - 15), Math.min(ctx.lines.length, i + 15)).join('\n');
      if (rateLimitCheck.test(window)) { continue; }

      const match = line.match(routePattern)!;
      const col = line.indexOf(match[0]);
      findings.push(makeFinding(this, i, col, col + match[0].length, raw,
        `Sensitive endpoint "${match[0].substring(0, 50)}" has no visible rate limiter. Without rate limiting, brute-force and credential-stuffing attacks are possible.`,
        {
          description: 'Add express-rate-limit (or equivalent) to this route',
          code: `import rateLimit from 'express-rate-limit';\n\nconst authLimiter = rateLimit({\n  windowMs: 15 * 60 * 1000,  // 15 minutes\n  max: 10,                    // max 10 attempts per window\n  message: { error: 'Too many attempts. Try again in 15 minutes.' },\n  standardHeaders: true,\n  legacyHeaders: false,\n});\n\nrouter.post('/login', authLimiter, loginHandler);`,
          safe: true,
          safetyNote: '✅ Safe to apply — adding rate limiting is non-breaking. Tune max/windowMs to match your UX requirements.',
          breakingRisk: 'none',
        },
        [ctx.lines[i - 1] ?? '', ctx.lines[i + 1] ?? '']
      ));
    }
    return findings;
  }
};

// ═══════════════════════════════════════════════════════════════════════════════
// A05 – Security Misconfiguration
// ═══════════════════════════════════════════════════════════════════════════════

export const debugEnabled: SecurityRule = {
  id: 'A05-001',
  category: OwaspCategory.A05,
  name: 'Debug Mode Enabled',
  severity: 'high',
  languages: ALL,
  detect(ctx: RuleContext): Finding[] {
    return scanLines(ctx, this,
      /(?:DEBUG\s*=\s*True|debug\s*:\s*true|app\.run\s*\([^)]*debug\s*=\s*True|NODE_ENV\s*=\s*['"`]development['"`]|\.set\s*\(\s*['"`]env['"`]\s*,\s*['"`]development['"`]\))/i,
      () => `Debug mode is enabled. This can expose stack traces, internal paths, environment variables, and detailed error messages to end users — a significant information disclosure risk.`,
      (match) => ({
        description: 'Disable debug mode and use environment variables for configuration',
        code: `// Use environment variables — never hardcode debug mode\nconst isDev = process.env.NODE_ENV === 'development';\n\n// Express\napp.set('env', process.env.NODE_ENV || 'production');\n\n// Python / Flask\napp.debug = os.environ.get('FLASK_DEBUG', 'false').lower() === 'true'\n\n// Generic\nif (process.env.NODE_ENV !== 'production') {\n  // dev-only middleware\n}`,
        safe: true,
        safetyNote: '✅ Safe to apply — disabling debug mode in production is always correct.',
        breakingRisk: 'none',
      })
    );
  }
};

export const defaultCredentials: SecurityRule = {
  id: 'A05-002',
  category: OwaspCategory.A05,
  name: 'Default / Weak Credentials',
  severity: 'critical',
  languages: ALL,
  detect(ctx: RuleContext): Finding[] {
    return scanLines(ctx, this,
      /(?:username|user|login|admin|root)\s*(?:===?|:)\s*['"`](?:admin|root|test|guest|default|administrator)['"`]\s*&&?\s*(?:password|pass|pwd)\s*(?:===?|:)\s*['"`](?:admin|root|password|123456|test|guest|default)['"`]/i,
      () => `Default credentials detected in source code. These are the first values tried in automated attacks and will result in immediate compromise if deployed.`,
      () => ({
        description: 'Remove hardcoded credentials entirely — use a proper auth system',
        code: `// Never hardcode credentials — authenticate against a database:\nconst user = await User.findOne({ username: req.body.username });\nif (!user) return res.status(401).json({ error: 'Invalid credentials' });\n\nconst valid = await bcrypt.compare(req.body.password, user.passwordHash);\nif (!valid) return res.status(401).json({ error: 'Invalid credentials' });\n\n// Rate limit + lockout after N failures (see A04-002)`,
        safe: false,
        safetyNote: '⚠️ Needs scrutiny — full auth system redesign required. Do not ship this code.',
        breakingRisk: 'high',
      })
    );
  }
};

export const exposedStackTrace: SecurityRule = {
  id: 'A05-003',
  category: OwaspCategory.A05,
  name: 'Stack Trace Exposed to Client',
  severity: 'medium',
  languages: WEB_JS,
  detect(ctx: RuleContext): Finding[] {
    return scanLines(ctx, this,
      /(?:res\.(?:send|json|status\(\d+\)\.json)\s*\(\s*(?:\{[^}]*stack|err\.stack|error\.stack|e\.stack))/i,
      () => `Stack trace sent to client response. Stack traces reveal internal file paths, library versions, and code structure — valuable reconnaissance for an attacker.`,
      () => ({
        description: 'Return a generic error message; log the stack trace server-side',
        code: `// Central error handler (Express)\napp.use((err: Error, req, res, next) => {\n  // Log full details internally\n  console.error({ message: err.message, stack: err.stack, url: req.url });\n\n  // Return a generic message to the client\n  const status = (err as any).status || 500;\n  res.status(status).json({\n    error: status < 500 ? err.message : 'An unexpected error occurred',\n    requestId: req.id,  // allow client to correlate with logs\n  });\n});`,
        safe: true,
        safetyNote: '✅ Safe to apply — no functional change, just hides internal details from clients.',
        breakingRisk: 'none',
      })
    );
  }
};

export const missingSecurityHeaders: SecurityRule = {
  id: 'A05-004',
  category: OwaspCategory.A05,
  name: 'Missing Security Headers (helmet / CSP)',
  severity: 'medium',
  languages: WEB_JS,
  detect(ctx: RuleContext): Finding[] {
    const findings: Finding[] = [];
    const appInit = /(?:const|let|var)\s+app\s*=\s*express\(\)/;
    const helmetCheck = /helmet\s*\(|res\.setHeader\s*\(\s*['"`]Content-Security-Policy/i;

    for (let i = 0; i < ctx.lines.length; i++) {
      const raw = ctx.lines[i];
      if (isCommentLine(raw, ctx.language)) { continue; }
      const line = stripInlineComment(raw, ctx.language);
      if (!appInit.test(line)) { continue; }

      const fullFile = ctx.lines.join('\n');
      if (helmetCheck.test(fullFile)) { continue; }

      const col = line.search(appInit);
      findings.push(makeFinding(this, i, col, col + 20, raw,
        `Express app initialised without helmet middleware. Security headers (X-Frame-Options, CSP, HSTS, etc.) are not set, leaving the app exposed to clickjacking, XSS, and MIME-sniffing attacks.`,
        {
          description: 'Add helmet middleware immediately after app initialisation',
          code: `import helmet from 'helmet';\n\nconst app = express();\napp.use(helmet());  // Sets 11 security headers by default\n\n// Customise CSP if needed:\napp.use(helmet.contentSecurityPolicy({\n  directives: {\n    defaultSrc: ["'self'"],\n    scriptSrc: ["'self'"],\n    styleSrc: ["'self'", "'unsafe-inline'"],\n  },\n}));`,
          safe: true,
          safetyNote: '✅ Safe to apply. Helmet may break inline scripts — check your CSP config if you use inline JS.',
          breakingRisk: 'low',
        },
        [ctx.lines[i - 1] ?? '', ctx.lines[i + 1] ?? '']
      ));
      break; // Only one finding per file for this rule
    }
    return findings;
  }
};

// ═══════════════════════════════════════════════════════════════════════════════
// A07 – Identification & Authentication Failures
// ═══════════════════════════════════════════════════════════════════════════════

export const jwtNoneAlgorithm: SecurityRule = {
  id: 'A07-001',
  category: OwaspCategory.A07,
  name: 'JWT "none" Algorithm / Signature Bypass',
  severity: 'critical',
  languages: ALL,
  detect(ctx: RuleContext): Finding[] {
    const findings: Finding[] = [];
    const patterns = [
      /(?:algorithms?\s*[:=]\s*\[?\s*['"`]none['"`])/i,
      /(?:verify\s*[:=]\s*false|options\.verify\s*=\s*false)/i,
      /jwt\.decode\s*\([^)]+\)\s*(?!;?\s*\/\/.*verify)/,  // jwt.decode without verify nearby
    ];
    for (const pat of patterns) {
      findings.push(...scanLines(ctx, this, pat,
        () => `JWT security bypass: "none" algorithm or disabled verification allows an attacker to forge tokens without knowing the secret.`,
        () => ({
          description: 'Always verify JWTs with a strong secret; reject "none" algorithm',
          code: `import jwt from 'jsonwebtoken';\n\n// Verify — always specify allowed algorithms\nconst payload = jwt.verify(token, process.env.JWT_SECRET!, {\n  algorithms: ['HS256'],  // explicitly whitelist; never include 'none'\n  issuer: 'your-app',\n  audience: 'your-api',\n});\n\n// Never use jwt.decode() for authentication — it skips verification`,
          safe: true,
          safetyNote: '✅ Safe to apply — stricter verification is always correct. Existing valid tokens remain valid.',
          breakingRisk: 'none',
        })
      ));
    }
    const seen = new Set<number>();
    return findings.filter(f => { if (seen.has(f.line)) return false; seen.add(f.line); return true; });
  }
};

export const weakPasswordPolicy: SecurityRule = {
  id: 'A07-002',
  category: OwaspCategory.A07,
  name: 'Weak Password Policy',
  severity: 'medium',
  languages: ALL,
  detect(ctx: RuleContext): Finding[] {
    return scanLines(ctx, this,
      /(?:password|pass|pwd).*\.length\s*[<>]=?\s*[1-7](?!\d)/i,
      (match) => `Weak password length check (${match[0].trim()}). NIST SP 800-63B recommends a minimum of 8 characters; industry best practice is 12+.`,
      () => ({
        description: 'Enforce a minimum of 12 characters and check against common passwords',
        code: `// Minimum 12 chars + reject common passwords\nimport { zxcvbn } from 'zxcvbn';\n\nfunction validatePassword(password: string): void {\n  if (password.length < 12) {\n    throw new Error('Password must be at least 12 characters');\n  }\n  const strength = zxcvbn(password);\n  if (strength.score < 3) {\n    throw new Error('Password is too weak: ' + strength.feedback.warning);\n  }\n}`,
        safe: true,
        safetyNote: '✅ Safe to apply for new registrations. Existing passwords are unaffected until the user changes them.',
        breakingRisk: 'none',
      })
    );
  }
};

export const sessionFixation: SecurityRule = {
  id: 'A07-003',
  category: OwaspCategory.A07,
  name: 'Session Not Regenerated After Login',
  severity: 'high',
  languages: WEB_JS,
  detect(ctx: RuleContext): Finding[] {
    const findings: Finding[] = [];
    // Find login success patterns without session.regenerate nearby
    const loginSuccessPattern = /(?:req\.session\.\w+\s*=\s*(?:user|userId|req\.body|true)|session\.user\s*=)/i;
    const regeneratePattern = /session\.regenerate|req\.session\.regenerate/i;

    for (let i = 0; i < ctx.lines.length; i++) {
      const raw = ctx.lines[i];
      if (isCommentLine(raw, ctx.language)) { continue; }
      const line = stripInlineComment(raw, ctx.language);
      if (!loginSuccessPattern.test(line)) { continue; }

      const window = ctx.lines.slice(Math.max(0, i - 10), Math.min(ctx.lines.length, i + 5)).join('\n');
      if (regeneratePattern.test(window)) { continue; }

      const col = line.search(loginSuccessPattern);
      findings.push(makeFinding(this, i, col, col + 20, raw,
        `Session ID not regenerated after login. An attacker who obtained a pre-login session ID can fixate it to hijack the authenticated session.`,
        {
          description: 'Call req.session.regenerate() before setting session data on login',
          code: `// Regenerate session ID before assigning authenticated data\nreq.session.regenerate((err) => {\n  if (err) return next(err);\n  req.session.userId = user.id;\n  req.session.role   = user.role;\n  req.session.save((err) => {\n    if (err) return next(err);\n    res.json({ success: true });\n  });\n});`,
          safe: true,
          safetyNote: '✅ Safe to apply — this is the recommended express-session pattern for login.',
          breakingRisk: 'none',
        },
        [ctx.lines[i - 1] ?? '', ctx.lines[i + 1] ?? '']
      ));
    }
    return findings;
  }
};

// ═══════════════════════════════════════════════════════════════════════════════
// A08 – Software & Data Integrity Failures
// ═══════════════════════════════════════════════════════════════════════════════

export const insecureDeserialization: SecurityRule = {
  id: 'A08-001',
  category: OwaspCategory.A08,
  name: 'Insecure Deserialization',
  severity: 'critical',
  languages: ALL,
  detect(ctx: RuleContext): Finding[] {
    return scanLines(ctx, this,
      /(?:pickle\.loads|pickle\.load\s*\(|yaml\.load\s*\([^)]*(?:Loader\s*=\s*yaml\.(?:FullLoader|Loader)|(?!yaml\.safe_load))|unserialize\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)|ObjectInputStream|readObject\(\)|Marshal\.load|Oj\.load)/i,
      (match) => `Insecure deserialization: "${match[0].substring(0, 40)}" with untrusted data can lead to Remote Code Execution. Deserializing attacker-controlled data in formats like pickle, PHP serialize, or Java ObjectInputStream is equivalent to code execution.`,
      (match) => ({
        description: 'Use safe serialization formats (JSON) or restrict deserializable types',
        code: `# Python — never use pickle on untrusted data\n# Replace with JSON:\nimport json\ndata = json.loads(user_input)  # JSON cannot execute code\n\n# If YAML is needed, use safe_load:\nimport yaml\ndata = yaml.safe_load(user_input)  # Does not load Python objects\n\n# PHP — avoid unserialize() on user input:\n$data = json_decode($userInput, true);  // Use JSON instead\n\n// Java — use a deserialization filter (JEP 290):\nObjectInputStream ois = new ObjectInputStream(input);\nois.setObjectInputFilter(ObjectInputFilter.Config.createFilter(\n  "maxdepth=5;!*"  // block by default, allow only specific classes\n));`,
        safe: false,
        safetyNote: '⚠️ Needs scrutiny — migrating away from pickle/serialize requires changing the data format. Plan a migration for any stored serialized data.',
        breakingRisk: 'high',
      })
    );
  }
};

// ═══════════════════════════════════════════════════════════════════════════════
// A09 – Security Logging & Monitoring Failures
// ═══════════════════════════════════════════════════════════════════════════════

export const sensitiveDataInLogs: SecurityRule = {
  id: 'A09-001',
  category: OwaspCategory.A09,
  name: 'Sensitive Data Logged',
  severity: 'high',
  languages: ALL,
  detect(ctx: RuleContext): Finding[] {
    return scanLines(ctx, this,
      /(?:console\.log|print\s*\(|logger\.\w+|log\.\w+)\s*\(.*(?:password|passwd|secret|token|credit_?card|cvv|ssn|social_?security|api_?key|auth)/i,
      (match) => `Sensitive data (password/token/secret) appears in a log statement. Log files are often stored insecurely, shipped to third-party services, or accessible to operations staff who should not see credentials.`,
      () => ({
        description: 'Redact or omit sensitive fields before logging',
        code: `// Redact sensitive fields from objects before logging\nfunction sanitizeForLog(obj: Record<string, unknown>) {\n  const REDACTED_FIELDS = ['password','token','secret','apiKey','creditCard'];\n  return Object.fromEntries(\n    Object.entries(obj).map(([k, v]) =>\n      REDACTED_FIELDS.some(f => k.toLowerCase().includes(f))\n        ? [k, '[REDACTED]']\n        : [k, v]\n    )\n  );\n}\nlogger.info('Login attempt', sanitizeForLog(req.body));`,
        safe: true,
        safetyNote: '✅ Safe to apply — adds redaction logic, no functional change.',
        breakingRisk: 'none',
      })
    );
  }
};

export const missingErrorHandling: SecurityRule = {
  id: 'A09-002',
  category: OwaspCategory.A09,
  name: 'Unhandled Promise / Silent Exception',
  severity: 'low',
  languages: WEB_JS,
  detect(ctx: RuleContext): Finding[] {
    return scanLines(ctx, this,
      /\.catch\s*\(\s*(?:\(\s*\)\s*=>?\s*\{\s*\}|err\s*=>\s*(?:null|undefined|\{\s*\}))\s*\)/,
      () => `Empty or silent .catch() swallows errors. Failed operations go unnoticed, security events are not logged, and issues become impossible to diagnose.`,
      () => ({
        description: 'Log errors and handle them explicitly',
        code: `// Always log errors, even when recovering gracefully\nasync function safeOperation() {\n  try {\n    await riskyOperation();\n  } catch (err) {\n    logger.error('Operation failed', {\n      error: err instanceof Error ? err.message : String(err),\n      stack: err instanceof Error ? err.stack : undefined,\n    });\n    // Re-throw, return a fallback, or respond with an error:\n    throw err;\n  }\n}`,
        safe: true,
        safetyNote: '✅ Safe to apply — adds logging, no functional change.',
        breakingRisk: 'none',
      })
    );
  }
};

// ═══════════════════════════════════════════════════════════════════════════════
// A10 – SSRF
// ═══════════════════════════════════════════════════════════════════════════════

export const ssrf: SecurityRule = {
  id: 'A10-001',
  category: OwaspCategory.A10,
  name: 'Server-Side Request Forgery (SSRF)',
  severity: 'high',
  languages: ALL,
  detect(ctx: RuleContext): Finding[] {
    const findings: Finding[] = [];
    const fetchPattern = /(?:fetch|axios\.(?:get|post|put|delete|request)|requests\.(?:get|post|put)|urllib\.request\.urlopen|http\.get|https\.get|got\s*\(|superagent\.get)\s*\(\s*(?:req\.|request\.|params\.|query\.|body\.|\w+Url|\w+URL|\w+url|\w+Uri)/i;
    const urlValidation = /(?:URL\.parse|new URL|isValidUrl|validateUrl|allowedHosts|ALLOWED_HOSTS|url\.startsWith|url\.includes|dns\.lookup)/i;

    for (let i = 0; i < ctx.lines.length; i++) {
      const raw = ctx.lines[i];
      if (isCommentLine(raw, ctx.language)) { continue; }
      const line = stripInlineComment(raw, ctx.language);
      if (!fetchPattern.test(line)) { continue; }

      const window = ctx.lines.slice(Math.max(0, i - 10), Math.min(ctx.lines.length, i + 5)).join('\n');
      if (urlValidation.test(window)) { continue; }

      const match = line.match(fetchPattern)!;
      const col = line.indexOf(match[0]);
      findings.push(makeFinding(this, i, col, col + match[0].length, raw,
        `SSRF: a user-controlled URL is fetched server-side without validation. An attacker can make the server request internal services (169.254.169.254, localhost, internal APIs) that should not be externally accessible.`,
        {
          description: 'Validate the URL against an allowlist before making the request',
          code: `import dns from 'dns/promises';\nimport { URL } from 'url';\n\nasync function safeServerFetch(rawUrl: string): Promise<Response> {\n  // 1. Parse — reject non-HTTP(S) schemes\n  const parsed = new URL(rawUrl);  // throws on invalid URL\n  if (!['http:', 'https:'].includes(parsed.protocol)) {\n    throw new Error('Only HTTP/HTTPS URLs are allowed');\n  }\n\n  // 2. Allowlist hostnames\n  const ALLOWED_HOSTS = ['api.trusted.com', 'cdn.trusted.com'];\n  if (!ALLOWED_HOSTS.includes(parsed.hostname)) {\n    throw new Error(\`Host \${parsed.hostname} is not allowed\`);\n  }\n\n  // 3. Resolve IP — block internal ranges (SSRF via DNS rebinding)\n  const { address } = await dns.lookup(parsed.hostname);\n  const PRIVATE = /^(10\\.|172\\.(1[6-9]|2\\d|3[01])\\.|192\\.168\\.|127\\.|169\\.254\\.)/;\n  if (PRIVATE.test(address)) {\n    throw new Error('Requests to private IP ranges are blocked');\n  }\n\n  return fetch(rawUrl);\n}`,
          safe: false,
          safetyNote: '⚠️ Needs scrutiny — populate ALLOWED_HOSTS with your actual allowed external services before applying.',
          breakingRisk: 'medium',
        },
        [ctx.lines[i - 1] ?? '', ctx.lines[i + 1] ?? '']
      ));
    }
    return findings;
  }
};
