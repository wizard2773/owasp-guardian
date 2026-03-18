// ─── A02: Cryptographic Failures ─────────────────────────────────────────────

import { Finding, Language, OwaspCategory, RuleContext, SecurityRule } from '../types';
import { isCommentLine, makeFinding, scanLines, stripInlineComment } from '../ruleHelpers';

const ALL: Language[] = ['javascript','typescript','javascriptreact','typescriptreact','python','java','php','go','ruby','csharp'];

// ── A02-001: Hardcoded Credentials / Secrets ──────────────────────────────────
export const hardcodedSecrets: SecurityRule = {
  id: 'A02-001',
  category: OwaspCategory.A02,
  name: 'Hardcoded Secret / Credential',
  severity: 'critical',
  languages: ALL,
  detect(ctx: RuleContext): Finding[] {
    const findings: Finding[] = [];
    // High-precision patterns: variable names strongly suggest secrets AND value is a non-empty literal
    const pattern = /(?:password|passwd|secret|api_?key|apikey|auth_?token|access_?token|client_?secret|private_?key|jwt_?secret|db_?pass|database_?password)\s*(?:=|:)\s*['"`]([^'"`\s]{4,})['"`]/i;
    // Exclude obvious placeholders
    const placeholders = /^(your[_-]|change[_-]|replace|example|placeholder|todo|xxx|<|CHANGE|INSERT|fill|dummy|fake|test|sample|demo)/i;

    for (let i = 0; i < ctx.lines.length; i++) {
      const raw = ctx.lines[i];
      if (isCommentLine(raw, ctx.language)) { continue; }
      const line = stripInlineComment(raw, ctx.language);
      const match = line.match(pattern);
      if (!match) { continue; }
      const value = match[1];
      if (placeholders.test(value)) { continue; }
      // Skip env var reads
      if (/process\.env|os\.environ|System\.getenv|getenv\(|ENV\[/.test(line)) { continue; }
      const col = line.indexOf(match[0]);
      findings.push(makeFinding(this, i, col, col + match[0].length, raw,
        `Hardcoded credential detected: "${match[0].substring(0, 40)}...". Secrets committed to source control can be extracted from git history even after removal.`,
        {
          description: 'Load secrets from environment variables or a secrets manager',
          code: `// Use environment variables instead\nconst secret = process.env.MY_SECRET;\nif (!secret) throw new Error('MY_SECRET is not set');\n\n// Or use a secrets manager (AWS Secrets Manager, Vault, etc.)\n// const secret = await secretsManager.getSecretValue({ SecretId: 'my-secret' });`,
          safe: true,
          safetyNote: '✅ Safe to apply — environment variables are the standard approach. Rotate the exposed secret immediately.',
          breakingRisk: 'low',
        },
        [ctx.lines[i - 1] ?? '', ctx.lines[i + 1] ?? '']
      ));
    }
    return findings;
  }
};

// ── A02-002: Weak Hashing Algorithm ──────────────────────────────────────────
export const weakHash: SecurityRule = {
  id: 'A02-002',
  category: OwaspCategory.A02,
  name: 'Weak Hashing Algorithm (MD5 / SHA-1)',
  severity: 'high',
  languages: ALL,
  detect(ctx: RuleContext): Finding[] {
    return scanLines(ctx, this,
      /(?:createHash|hashlib\.new|MessageDigest\.getInstance|Hash::)\s*\(?\s*['"`](md5|sha1|sha-1)['"`]/i,
      (match) => `Weak hash function "${match[1].toUpperCase()}" is cryptographically broken. MD5 and SHA-1 are vulnerable to collision attacks and must not be used for passwords, signatures, or integrity checks.`,
      (match) => ({
        description: `Replace ${match[1].toUpperCase()} with SHA-256 or bcrypt/argon2 (for passwords)`,
        code: `// For general integrity checks:\ncrypto.createHash('sha256').update(data).digest('hex');\n\n// For passwords — use a slow KDF, never a raw hash:\nimport bcrypt from 'bcrypt';\nconst hash = await bcrypt.hash(password, 12);\nconst valid = await bcrypt.compare(password, hash);`,
        safe: true,
        safetyNote: '✅ Safe to apply for new code. If replacing stored hashes, plan a migration strategy — users will need to re-authenticate.',
        breakingRisk: 'medium',
      })
    );
  }
};

// ── A02-003: Insecure Randomness ──────────────────────────────────────────────
export const insecureRandom: SecurityRule = {
  id: 'A02-003',
  category: OwaspCategory.A02,
  name: 'Insecure Randomness for Security Context',
  severity: 'high',
  languages: ['javascript','typescript','javascriptreact','typescriptreact','python','ruby','php'],
  detect(ctx: RuleContext): Finding[] {
    const findings: Finding[] = [];
    const triggerPattern = /Math\.random\(\)|random\.random\(\)|rand\(\)|Kernel\.rand/;
    const securityContext = /(?:token|secret|session|csrf|nonce|otp|password|salt|key|auth|verification)/i;

    for (let i = 0; i < ctx.lines.length; i++) {
      const raw = ctx.lines[i];
      if (isCommentLine(raw, ctx.language)) { continue; }
      const line = stripInlineComment(raw, ctx.language);
      if (!triggerPattern.test(line)) { continue; }

      // Only flag if the surrounding context suggests a security use
      const window = ctx.lines.slice(Math.max(0, i - 3), Math.min(ctx.lines.length, i + 3)).join(' ');
      if (!securityContext.test(window) && !securityContext.test(line)) { continue; }

      const match = line.match(triggerPattern)!;
      const col = line.indexOf(match[0]);
      findings.push(makeFinding(this, i, col, col + match[0].length, raw,
        `Insecure PRNG used in a security-sensitive context. Math.random() / random.random() are not cryptographically secure and can be predicted by an attacker.`,
        {
          description: 'Use a CSPRNG (Cryptographically Secure Pseudo-Random Number Generator)',
          code: `// Node.js / browser:\nimport crypto from 'crypto';\nconst token = crypto.randomBytes(32).toString('hex'); // 256-bit token\n\n// Python:\nimport secrets\ntoken = secrets.token_hex(32)  # 256-bit token\nnonce = secrets.token_urlsafe(16)`,
          safe: true,
          safetyNote: '✅ Safe to apply — direct drop-in replacement. Adjust byte length to your security requirements.',
          breakingRisk: 'none',
        },
        [ctx.lines[i - 1] ?? '', ctx.lines[i + 1] ?? '']
      ));
    }
    return findings;
  }
};

// ── A02-004: HTTP (not HTTPS) for remote endpoints ───────────────────────────
export const insecureHttp: SecurityRule = {
  id: 'A02-004',
  category: OwaspCategory.A02,
  name: 'Plaintext HTTP Endpoint',
  severity: 'medium',
  languages: ALL,
  detect(ctx: RuleContext): Finding[] {
    const findings: Finding[] = [];
    const pattern = /['"`]http:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0|::1)([a-zA-Z0-9.\-]+)/;
    for (let i = 0; i < ctx.lines.length; i++) {
      const raw = ctx.lines[i];
      if (isCommentLine(raw, ctx.language)) { continue; }
      const line = stripInlineComment(raw, ctx.language);
      const match = line.match(pattern);
      if (!match) { continue; }
      const col = line.indexOf(match[0]);
      findings.push(makeFinding(this, i, col, col + match[0].length, raw,
        `Plaintext HTTP URL detected: "${match[0]}". Traffic can be intercepted, modified, or read by a MITM attacker. Use HTTPS.`,
        {
          description: 'Upgrade to HTTPS',
          code: `// Replace http:// with https://\nconst url = '${match[0].replace('http://', 'https://')}...';`,
          safe: true,
          safetyNote: '✅ Safe to apply if the remote server supports HTTPS (most modern services do). Verify the endpoint before applying.',
          breakingRisk: 'low',
        },
        [ctx.lines[i - 1] ?? '', ctx.lines[i + 1] ?? '']
      ));
    }
    return findings;
  }
};

// ── A02-005: ECB Cipher Mode ──────────────────────────────────────────────────
export const ecbMode: SecurityRule = {
  id: 'A02-005',
  category: OwaspCategory.A02,
  name: 'ECB Block Cipher Mode',
  severity: 'high',
  languages: ALL,
  detect(ctx: RuleContext): Finding[] {
    return scanLines(ctx, this,
      /['"` ](?:AES\/ECB|aes-\d+-ecb|AES_ECB|ECB_MODE|ECB)['"` ]/i,
      () => `ECB (Electronic Code Book) mode encrypts identical plaintext blocks to identical ciphertext blocks, leaking data patterns. It is not semantically secure.`,
      () => ({
        description: 'Use AES-GCM or AES-CBC with a random IV',
        code: `// AES-GCM (authenticated encryption — preferred)\nconst iv = crypto.randomBytes(12);  // 96-bit IV for GCM\nconst cipher = crypto.createCipheriv('aes-256-gcm', key, iv);\nlet encrypted = cipher.update(plaintext, 'utf8', 'hex');\nencrypted += cipher.final('hex');\nconst authTag = cipher.getAuthTag().toString('hex');\n// Store: iv + authTag + encrypted`,
        safe: false,
        safetyNote: '⚠️ Needs scrutiny — switching cipher modes requires re-encrypting all existing data. Plan a migration.',
        breakingRisk: 'high',
      })
    );
  }
};
