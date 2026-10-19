# 🛡️ OWASP Guardian — VS Code Extension

Static analysis for **OWASP Top 10** vulnerabilities. No AI, no network calls, no subscriptions.  
Works entirely offline using hand-crafted, high-precision detection rules.

---

## Features

| Feature | Detail |
|---|---|
| **Inline diagnostics** | Red/yellow squiggles on vulnerable lines — visible as you type |
| **Hover card** | Hover over any flagged line → see: what's wrong, why it matters, suggested fix |
| **Quick Fix** | Code-action lightbulb → insert fix as commented code block |
| **Full report panel** | Dashboard with severity breakdown, OWASP category heatmap, and all findings |
| **Workspace scan** | Scan every source file in the repo at once |
| **Auto-scan on save** | Findings update automatically every time you save |
| **Safety indicator** | Every fix is labeled: ✅ Safe to apply or ⚠️ Needs scrutiny |
| **Breaking risk** | Each fix is rated: None / Low / Medium / High |

---

## Supported Languages

JavaScript · TypeScript · JSX/TSX · Python · Java · PHP · Go · Ruby · C#

---

## OWASP Categories Covered

| ID | Category | Rules |
|---|---|---|
| A01 | Broken Access Control | Path traversal, IDOR, CORS wildcard |
| A02 | Cryptographic Failures | Hardcoded secrets, MD5/SHA-1, insecure random, HTTP URLs, ECB mode |
| A03 | Injection | SQL, command, XSS, eval(), LDAP |
| A04 | Insecure Design | Mass assignment, missing rate limiting |
| A05 | Security Misconfiguration | Debug mode, default credentials, exposed stack traces, missing helmet |
| A07 | Auth Failures | JWT `none` algorithm, weak passwords, session fixation |
| A08 | Integrity Failures | Insecure deserialization (pickle, PHP unserialize, Java ObjectInputStream) |
| A09 | Logging Failures | Credentials in logs, silent error handlers |
| A10 | SSRF | Unvalidated server-side URL fetching |

---

## Installation

### Option A — Install from VSIX (recommended for private use)

```bash
# 1. Clone and build
git clone https://github.com/wizard2773/owasp-guardian.git
cd owasp-guardian
npm install
npm run package   # creates owasp-guardian-1.1.0.vsix

# 2. Install in VS Code
code --install-extension owasp-guardian-1.1.0.vsix
```

### Option B — Install from VS Code Marketplace (once published)

1. Open VS Code → Extensions (`Ctrl+Shift+X`)
2. Search: `OWASP Guardian`
3. Click Install

---

## Usage

| Action | How |
|---|---|
| Scan current file | `Ctrl+Shift+P` → **OWASP Guardian: Scan Current File** |
| Scan workspace | `Ctrl+Shift+P` → **OWASP Guardian: Scan Entire Workspace** |
| Open full report | `Ctrl+Shift+P` → **OWASP Guardian: Show Full Report** |
| See fix details | Hover over any squiggled line |
| Apply / insert fix | Click the 💡 lightbulb on any flagged line |
| Right-click shortcut | Right-click in editor → **OWASP Guardian: Scan Current File** |

---

## Configuration

Open **Settings** → search `owaspGuardian`:

| Setting | Default | Description |
|---|---|---|
| `owaspGuardian.enableOnSave` | `true` | Auto-scan on file save |
| `owaspGuardian.minSeverity` | `medium` | Minimum severity to report (`low` / `medium` / `high` / `critical`) |
| `owaspGuardian.excludePatterns` | `["**/node_modules/**", ...]` | Glob patterns to skip |
| `owaspGuardian.excludeTestFiles` | `false` | Skip `*.test.*` and `*.spec.*` files |

---

## False Positive Policy

This extension prioritises **precision over recall**:

- Comment lines are always skipped
- Rules require multiple confirming signals (e.g. IDOR requires both a DB lookup *and* absence of auth check in surrounding 16 lines)
- Security-context checks prevent non-security uses of `Math.random()` from triggering the insecure randomness rule
- Placeholder values (`your-secret-here`, `CHANGE_ME`, etc.) are excluded from hardcoded-secrets detection

If you see a false positive, open an issue with the file + line number.

---

## Adding Custom Rules

Edit `src/rules/index.ts` and add your `SecurityRule` object:

```typescript
import { SecurityRule, OwaspCategory } from '../types';

const myRule: SecurityRule = {
  id: 'CUSTOM-001',
  category: OwaspCategory.A03,
  name: 'My Custom Rule',
  severity: 'high',
  languages: ['javascript', 'typescript'],
  detect(ctx) {
    return scanLines(ctx, this,
      /myDangerousPattern/,
      () => 'Description of the issue',
      () => ({
        description: 'How to fix it',
        code: '// Safe replacement code',
        safe: true,
        safetyNote: '✅ Safe to apply',
        breakingRisk: 'none',
      })
    );
  }
};
```

---

## License

MIT
