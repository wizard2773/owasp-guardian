// ─── OWASP Guardian – Rule Helpers ────────────────────────────────────────────

import { Finding, Fix, Language, OwaspCategory, RuleContext, SecurityRule, Severity } from './types';

// ── Comment detection ─────────────────────────────────────────────────────────

const SINGLE_LINE_COMMENT: Record<string, RegExp> = {
  javascript:       /^\s*(\/\/|\/\*|\*)/,
  typescript:       /^\s*(\/\/|\/\*|\*)/,
  javascriptreact:  /^\s*(\/\/|\/\*|\*)/,
  typescriptreact:  /^\s*(\/\/|\/\*|\*)/,
  java:             /^\s*(\/\/|\/\*|\*)/,
  csharp:           /^\s*(\/\/|\/\*|\*)/,
  go:               /^\s*(\/\/|\/\*|\*)/,
  python:           /^\s*#/,
  ruby:             /^\s*#/,
  php:              /^\s*(\/\/|#|\/\*|\*)/,
};

export function isCommentLine(line: string, lang: Language): boolean {
  const re = SINGLE_LINE_COMMENT[lang];
  return re ? re.test(line) : false;
}

/**
 * Very lightweight inline-comment stripper — removes trailing // comments
 * so patterns don't fire on commented-out code that appears after real code.
 * Not perfect for block comments but good enough for line-level analysis.
 */
export function stripInlineComment(line: string, lang: Language): string {
  if (['javascript','typescript','javascriptreact','typescriptreact','java','csharp','go'].includes(lang)) {
    // Remove // comment not inside a string (simple heuristic: find first // not preceded by odd number of quotes)
    const idx = line.indexOf('//');
    if (idx !== -1) {
      const before = line.slice(0, idx);
      const singleQuotes = (before.match(/'/g) || []).length;
      const doubleQuotes = (before.match(/"/g) || []).length;
      if (singleQuotes % 2 === 0 && doubleQuotes % 2 === 0) {
        return before;
      }
    }
  }
  return line;
}

// ── Building-block factory ─────────────────────────────────────────────────────

export function makeFinding(
  rule: Omit<SecurityRule, 'detect'>,
  line: number,
  col: number,
  endCol: number,
  rawLine: string,
  description: string,
  fix: Fix,
  context?: string[]
): Finding {
  return {
    ruleId: rule.id,
    category: rule.category,
    name: rule.name,
    severity: rule.severity,
    line,
    column: col,
    endColumn: endCol,
    description,
    codeSnippet: rawLine.trim(),
    fix,
    context,
  };
}

/**
 * Core scanner: iterates every non-comment line and applies a pattern.
 * Returns a Finding for every match, calling the provided callbacks to
 * build the description and fix per match.
 */
export function scanLines(
  ctx: RuleContext,
  rule: Omit<SecurityRule, 'detect'>,
  pattern: RegExp,
  descriptionFn: (match: RegExpMatchArray, line: string) => string,
  fixFn: (match: RegExpMatchArray, line: string) => Fix
): Finding[] {
  const findings: Finding[] = [];
  for (let i = 0; i < ctx.lines.length; i++) {
    const raw = ctx.lines[i];
    if (isCommentLine(raw, ctx.language)) { continue; }
    const stripped = stripInlineComment(raw, ctx.language);
    const match = stripped.match(pattern);
    if (!match) { continue; }
    const col = stripped.indexOf(match[0]);
    const context = [
      ctx.lines[i - 1] ?? '',
      ctx.lines[i + 1] ?? '',
    ];
    findings.push(makeFinding(
      rule, i, col, col + match[0].length,
      raw,
      descriptionFn(match, raw),
      fixFn(match, raw),
      context
    ));
  }
  return findings;
}

/**
 * Multi-line scanner: looks for a trigger pattern on a line and then
 * inspects up to `lookAhead` subsequent lines for a confirming pattern.
 * Reduces false positives by requiring two signals.
 */
export function scanLinesWithContext(
  ctx: RuleContext,
  rule: Omit<SecurityRule, 'detect'>,
  triggerPattern: RegExp,
  confirmPattern: RegExp,
  lookAhead: number,
  descriptionFn: (matchLine: string) => string,
  fixFn: (matchLine: string) => Fix
): Finding[] {
  const findings: Finding[] = [];
  for (let i = 0; i < ctx.lines.length; i++) {
    const raw = ctx.lines[i];
    if (isCommentLine(raw, ctx.language)) { continue; }
    const stripped = stripInlineComment(raw, ctx.language);
    if (!triggerPattern.test(stripped)) { continue; }

    // Check surrounding lines for the confirming signal
    const windowEnd = Math.min(i + lookAhead, ctx.lines.length - 1);
    let confirmed = false;
    for (let j = Math.max(0, i - 2); j <= windowEnd; j++) {
      if (confirmPattern.test(ctx.lines[j])) { confirmed = true; break; }
    }
    if (!confirmed) { continue; }

    const match = stripped.match(triggerPattern)!;
    const col = stripped.indexOf(match[0]);
    findings.push(makeFinding(
      rule, i, col, col + match[0].length,
      raw,
      descriptionFn(raw),
      fixFn(raw),
      [ctx.lines[i - 1] ?? '', ctx.lines[i + 1] ?? '']
    ));
  }
  return findings;
}
