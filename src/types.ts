// ─── OWASP Guardian – Core Types ─────────────────────────────────────────────

export type Language =
  | 'javascript' | 'typescript' | 'javascriptreact' | 'typescriptreact'
  | 'python' | 'java' | 'php' | 'go' | 'ruby' | 'csharp';

export type Severity = 'critical' | 'high' | 'medium' | 'low';

export type BreakingRisk = 'none' | 'low' | 'medium' | 'high';

export const SEVERITY_RANK: Record<Severity, number> = {
  critical: 4, high: 3, medium: 2, low: 1
};

export enum OwaspCategory {
  A01 = 'A01:2021 – Broken Access Control',
  A02 = 'A02:2021 – Cryptographic Failures',
  A03 = 'A03:2021 – Injection',
  A04 = 'A04:2021 – Insecure Design',
  A05 = 'A05:2021 – Security Misconfiguration',
  A06 = 'A06:2021 – Vulnerable & Outdated Components',
  A07 = 'A07:2021 – Identification & Authentication Failures',
  A08 = 'A08:2021 – Software & Data Integrity Failures',
  A09 = 'A09:2021 – Security Logging & Monitoring Failures',
  A10 = 'A10:2021 – Server-Side Request Forgery (SSRF)',
}

export interface Fix {
  description: string;
  /** Replacement code snippet or guidance */
  code: string;
  /** true = safe to apply automatically, false = needs developer review */
  safe: boolean;
  /** Human-readable note explaining the safety assessment */
  safetyNote: string;
  breakingRisk: BreakingRisk;
}

export interface Finding {
  ruleId: string;
  category: OwaspCategory;
  name: string;
  severity: Severity;
  /** 0-indexed line number */
  line: number;
  column: number;
  endColumn: number;
  description: string;
  /** The raw line of code that triggered this finding */
  codeSnippet: string;
  fix: Fix;
  /** Extra context lines (1 before, 1 after) for the report */
  context?: string[];
}

export interface ScanResult {
  filePath: string;
  language: Language;
  findings: Finding[];
  scannedAt: Date;
  linesScanned: number;
}

export interface WorkspaceScanResult {
  results: ScanResult[];
  totalFindings: number;
  bySeverity: Record<Severity, number>;
  byCategory: Partial<Record<OwaspCategory, number>>;
  scannedAt: Date;
}

/** Internal context passed to each rule's detect function */
export interface RuleContext {
  lines: string[];
  filePath: string;
  language: Language;
}

export interface SecurityRule {
  id: string;
  category: OwaspCategory;
  name: string;
  severity: Severity;
  languages: Language[];
  /** Analyse the file and return zero or more findings */
  detect(ctx: RuleContext): Finding[];
}
