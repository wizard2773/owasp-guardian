// ─── File Scanner ─────────────────────────────────────────────────────────────
'use strict';

const fs   = require('fs');
const path = require('path');
const { runRules } = require('./engine');

const EXT_LANG = {
  '.js': 'javascript', '.mjs': 'javascript', '.cjs': 'javascript',
  '.ts': 'typescript', '.mts': 'typescript',
  '.jsx': 'javascript', '.tsx': 'typescript',
  '.py': 'python',
  '.java': 'java',
  '.php': 'php',
  '.go': 'go',
  '.rb': 'ruby',
  '.cs': 'csharp',
};

const SUPPORTED_EXTS = new Set(Object.keys(EXT_LANG));

const EXCLUDE_DIRS = new Set([
  'node_modules', '.git', 'dist', 'build', 'out', 'target',
  '.venv', '__pycache__', '.gradle', 'vendor', 'coverage',
  '.next', '.nuxt', 'public', 'static',
]);

function detectLanguage(filePath) {
  return EXT_LANG[path.extname(filePath).toLowerCase()] || null;
}

function scanFile(filePath) {
  const lang = detectLanguage(filePath);
  if (!lang) return null;

  let text;
  try { text = fs.readFileSync(filePath, 'utf8'); }
  catch { return null; }

  const lines = text.split('\n');
  const findings = runRules(lines, lang);

  return {
    filePath: path.resolve(filePath),
    lang,
    lines: lines.length,
    chars: text.length,
    findings,
    scannedAt: new Date(),
  };
}

function collectFiles(dirOrFile, opts = {}) {
  const stat = fs.statSync(dirOrFile);
  if (stat.isFile()) {
    return detectLanguage(dirOrFile) ? [dirOrFile] : [];
  }

  const files = [];
  const maxDepth = opts.maxDepth ?? 10;

  function walk(dir, depth) {
    if (depth > maxDepth) return;
    let entries;
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); }
    catch { return; }

    for (const entry of entries) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (!EXCLUDE_DIRS.has(entry.name) && !entry.name.startsWith('.')) {
          walk(full, depth + 1);
        }
      } else if (entry.isFile()) {
        const ext = path.extname(entry.name).toLowerCase();
        if (SUPPORTED_EXTS.has(ext)) {
          // Skip minified / bundled files
          if (/\.min\.|\.bundle\.|\.chunk\./.test(entry.name)) continue;
          files.push(full);
        }
      }
    }
  }

  walk(dirOrFile, 0);
  return files;
}

function scanDirectory(dirPath, opts = {}, progressCb = null) {
  const files = collectFiles(dirPath, opts);
  const results = [];
  let done = 0;

  for (const file of files) {
    const result = scanFile(file);
    if (result) results.push(result);
    done++;
    if (progressCb) progressCb(done, files.length, file);
  }

  return results;
}

function summarise(results) {
  const bySev = { critical: 0, high: 0, medium: 0, low: 0 };
  const byCat = {};
  const byFile = {};
  let total = 0;

  for (const r of results) {
    byFile[r.filePath] = r.findings.length;
    for (const f of r.findings) {
      bySev[f.severity]++;
      byCat[f.category] = (byCat[f.category] || 0) + 1;
      total++;
    }
  }

  return { total, bySev, byCat, byFile, filesScanned: results.length };
}

module.exports = { scanFile, scanDirectory, collectFiles, summarise, detectLanguage };
