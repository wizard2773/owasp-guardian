// ─── CLI Output Utilities ─────────────────────────────────────────────────────
'use strict';

const ESC = '\x1b';
const c = {
  reset:   `${ESC}[0m`,
  bold:    `${ESC}[1m`,
  dim:     `${ESC}[2m`,
  italic:  `${ESC}[3m`,

  black:   `${ESC}[30m`,
  red:     `${ESC}[31m`,
  green:   `${ESC}[32m`,
  yellow:  `${ESC}[33m`,
  blue:    `${ESC}[34m`,
  magenta: `${ESC}[35m`,
  cyan:    `${ESC}[36m`,
  white:   `${ESC}[37m`,
  gray:    `${ESC}[90m`,

  bgRed:     `${ESC}[41m`,
  bgGreen:   `${ESC}[42m`,
  bgYellow:  `${ESC}[43m`,
  bgBlue:    `${ESC}[44m`,
  bgMagenta: `${ESC}[45m`,
  bgCyan:    `${ESC}[46m`,
  bgGray:    `${ESC}[100m`,
  bgOrange:  `${ESC}[48;5;208m`,
};

const termWidth = () => process.stdout.columns || 100;

function paint(color, text) { return `${color}${text}${c.reset}`; }

const SEV_COLOR = {
  critical: (t) => `${c.bold}${c.bgRed}${c.white} ${t} ${c.reset}`,
  high:     (t) => `${c.bold}${c.bgOrange}${c.white} ${t} ${c.reset}`,
  medium:   (t) => `${c.bold}${c.yellow} ${t} ${c.reset}`,
  low:      (t) => `${c.bold}${c.blue} ${t} ${c.reset}`,
};

const SEV_DOT = {
  critical: paint(c.red,     '●'),
  high:     paint(c.yellow,  '●'),
  medium:   paint(c.cyan,    '●'),
  low:      paint(c.blue,    '●'),
};

const SAFE_BADGE = {
  true:  `${c.green}✔ Safe${c.reset}`,
  false: `${c.yellow}⚠ Needs scrutiny${c.reset}`,
};

const BREAK_COLOR = {
  none:   (t) => paint(c.green,   t),
  low:    (t) => paint(c.cyan,    t),
  medium: (t) => paint(c.yellow,  t),
  high:   (t) => paint(c.red,     t),
};

function hr(char = '─', color = c.gray) {
  return paint(color, char.repeat(Math.min(termWidth(), 90)));
}

function header(text) {
  const tw = Math.min(termWidth(), 90);
  const pad = Math.max(0, Math.floor((tw - text.length - 2) / 2));
  const line = '═'.repeat(tw);
  console.log(paint(c.cyan, line));
  console.log(paint(c.cyan, '  ') + paint(c.bold + c.white, text));
  console.log(paint(c.cyan, line));
}

function subheader(text) {
  console.log(`\n${paint(c.bold + c.cyan, '┌─ ' + text)}`);
}

function info(msg)    { console.log(`${paint(c.blue,   '  ℹ')} ${msg}`); }
function success(msg) { console.log(`${paint(c.green,  '  ✔')} ${msg}`); }
function warn(msg)    { console.log(`${paint(c.yellow, '  ⚠')} ${msg}`); }
function error(msg)   { console.log(`${paint(c.red,    '  ✖')} ${msg}`); }
function muted(msg)   { console.log(paint(c.gray, `  ${msg}`)); }

function dim(text)  { return `${c.dim}${text}${c.reset}`; }
function bold(text) { return `${c.bold}${text}${c.reset}`; }

function prompt() {
  process.stdout.write(`\n${paint(c.cyan + c.bold, 'guardian')}${paint(c.gray, '›')} `);
}

function codeBlock(code, label = '') {
  const lines = code.split('\n');
  const tw = Math.min(termWidth() - 4, 86);
  if (label) console.log(paint(c.gray, `  ╔${'═'.repeat(tw - 2)}╗  ${label}`));
  else        console.log(paint(c.gray, `  ╔${'═'.repeat(tw - 2)}╗`));
  for (const line of lines) {
    const truncated = line.length > tw - 4 ? line.slice(0, tw - 7) + '...' : line;
    console.log(paint(c.gray, '  ║ ') + paint(c.green, truncated));
  }
  console.log(paint(c.gray, `  ╚${'═'.repeat(tw - 2)}╝`));
}

function table(rows, cols) {
  // rows: array of arrays; cols: array of {label, width}
  const header = cols.map(col => bold(col.label.padEnd(col.width))).join('  ');
  console.log(`  ${header}`);
  console.log(`  ${paint(c.gray, cols.map(col => '─'.repeat(col.width)).join('  '))}`);
  for (const row of rows) {
    const line = row.map((cell, i) => {
      const str = String(cell ?? '');
      return str.length > cols[i].width ? str.slice(0, cols[i].width - 1) + '…' : str.padEnd(cols[i].width);
    }).join('  ');
    console.log(`  ${line}`);
  }
}

module.exports = { c, paint, SEV_COLOR, SEV_DOT, SAFE_BADGE, BREAK_COLOR, hr, header, subheader, info, success, warn, error, muted, dim, bold, prompt, codeBlock, table };
