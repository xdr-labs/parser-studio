#!/usr/bin/env node
// Grammar duplication ratchet.
//
// The Syslog header grammar is defined once, in contracts/syslog-header-grammar.v1.json.
// Historically the same tokens were hand-written in many TypeScript, Ruby and
// Python sites, which is how one site gets fixed while the others keep the
// defect. This gate counts the hand-written copies per file and compares them
// with contracts/grammar-duplication-baseline.v1.json:
//   - more copies than the baseline (or a copy in a new file)  -> FAIL
//   - fewer copies than the baseline                           -> FAIL until the
//     baseline is lowered with --write, so the baseline can only go down.
// New grammar must come from the contract generator, not from another literal.
//
//   node scripts/verification/grammar-duplication-ratchet.mjs           check
//   node scripts/verification/grammar-duplication-ratchet.mjs --write   lower the baseline (never raises it)
import { readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs';
import { join, relative, resolve } from 'node:path';

const ROOT = resolve('.');
const BASELINE = 'contracts/grammar-duplication-baseline.v1.json';
const SCAN_ROOTS = ['src', 'backend/src', 'backend/templates', 'runtime/multipass'];
const GENERATED = new Set(['src/grammar/syslogHeaderGrammar.generated.ts', 'backend/src/syslog-header-grammar.generated.ts', 'runtime/multipass/syslog_header_grammar_generated.py']);
/** Literal source text that identifies a hand-written copy of a contract token. */
export const SIGNATURES = Object.freeze({
  'hostname-printable-ascii-255': '[!-~]{1,255}',
  'bsd-month-token': '[A-Z][a-z]{2}',
  'pri-capture': '(\\d{1,3})>',
  'rfc5424-version-any-digits': '[1-9]\\d{0,2}',
  'rfc5424-version-literal-one': '>(1) ',
});

function sourceFiles(directory) {
  const out = [];
  for (const name of readdirSync(directory).sort()) {
    const path = join(directory, name);
    if (statSync(path).isDirectory()) { if (name !== 'node_modules' && name !== 'dist') out.push(...sourceFiles(path)); continue; }
    if (!/\.(ts|tsx|tpl|py|rb)$/.test(name) || /\.(test|spec)\.tsx?$/.test(name) || /^test_.*\.py$/.test(name)) continue;
    out.push(path);
  }
  return out;
}

export function measure(root = ROOT) {
  const counts = Object.fromEntries(Object.keys(SIGNATURES).map(name => [name, {}]));
  for (const scanRoot of SCAN_ROOTS) {
    for (const path of sourceFiles(join(root, scanRoot))) {
      const rel = relative(root, path).split('\\').join('/');
      if (GENERATED.has(rel)) continue;
      const text = readFileSync(path, 'utf8');
      for (const [name, literal] of Object.entries(SIGNATURES)) {
        const count = text.split(literal).length - 1;
        if (count > 0) counts[name][rel] = count;
      }
    }
  }
  return counts;
}

export function compare(baseline, current) {
  const increases = [], decreases = [];
  for (const name of Object.keys(SIGNATURES)) {
    const before = baseline.signatures?.[name]?.files ?? {};
    const now = current[name] ?? {};
    for (const file of new Set([...Object.keys(before), ...Object.keys(now)])) {
      const was = before[file] ?? 0, is = now[file] ?? 0;
      if (is > was) increases.push(`${name}: ${file} ${was} -> ${is}`);
      if (is < was) decreases.push(`${name}: ${file} ${was} -> ${is}`);
    }
  }
  return { increases, decreases };
}

const total = counts => Object.values(counts).reduce((sum, files) => sum + Object.values(files).reduce((a, b) => a + b, 0), 0);

function main(argv) {
  const current = measure();
  let baseline = { signatures: {} };
  try { baseline = JSON.parse(readFileSync(join(ROOT, BASELINE), 'utf8')); } catch { if (!argv.includes('--write')) { process.stderr.write('GRAMMAR_RATCHET_BASELINE_MISSING\n'); process.exit(1); } }
  const { increases, decreases } = compare(baseline, current);
  if (argv.includes('--write')) {
    if (Object.keys(baseline.signatures).length > 0 && increases.length > 0) {
      for (const line of increases) process.stderr.write(`GRAMMAR_RATCHET_INCREASE ${line}\n`);
      process.stderr.write('The baseline never goes up: take the token from the grammar contract instead.\n');
      process.exit(1);
    }
    const next = {
      schema: 'parserstudio.grammar-duplication-baseline.v1',
      purpose: 'Hand-written copies of Syslog header grammar tokens that still exist outside contracts/syslog-header-grammar.v1.json. The numbers may only decrease; scripts/verification/grammar-duplication-ratchet.mjs enforces it.',
      total: total(current),
      signatures: Object.fromEntries(Object.entries(SIGNATURES).map(([name, literal]) => [name, { literal, files: current[name] }])),
    };
    writeFileSync(join(ROOT, BASELINE), JSON.stringify(next, null, 2) + '\n');
    process.stdout.write(`GRAMMAR_RATCHET_BASELINE_WRITTEN total=${next.total}\n`);
    return;
  }
  for (const line of increases) process.stderr.write(`GRAMMAR_RATCHET_INCREASE ${line}\n`);
  for (const line of decreases) process.stderr.write(`GRAMMAR_RATCHET_STALE_BASELINE ${line} (run with --write to lower the baseline)\n`);
  if (increases.length || decreases.length) process.exit(1);
  process.stdout.write(`GRAMMAR_RATCHET_PASS hand_written_copies=${total(current)} baseline=${baseline.total}\n`);
}

if (process.argv[1] && resolve(process.argv[1]) === resolve(new URL(import.meta.url).pathname)) main(process.argv.slice(2));
