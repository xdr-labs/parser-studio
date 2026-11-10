// Negative controls for the aggregate golden gate (scripts/verification/golden-ruby-gate.ts).
//
// A gate that has only ever been seen passing proves nothing. This test builds a
// perfect set of bundles and runner output for the real corpus, checks the gate
// accepts it, then breaks exactly one thing at a time and requires the gate to fail
// with the code that names that thing. It needs no Ruby and no browser: the gate's
// job is the bookkeeping between corpus, bundles, recorded downloads and executed
// events, and that is what is attacked here.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import test from 'node:test';

const root = resolve(import.meta.dirname, '../..');
const TSX = resolve(root, 'backend/node_modules/tsx/dist/cli.mjs');
const GATE = resolve(root, 'scripts/verification/golden-ruby-gate.ts');

interface Case { id: string; sampleClass: string; rawSample: string; desiredFields: string;
  goldenSourceValues: { sourcePath: string; sourceValue: unknown }[] }
interface Bundle { contract: string; id: string; raw: string; ruby: string; rubySha256: string;
  rows: { source: string; target: string; vendorNamespace: boolean }[]; required: string[] }
interface Fixture { dir: string; bundles: Map<string, Bundle>; recorded: Set<string>;
  results: Record<string, { calls: [unknown, unknown][] }>; ruby: string }

const registry = JSON.parse(readFileSync(resolve(root, 'evals/golden-corpus/corpus-files.v1.json'), 'utf8')) as { files: string[] };
const cases: Case[] = registry.files
  .flatMap(file => (JSON.parse(readFileSync(resolve(root, file), 'utf8')) as { cases: Case[] }).cases)
  .filter(item => item.sampleClass.startsWith('VENDOR_DOCUMENTED'));

const sha = (text: string) => createHash('sha256').update(text, 'utf8').digest('hex');

function perfect(): Fixture {
  const bundles = new Map<string, Bundle>();
  const recorded = new Set<string>();
  const results: Fixture['results'] = {};
  for (const item of cases) {
    const required = item.desiredFields.split(',').map(field => field.trim()).filter(Boolean);
    const ruby = '# fragment for ' + item.id;
    recorded.add(sha(ruby));
    // Flat official-style targets: the event holds exactly the documented value.
    const rows = item.goldenSourceValues.map((golden, index) => ({
      source: golden.sourcePath, target: 'f' + index, vendorNamespace: false }));
    bundles.set(item.id, { contract: 'parser-studio.golden-bundle.v1', id: item.id, raw: item.rawSample,
      ruby, rubySha256: sha(ruby), rows, required });
    const record: Record<string, string> = {};
    item.goldenSourceValues.forEach((golden, index) => { record['f' + index] = String(golden.sourceValue); });
    results[item.id] = { calls: [[null, record]] };
  }
  return { dir: '', bundles, recorded, results, ruby: '2.4.9' };
}

function materialise(fixture: Fixture): { dir: string; out: string; output: string } {
  const dir = mkdtempSync(join(tmpdir(), 'golden-gate-'));
  mkdirSync(join(dir, 'golden-bundles'));
  for (const bundle of fixture.bundles.values()) {
    writeFileSync(join(dir, 'golden-bundles', bundle.id + '.json'), JSON.stringify(bundle));
  }
  writeFileSync(join(dir, 'index-1.jsonl'),
    [...fixture.recorded].map(hash => JSON.stringify({ sha256: hash, synthetic: null })).join('\n') + '\n');
  const output = join(dir, 'runner-output.json');
  writeFileSync(output, JSON.stringify({ ruby: fixture.ruby, results: fixture.results }));
  return { dir, out: join(dir, 'runner-input.json'), output };
}

function gate(args: string[]): { status: number | null; stdout: string; stderr: string } {
  const run = spawnSync(process.execPath, [TSX, GATE, ...args], { cwd: root, encoding: 'utf8' });
  return { status: run.status, stdout: run.stdout, stderr: run.stderr };
}

function attack(name: string, mutate: (fixture: Fixture) => void, stage: 'prepare' | 'compare', code: string): void {
  test('golden gate rejects: ' + name, () => {
    const fixture = perfect();
    mutate(fixture);
    const { dir, out, output } = materialise(fixture);
    try {
      const run = stage === 'prepare' ? gate(['prepare', dir, out])
        : gate(['compare', dir, output, '--expect-ruby', '2.4.9']);
      assert.notEqual(run.status, 0, 'gate accepted a broken input: ' + name);
      assert.ok(run.stderr.includes(code), 'expected ' + code + ' in: ' + run.stderr);
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });
}

test('golden gate accepts a perfect set of bundles and executed events', () => {
  assert.ok(cases.length >= 14);
  const { dir, out, output } = materialise(perfect());
  try {
    const prepared = gate(['prepare', dir, out]);
    assert.equal(prepared.status, 0, prepared.stderr);
    assert.ok(prepared.stdout.includes('cases=' + cases.length));
    const compared = gate(['compare', dir, output, '--expect-ruby', '2.4.9']);
    assert.equal(compared.status, 0, compared.stderr);
    assert.ok(compared.stdout.includes('GOLDEN_RUBY_GATE_PASS ruby=2.4.9 cases=' + cases.length));
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

const first = cases[0]!.id;
const second = cases[1]!.id;

attack('a vendor case with no bundle', f => { f.bundles.delete(first); }, 'prepare', 'GOLDEN_BUNDLE_MISSING ' + first);
attack('a bundle whose raw log differs from the corpus', f => {
  const b = f.bundles.get(first)!; f.bundles.set(first, { ...b, raw: b.raw + ' ' }); }, 'prepare', 'GOLDEN_RAW_DIFFERS_FROM_CORPUS ' + first);
attack('Ruby edited after hashing', f => {
  const b = f.bundles.get(first)!; f.bundles.set(first, { ...b, ruby: b.ruby + '\n# edited' }); }, 'prepare', 'GOLDEN_RUBY_HASH_MISMATCH ' + first);
attack('Ruby that no browser download recorded', f => {
  const b = f.bundles.get(first)!; const ruby = b.ruby + '\n# never downloaded';
  f.bundles.set(first, { ...b, ruby, rubySha256: sha(ruby) }); }, 'prepare', 'GOLDEN_RUBY_NOT_A_RECORDED_DOWNLOAD ' + first);
attack('a bundle that is not in the corpus', f => {
  f.bundles.set('stray_case', { ...f.bundles.get(first)!, id: 'stray_case' }); }, 'prepare', 'GOLDEN_BUNDLE_NOT_IN_CORPUS stray_case');
attack('a bundle with a wrong contract tag', f => {
  f.bundles.set(first, { ...f.bundles.get(first)!, contract: 'something.else' }); }, 'prepare', 'GOLDEN_BUNDLE_CONTRACT');

attack('output from another Ruby version', f => { f.ruby = '3.2.3'; }, 'compare', 'GOLDEN_RUBY_VERSION expected 2.4.9 got 3.2.3');
attack('a case the runner never executed', f => { delete f.results[first]; }, 'compare', 'GOLDEN_NOT_EXECUTED ' + first);
attack('an emitted value that differs from the documentation', f => {
  const call = f.results[first]!.calls[0]!; const record = { ...(call[1] as Record<string, string>) };
  record['f0'] = record['f0'] + 'x'; f.results[first] = { calls: [[call[0], record]] }; },
'compare', 'GOLDEN_REQUIRED_FIELD_VALUE_MISMATCH ' + first);
attack('a required field absent from the emitted event', f => {
  const call = f.results[second]!.calls[0]!; const record = { ...(call[1] as Record<string, string>) };
  delete record['f0']; f.results[second] = { calls: [[call[0], record]] }; },
'compare', 'GOLDEN_REQUIRED_FIELD_MISSING_IN_EVENT ' + second);
attack('a bundle that shrank its own required list', f => {
  const b = f.bundles.get(first)!; f.bundles.set(first, { ...b, required: b.required.slice(0, 1) }); },
'compare', 'GOLDEN_REQUIRED_DIFFERS_FROM_CORPUS ' + first);
attack('a mapping row pointing at the wrong destination', f => {
  const b = f.bundles.get(first)!;
  f.bundles.set(first, { ...b, rows: b.rows.map((row, index) => index === 0 ? { ...row, target: 'elsewhere' } : row) }); },
'compare', 'GOLDEN_REQUIRED_FIELD_MISSING_IN_EVENT ' + first);
attack('two events for one raw log', f => {
  const call = f.results[first]!.calls[0]!; f.results[first] = { calls: [call, call] }; }, 'compare', 'GOLDEN_EVENT_COUNT ' + first);
