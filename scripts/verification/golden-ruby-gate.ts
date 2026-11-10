// Aggregate gate for the golden vendor chain on the pinned Ruby target.
//
// The browser golden spec (tests/golden-vendor-execution-20261110.spec.ts) leaves
// one bundle per vendor case in <downloads>/golden-bundles: the Ruby Fragment the
// browser actually downloaded, the raw log and the mapping rows the Map Fields
// stage showed. This gate:
//   prepare  - checks the bundles against the corpus and the recorded downloads
//              (every vendor case present, raw log identical to the corpus, the
//              Ruby byte-identical to a recorded download) and writes the input
//              for scripts/verification/ruby-golden-event-runner.rb;
//   compare  - takes the events that runner printed on some Ruby version and
//              compares them with the documented values read from the corpus.
// Documented values never travel through the bundle, so a bundle cannot vouch for
// itself. Scope: Parser Studio output only; not a Stellar Cyber import, Syslog
// reception or indexing result.
//
//   golden-ruby-gate.ts prepare <downloads-dir> <runner-input.json>
//   golden-ruby-gate.ts compare <downloads-dir> <runner-output.json> [--expect-ruby 2.4.9]
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { readFile, readdir, writeFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { compareEventToGolden, type MappingRow } from '../../backend/src/golden-event-comparison.js';

interface Golden { sourcePath: string; sourceValue: unknown }
interface VendorCase { id: string; sampleClass: string; rawSample: string; desiredFields: string; goldenSourceValues: Golden[] }
interface Bundle { contract: string; id: string; raw: string; ruby: string; rubySha256: string; rows: MappingRow[]; required: string[] }

// One registry for the browser spec and this gate (backend/test/golden-corpus-registry.test.ts keeps it complete).
export const CORPUS_FILES: string[] = (JSON.parse(readFileSync(resolve('evals/golden-corpus/corpus-files.v1.json'), 'utf8')) as { files: string[] }).files;

async function corpus(): Promise<VendorCase[]> {
  const all: VendorCase[] = [];
  for (const file of CORPUS_FILES) all.push(...(JSON.parse(await readFile(resolve(file), 'utf8')) as { cases: VendorCase[] }).cases);
  // Same selection as the browser spec: publisher-documented examples only.
  return all.filter(item => item.sampleClass.startsWith('VENDOR_DOCUMENTED'));
}

async function files(dir: string, match: RegExp): Promise<string[]> {
  const entries = await readdir(dir, { recursive: true, withFileTypes: true });
  return entries.filter(e => e.isFile() && match.test(e.name)).map(e => join(e.parentPath, e.name)).sort();
}

async function recordedDownloadHashes(dir: string): Promise<Set<string>> {
  const hashes = new Set<string>();
  for (const index of await files(dir, /^index-.*\.jsonl$/)) {
    for (const line of (await readFile(index, 'utf8')).split('\n').filter(Boolean)) {
      const entry = JSON.parse(line) as { sha256: string; synthetic: string | null };
      if (entry.synthetic === null) hashes.add(entry.sha256);
    }
  }
  return hashes;
}

async function loadBundles(dir: string): Promise<{ bundles: Map<string, Bundle>; problems: string[] }> {
  const problems: string[] = [];
  const bundles = new Map<string, Bundle>();
  for (const path of await files(dir, /\.json$/)) {
    if (!path.includes('/golden-bundles/')) continue;
    const bundle = JSON.parse(await readFile(path, 'utf8')) as Bundle;
    if (bundle.contract !== 'parser-studio.golden-bundle.v1') { problems.push('GOLDEN_BUNDLE_CONTRACT ' + path); continue; }
    if (bundles.has(bundle.id)) { problems.push('GOLDEN_BUNDLE_DUPLICATE ' + bundle.id); continue; }
    bundles.set(bundle.id, bundle);
  }
  return { bundles, problems };
}

async function prepare(dir: string, out: string): Promise<void> {
  const cases = await corpus();
  const { bundles, problems } = await loadBundles(dir);
  const hashes = await recordedDownloadHashes(dir);
  for (const item of cases) {
    const bundle = bundles.get(item.id);
    if (!bundle) { problems.push('GOLDEN_BUNDLE_MISSING ' + item.id); continue; }
    if (bundle.raw !== item.rawSample) problems.push('GOLDEN_RAW_DIFFERS_FROM_CORPUS ' + item.id);
    const sha = createHash('sha256').update(bundle.ruby, 'utf8').digest('hex');
    if (sha !== bundle.rubySha256) problems.push('GOLDEN_RUBY_HASH_MISMATCH ' + item.id);
    // The executed Ruby must be a file the browser really downloaded.
    if (!hashes.has(sha)) problems.push('GOLDEN_RUBY_NOT_A_RECORDED_DOWNLOAD ' + item.id);
  }
  for (const id of bundles.keys()) if (!cases.some(item => item.id === id)) problems.push('GOLDEN_BUNDLE_NOT_IN_CORPUS ' + id);
  if (problems.length) { process.stderr.write(problems.join('\n') + '\n'); process.exit(1); }
  await writeFile(out, JSON.stringify({ cases: cases.map(item => ({ id: item.id, ruby: bundles.get(item.id)!.ruby, raw: item.rawSample })) }), { mode: 0o600 });
  process.stdout.write('GOLDEN_RUBY_GATE_PREPARED cases=' + cases.length + '\n');
}

async function compare(dir: string, outputPath: string, expectRuby: string | undefined): Promise<void> {
  const cases = await corpus();
  const { bundles } = await loadBundles(dir);
  const output = JSON.parse(await readFile(outputPath, 'utf8')) as { ruby: string; results: Record<string, { calls: [unknown, unknown][] }> };
  const problems: string[] = [];
  if (expectRuby && output.ruby !== expectRuby) problems.push('GOLDEN_RUBY_VERSION expected ' + expectRuby + ' got ' + output.ruby);
  let checked = 0;
  for (const item of cases) {
    const bundle = bundles.get(item.id);
    const result = output.results[item.id];
    if (!bundle || !result) { problems.push('GOLDEN_NOT_EXECUTED ' + item.id); continue; }
    const comparison = compareEventToGolden({
      golden: item.goldenSourceValues, rows: bundle.rows, required: bundle.required,
      events: result.calls.map(([time, record]) => ({ time, record })),
    });
    // The required list must be exactly what the corpus asks for, not what the bundle claims.
    const wanted = item.desiredFields.split(',').map(f => f.trim()).filter(Boolean);
    if (JSON.stringify([...wanted].sort()) !== JSON.stringify([...bundle.required].sort())) problems.push('GOLDEN_REQUIRED_DIFFERS_FROM_CORPUS ' + item.id);
    for (const problem of comparison.problems) problems.push('GOLDEN_' + problem.code + ' ' + item.id + ' ' + problem.sourcePath + ' ' + problem.detail);
    if (comparison.matched.length !== wanted.length) problems.push('GOLDEN_MATCH_COUNT ' + item.id + ' ' + comparison.matched.length + '/' + wanted.length);
    checked += 1;
  }
  if (problems.length) { process.stderr.write(problems.join('\n') + '\n'); process.exit(1); }
  process.stdout.write('GOLDEN_RUBY_GATE_PASS ruby=' + output.ruby + ' cases=' + checked + '\n');
}

const [mode, dir, file, ...rest] = process.argv.slice(2);
const run = mode === 'prepare' && dir && file ? prepare(resolve(dir), resolve(file))
  : mode === 'compare' && dir && file ? compare(resolve(dir), resolve(file), rest[0] === '--expect-ruby' ? rest[1] : undefined)
  : Promise.reject(new Error('usage: golden-ruby-gate.ts prepare|compare <downloads-dir> <file> [--expect-ruby X.Y.Z]'));
run.catch(error => { process.stderr.write(String(error instanceof Error ? error.message : error) + '\n'); process.exit(2); });
