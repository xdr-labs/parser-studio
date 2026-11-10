// Validates the Ruby Fragments and .conf files that Chromium E2E tests actually
// downloaded (recorded by tests/support/downloadSink.ts) against the Stellar
// structure contract, and optionally writes them as a payload for the offline
// Ruby 2.4.9 / 3.2.11 runner (scripts/verification/ruby-variant-matrix-runner.rb).
//
//   validate-downloaded-artifacts.ts <dir> [--min-real-fragments N] [--min-real-confs N]
//                                    [--ruby-payload <file>]
//
// <dir> may hold one sink directory or several (one per CI shard); every
// index-*.jsonl found below it is read and its files resolve relative to it.
// Only counts and rule ids are printed, never artifact content.
import { createHash } from 'node:crypto';
import { readFile, readdir, writeFile } from 'node:fs/promises';
import { dirname, join, relative, resolve } from 'node:path';
import { deflateSync } from 'node:zlib';
import { expandZipDownload, validateDownloads, type DownloadedFile } from '../../backend/src/downloaded-artifact-validation.js';

interface IndexEntry { file: string; name: string; sha256: string; bytes: number; test: string; testKey: string; synthetic: string | null }

async function findIndexes(dir: string): Promise<string[]> {
  const entries = await readdir(dir, { recursive: true, withFileTypes: true });
  return entries.filter(e => e.isFile() && /^index-.*\.jsonl$/.test(e.name)).map(e => join(e.parentPath, e.name)).sort();
}

function option(args: string[], flag: string): string | undefined {
  const at = args.indexOf(flag);
  return at >= 0 ? args[at + 1] : undefined;
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const dir = args[0] && !args[0].startsWith('--') ? resolve(args[0]) : undefined;
  if (!dir) throw new Error('usage: validate-downloaded-artifacts.ts <dir> [--min-real-fragments N] [--min-real-confs N] [--ruby-payload <file>]');
  const minFragments = Number(option(args, '--min-real-fragments') ?? 0);
  const minConfs = Number(option(args, '--min-real-confs') ?? 0);
  const payloadPath = option(args, '--ruby-payload');

  const indexes = await findIndexes(dir);
  const files: DownloadedFile[] = [];
  const zipProblems: string[] = [];
  let zips = 0;
  for (const index of indexes) {
    const lines = (await readFile(index, 'utf8')).split('\n').filter(Boolean);
    for (const line of lines) {
      const entry = JSON.parse(line) as IndexEntry;
      const path = join(dirname(index), entry.file);
      const raw = await readFile(path);
      if (createHash('sha256').update(raw).digest('hex') !== entry.sha256) throw new Error('Download changed after recording: ' + relative(dir, path));
      const id = relative(dir, path);
      const testKey = relative(dir, dirname(index)) + '/' + entry.testKey;
      if (/\.zip$/i.test(entry.name)) {
        // A ZIP is validated as the user receives it: integrity first, then every
        // artifact inside is held to the same contract as a loose download.
        const expanded = expandZipDownload(raw);
        zipProblems.push(...expanded.problems.map(p => 'DOWNLOADED_ZIP_INTEGRITY ' + id + ' ' + p));
        zips += 1;
        for (const inner of expanded.entries) files.push({ id: id + '!/' + inner.name, testKey: testKey + '#' + id, name: inner.name, content: inner.content, synthetic: entry.synthetic });
      } else {
        files.push({ id, testKey, name: entry.name, content: raw.toString('utf8'), synthetic: entry.synthetic });
      }
    }
  }

  const report = validateDownloads(files);
  const problems: string[] = [...zipProblems, ...report.failures.map(f => 'DOWNLOADED_ARTIFACT_CONTRACT_VIOLATION ' + f.id + ' ' + f.rules.join(','))];
  if (report.real.fragments < minFragments) problems.push('TOO_FEW_REAL_FRAGMENTS ' + report.real.fragments + '<' + minFragments);
  if (report.real.confs < minConfs) problems.push('TOO_FEW_REAL_CONFS ' + report.real.confs + '<' + minConfs);

  if (payloadPath) {
    const seen = new Set<string>();
    const variants = files.filter(f => f.synthetic === null && /^customized_[A-Za-z0-9_]+$/.test(f.name)).flatMap(f => {
      const sha256 = createHash('sha256').update(Buffer.from(f.content, 'utf8')).digest('hex');
      if (seen.has(sha256)) return [];
      seen.add(sha256);
      return [{ id: 'download:' + f.name + ':' + sha256.slice(0, 12), sha256, compressedRuby: deflateSync(Buffer.from(f.content, 'utf8')).toString('base64') }];
    });
    const input = JSON.stringify({ contract: 'parser-studio.variant-matrix.v1', count: variants.length, variants });
    await writeFile(payloadPath, deflateSync(Buffer.from(input, 'utf8')).toString('base64') + '\n', { mode: 0o600 });
  }

  process.stdout.write(JSON.stringify({
    contract: 'parser-studio.downloaded-artifact-report.v1',
    indexes: indexes.length, zipsExpanded: zips, ...report,
    failures: report.failures.map(f => ({ id: f.id, name: f.name, rules: f.rules })),
    verdict: problems.length ? 'FAIL' : 'PASS',
    note: 'Structure contract and offline Ruby checks only; not a Stellar Cyber import, Syslog or indexing result.',
  }, null, 2) + '\n');
  if (problems.length) { process.stderr.write(problems.join('\n') + '\n'); process.exit(1); }
}

main().catch(error => { process.stderr.write(String(error instanceof Error ? error.message : error) + '\n'); process.exit(2); });
