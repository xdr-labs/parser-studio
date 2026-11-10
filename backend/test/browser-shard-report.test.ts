import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
// @ts-expect-error plain ESM verifier used by the browser CI job
import { validateBrowserShardReport } from '../../scripts/verification/browser-shard-report.mjs';

const valid = { stats: { expected: 12, unexpected: 0, flaky: 0 }, errors: [] };

test('Playwright JSON reporter evidence is parsed from a dedicated file, never polluted stdout', () => {
  assert.equal(validateBrowserShardReport(JSON.stringify(valid)).expected, 12);
  assert.throws(() => validateBrowserShardReport('GitCommitInfo\n' + JSON.stringify(valid)), SyntaxError);
  assert.throws(() => validateBrowserShardReport(''));
  const workflow = readFileSync(new URL('../../.github/workflows/quality.yml', import.meta.url), 'utf8');
  assert.match(workflow, /PLAYWRIGHT_JSON_OUTPUT_FILE/);
  assert.doesNotMatch(workflow, /--reporter=json\s*>/);
  // Every JSON-reporter invocation must have an independent output target,
  // including the long web-quality browser suites, not only the six shards.
  const lines = workflow.split('\n');
  const jsonRuns = lines.map((line, i) => ({ line, i })).filter(({ line }) => line.includes('npx playwright test') && line.includes('--reporter=json'));
  assert.ok(jsonRuns.length >= 11, 'unexpectedly small Playwright JSON command inventory');
  for (const { i } of jsonRuns)
    assert.match(lines.slice(Math.max(0, i - 3), i + 1).join(' '), /PLAYWRIGHT_JSON_OUTPUT_FILE=/, 'JSON report not isolated at workflow line ' + (i + 1));
});

test('Playwright JSON release gate rejects empty, failed, flaky or invalid evidence', () => {
  for (const report of [
    { ...valid, stats: { ...valid.stats, expected: 0 } },
    { ...valid, stats: { ...valid.stats, unexpected: 1 } },
    { ...valid, stats: { ...valid.stats, flaky: 1 } },
    { ...valid, errors: ['failure'] },
    { stats: { expected: 1, unexpected: 0, flaky: 0 }, errors: null },
    { errors: [] },
    null,
    [],
  ]) assert.throws(() => validateBrowserShardReport(JSON.stringify(report)));
});
