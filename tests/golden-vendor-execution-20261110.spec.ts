// Golden vendor log -> browser parsing -> Stellar mapping -> downloaded Ruby execution.
//
// For every publisher-documented case in the corpus, three independent sources
// must agree on the same documented field values:
//   1. the vendor's own documentation example (corpus `goldenSourceValues`),
//   2. the Stellar output the browser previews after mapping,
//   3. the event the actually downloaded Ruby Fragment emits for the raw log
//      (executed offline on Ruby, loaded the way the shipped wrapper loads it).
// Fields listed in the case's `desiredFields` are required to be mapped and to
// round-trip exactly; any gap fails with the field named.
//
// Scope: Parser Studio output only. This is not a Stellar Cyber import, Syslog
// reception or indexing result.
import { test, expect } from './support/downloadSink';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { compareEventToGolden, type MappingRow } from '../backend/src/golden-event-comparison';

interface Golden { sourcePath: string; sourceValue: unknown }
interface VendorCase {
  id: string; sampleClass: string; rawSample: string; desiredFields: string;
  publisher: string; product: string; goldenSourceValues: Golden[];
}
const loadCases = (path: string) => (JSON.parse(readFileSync(resolve(path), 'utf8')) as { cases: VendorCase[] }).cases;
// Publisher-documented examples only. PROJECT_SYNTHETIC cases are never counted here.
const vendorCases = [
  ...loadCases('evals/chatgpt/security-cases.json'),
  ...loadCases('evals/golden-corpus/vendor-documented-additional.v1.json'),
].filter(item => item.sampleClass.startsWith('VENDOR_DOCUMENTED'));
const RUNNER = resolve('scripts/verification/ruby-golden-event-runner.rb');

const isObject = (value: unknown): value is Record<string, unknown> =>
  value !== null && typeof value === 'object' && !Array.isArray(value);

for (const vendorCase of vendorCases) {
  test('golden vendor log executes to the documented values · ' + vendorCase.id, async ({ page }) => {
    test.skip(!process.env.PARSER_STUDIO_BROWSER_BACKEND,
      'Needs the real compile backend; the exact-head browser shards provide it.');
    const required = vendorCase.desiredFields.split(',').map(item => item.trim()).filter(Boolean);
    expect(vendorCase.goldenSourceValues.length).toBeGreaterThan(0);

    await page.goto('/');
    await page.getByLabel('Auto Parser raw logs').fill(vendorCase.rawSample);
    // The generated namespace accepts letters, digits, space and . _ & ( ) - only.
    await page.getByLabel('Parser manufacturer').fill(vendorCase.publisher.replace(/[^A-Za-z0-9 ._&()-]+/g, ' ').trim());
    await page.getByLabel('Parser product', { exact: true }).fill(vendorCase.product);
    await expect(page.getByLabel('Automatic event accounting')).toContainText('1/1 events analyzed locally');
    await page.getByRole('button', { name: 'Analyze Logs', exact: true }).click();
    await expect(page.getByLabel('Beginner analysis summary'))
      .toContainText('1 of 1 log event structurally parsed', { timeout: 20_000 });
    const review = page.getByRole('button', { name: 'Review Fields', exact: true });
    await expect(review).toBeEnabled();
    await review.click();
    await page.getByLabel('Review Fields stage').getByRole('button', { name: 'Map Fields' }).click();
    const map = page.getByLabel('Map Fields stage');
    await expect(map).toBeVisible();

    // Stage 2: what the browser shows will be emitted, and where.
    const previews = map.locator('.normalization-full-preview pre');
    const normalized = JSON.parse((await previews.nth(2).textContent()) ?? '{}') as unknown;
    expect(isObject(normalized), vendorCase.id + ': Stellar output preview is not an object').toBe(true);
    const pairs = await map.locator('.normalization-diff-list > div').evaluateAll(nodes =>
      nodes.map(node => {
        const strong = node.querySelectorAll('strong');
        return { source: strong[0]?.textContent ?? '', target: strong[1]?.textContent ?? '' };
      }));
    expect(pairs.length, vendorCase.id + ': no field mappings shown').toBeGreaterThan(0);
    const rows: MappingRow[] = pairs.map(pair => ({
      ...pair,
      vendorNamespace: !Object.prototype.hasOwnProperty.call(normalized as object, pair.target),
    }));
    const browserStage = compareEventToGolden({
      golden: vendorCase.goldenSourceValues, rows, required,
      events: [{ time: null, record: normalized }],
    });
    expect(browserStage.problems, vendorCase.id + ' browser Stellar preview vs documented values').toEqual([]);

    // Stage 3: the Ruby the user would actually download, executed on the raw log.
    await map.getByRole('button', { name: 'Create Parser' }).click();
    await expect(page.getByLabel('Create Parser stage')).toBeVisible();
    await page.getByRole('button', { name: 'Create Parser Files' }).click();
    const files = page.getByLabel('Generated parser files');
    await expect(files).toContainText('Parser files created successfully', { timeout: 20_000 });
    const downloadPromise = page.waitForEvent('download');
    await files.getByRole('button', { name: /customized_[a-z0-9_]+$/ }).click();
    const download = await downloadPromise;
    const ruby = readFileSync((await download.path())!, 'utf8');
    expect(ruby.length).toBeGreaterThan(0);

    // Hand the exact downloaded Ruby, the raw log and the browser's mapping rows
    // to the aggregate gate (scripts/verification/ruby-golden-container-gate.sh),
    // which executes it again on the pinned Ruby 2.4.9 target image. Documented
    // values are NOT stored here: the gate reads them from the corpus itself.
    const bundleRoot = process.env.PARSER_STUDIO_E2E_ARTIFACT_DIR;
    if (bundleRoot) {
      mkdirSync(join(bundleRoot, 'golden-bundles'), { recursive: true });
      writeFileSync(join(bundleRoot, 'golden-bundles', vendorCase.id + '.json'), JSON.stringify({
        contract: 'parser-studio.golden-bundle.v1', id: vendorCase.id, raw: vendorCase.rawSample, ruby,
        rubySha256: createHash('sha256').update(ruby, 'utf8').digest('hex'), rows, required,
      }));
    }

    const run = spawnSync(process.env.PARSER_RUBY_BIN || 'ruby', [RUNNER], {
      input: JSON.stringify({ cases: [{ id: vendorCase.id, ruby, raw: vendorCase.rawSample }] }),
      encoding: 'utf8', timeout: 60_000, maxBuffer: 4 * 1024 * 1024,
    });
    expect(run.status, vendorCase.id + ' ruby runner: ' + String(run.stderr).slice(0, 300)).toBe(0);
    const out = JSON.parse(run.stdout) as { ruby: string; results: Record<string, { calls: [unknown, unknown][] }> };
    const calls = out.results[vendorCase.id]!.calls;
    const rubyStage = compareEventToGolden({
      golden: vendorCase.goldenSourceValues, rows, required,
      events: calls.map(([time, record]) => ({ time, record })),
    });
    expect(rubyStage.problems, vendorCase.id + ' downloaded Ruby event (ruby ' + out.ruby + ') vs documented values').toEqual([]);
    expect(rubyStage.matched.length).toBe(required.length);
  });
}

test('a manufacturer name with an unsupported character explains the one thing to change', async ({ page }) => {
  const suricata = vendorCases.find(item => item.id === 'suricata_eve_alert')!;
  await page.goto('/');
  await page.getByLabel('Auto Parser raw logs').fill(suricata.rawSample);
  await page.getByLabel('Parser manufacturer').fill('OISF/Suricata');
  await page.getByLabel('Parser product', { exact: true }).fill('Suricata EVE JSON');
  await page.getByRole('button', { name: 'Analyze Logs', exact: true }).click();
  const review = page.getByRole('button', { name: 'Review Fields', exact: true });
  await expect(page.getByLabel('Beginner analysis summary')).toContainText('structurally parsed', { timeout: 20_000 });
  await expect(review).toBeEnabled();
  await review.click();
  const alert = page.getByRole('alert', { name: 'Parser draft not ready' });
  await expect(alert).toContainText('manufacturer name can only use letters, digits, spaces');
  await expect(alert).not.toContainText('repeated occurrences');
  await page.getByLabel('Parser manufacturer').fill('OISF Suricata');
  await expect(review).toBeEnabled();
});
