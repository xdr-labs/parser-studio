// Shared Playwright test object that records every file the browser downloads,
// so CI can validate the exact Ruby Fragment and .conf a user would receive.
//
// Specs that download files must import `test` from this module instead of
// '@playwright/test' (scripts/verification/download-sink-guard.mjs enforces it).
// The sink only records; it never changes how a test downloads or asserts.
//
// Recording is active when PARSER_STUDIO_E2E_ARTIFACT_DIR is set (CI sets it in
// every browser shard). Local runs without the variable behave exactly like the
// stock Playwright test object.
//
// Specs whose backend responses are synthetic (route-mocked artifacts) must say
// so with test.use({ downloadSyntheticReason: '<why>' }); those files are kept
// apart and are reported, but never counted as validated product output.
import { test as base, type BrowserContext, type Download, type Page, type TestInfo } from '@playwright/test';
import { createHash } from 'node:crypto';
import { appendFile, copyFile, mkdir, readFile } from 'node:fs/promises';
import { join } from 'node:path';

export * from '@playwright/test';

export interface DownloadIndexEntry {
  readonly file: string;
  readonly name: string;
  readonly sha256: string;
  readonly bytes: number;
  readonly test: string;
  readonly testKey: string;
  readonly synthetic: string | null;
}

const safeSegment = (text: string) => text.replace(/[^A-Za-z0-9._-]+/g, '_').slice(0, 80) || 'x';
let sequence = 0;

export function attachDownloadSink(context: BrowserContext, testInfo: TestInfo, syntheticReason?: string): () => Promise<void> {
  const root = process.env.PARSER_STUDIO_E2E_ARTIFACT_DIR;
  if (!root) return async () => undefined;
  const pending: Promise<void>[] = [];
  const testKey = testInfo.workerIndex + '-' + testInfo.testId;

  const record = async (download: Download): Promise<void> => {
    const source = await download.path();
    if (!source) throw new Error('Download ' + download.suggestedFilename() + ' did not complete; it cannot be validated.');
    const name = download.suggestedFilename();
    const folder = join(syntheticReason ? 'synthetic' : 'real', safeSegment(testKey) + '-' + String(++sequence));
    await mkdir(join(root, folder), { recursive: true });
    const destination = join(root, folder, safeSegment(name));
    await copyFile(source, destination);
    const bytes = await readFile(destination);
    const entry: DownloadIndexEntry = {
      file: join(folder, safeSegment(name)),
      name,
      sha256: createHash('sha256').update(bytes).digest('hex'),
      bytes: bytes.length,
      test: testInfo.titlePath.join(' > '),
      testKey,
      synthetic: syntheticReason ?? null,
    };
    await appendFile(join(root, 'index-' + process.pid + '.jsonl'), JSON.stringify(entry) + '\n');
  };
  const watch = (page: Page) => { page.on('download', download => { pending.push(record(download)); }); };
  context.pages().forEach(watch);
  context.on('page', watch);

  return async () => {
    const results = await Promise.race([
      Promise.allSettled(pending),
      new Promise<null>(resolve => setTimeout(() => resolve(null), 15_000)),
    ]);
    if (results === null) throw new Error('Download sink timed out while recording downloads.');
    const failed = results.filter((r): r is PromiseRejectedResult => r.status === 'rejected');
    if (failed.length) throw new Error('Download sink failed: ' + failed.map(f => String(f.reason)).join('; '));
  };
}

export const test = base.extend<{ _downloadSink: void; downloadSyntheticReason: string | undefined }>({
  downloadSyntheticReason: [undefined, { option: true }],
  _downloadSink: [async ({ context, downloadSyntheticReason }, use, testInfo) => {
    const finish = attachDownloadSink(context, testInfo, downloadSyntheticReason);
    await use();
    await finish();
  }, { auto: true }],
});
