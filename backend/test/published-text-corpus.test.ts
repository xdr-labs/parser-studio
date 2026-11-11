// Samples whose page bytes could not be hashed must never be counted as
// VENDOR_DOCUMENTED. This test keeps that line honest for the published-text corpus
// and re-checks the assembled sample against the verbatim printed fragments.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync, readdirSync } from 'node:fs';
import { resolve } from 'node:path';
import test from 'node:test';

const root = resolve(import.meta.dirname, '../..');
const dir = resolve(root, 'evals/golden-corpus');
const files = readdirSync(dir).filter(name => /^vendor-published-text-.*\.json$/.test(name));

interface PublishedCase {
  id: string; sampleClass: string; rawSample: string; originalSha256: string; provenanceUrl: string;
  expectedMatch: boolean; expectedFields: Record<string, string>; expectedStellarFields: Record<string, string>;
  provenance: { pageSha256: string | null; pageBytesCaptured: boolean; blocker?: string; extraction: string;
    publishedFragments: string[]; retrievedAt: string };
}

test('published-text corpus is registered nowhere as VENDOR_DOCUMENTED and states why', () => {
  assert.ok(files.length >= 1, 'expected the Cisco ASA published-text corpus');
  const registry = readFileSync(resolve(dir, 'corpus-files.v1.json'), 'utf8');
  const ids = new Set<string>();
  for (const file of files) {
    assert.ok(!registry.includes(file), file + ' must not be in the VENDOR_DOCUMENTED registry');
    const doc = JSON.parse(readFileSync(resolve(dir, file), 'utf8')) as { sourcePolicy: string; cases: PublishedCase[] };
    assert.equal(doc.sourcePolicy, 'VENDOR_PUBLISHED_TEXT_NO_PAGE_BYTES');
    for (const item of doc.cases) {
      assert.ok(!ids.has(item.id), 'duplicate id ' + item.id);
      ids.add(item.id);
      assert.equal(item.sampleClass, 'VENDOR_PUBLISHED_TEXT');
      assert.match(item.provenanceUrl, /^https:\/\/www\.cisco\.com\//);
      // No raw page bytes: the hash is absent and the blocker is recorded, never invented.
      assert.equal(item.provenance.pageBytesCaptured, false);
      assert.equal(item.provenance.pageSha256, null);
      assert.ok((item.provenance.blocker ?? '').length > 20, item.id + ' records no blocker');
      assert.equal(item.provenance.extraction, 'published-line-wrap-joined-with-single-space');
      assert.equal(item.provenance.publishedFragments.join(' '), item.rawSample, item.id);
      assert.equal(createHash('sha256').update(item.rawSample).digest('hex'), item.originalSha256, item.id);
      if (item.expectedMatch) {
        assert.ok(Object.keys(item.expectedFields).length >= 8, item.id + ' expects too few fields');
        assert.ok(Object.keys(item.expectedStellarFields).length >= 3, item.id);
      } else {
        assert.deepEqual(item.expectedFields, {});
      }
    }
  }
});
