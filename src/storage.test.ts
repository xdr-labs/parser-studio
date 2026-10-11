import { beforeEach, describe, expect, it } from 'vitest';
import { createDraft } from './model';
import { exportPortableDraft, readRevisions, saveRevision } from './storage';

describe('private configuration-only browser draft history', () => {
  beforeEach(() => { localStorage.clear(); });

  it('retains ordered mappings but not raw sample logs', () => {
    const draft = createDraft();
    const record = saveRevision(draft);
    expect(readRevisions()[0].id).toBe(record.id);
    expect(readRevisions()[0].draft.mappings).toEqual(draft.mappings);
    expect(JSON.stringify(readRevisions())).not.toContain('DEMO-FW');
    expect(readRevisions()[0].compatibility).toBe('not-verified');
  });

  it('exports a portable unverified draft with no customer data', () => {
    const exported = JSON.parse(exportPortableDraft(createDraft()));
    expect(exported.schema_revision).toBe('draft-preview-v0.1');
    expect(exported.sample_logs_included).toBe(false);
    expect(exported.compatibility.stellar_cyber).toBe('pending-evidence');
  });

  it('survives corrupted browser storage without false revisions', () => {
    localStorage.setItem('xdr-parser-studio:revisions:v1', 'broken-json');
    expect(readRevisions()).toEqual([]);
  });
});
