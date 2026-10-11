import type { ParserDraft } from './model';

const STORAGE_KEY = 'xdr-parser-studio:revisions:v1';
export const MAX_REVISIONS = 30;

export interface SavedRevision {
  id: string;
  createdAt: string;
  draft: ParserDraft;
  origin: 'browser-local';
  compatibility: 'not-verified';
}

export function readRevisions(): SavedRevision[] {
  try {
    const parsed: unknown = JSON.parse(localStorage.getItem(STORAGE_KEY) ?? '[]');
    if (!Array.isArray(parsed)) return [];
    return parsed.filter((value): value is SavedRevision =>
      !!value && typeof value.id === 'string' &&
      typeof value.createdAt === 'string' &&
      value.origin === 'browser-local' &&
      value.draft && typeof value.draft.name === 'string' &&
      Array.isArray(value.draft.mappings),
    );
  } catch {
    return [];
  }
}

export function saveRevision(draft: ParserDraft): SavedRevision {
  // The caller provides only rule configuration. Raw customer logs are never persisted.
  const revision: SavedRevision = {
    id: crypto.randomUUID(),
    createdAt: new Date().toISOString(),
    draft: structuredClone(draft),
    origin: 'browser-local',
    compatibility: 'not-verified',
  };
  const revisions = [revision, ...readRevisions()].slice(0, MAX_REVISIONS);
  localStorage.setItem(STORAGE_KEY, JSON.stringify(revisions));
  return revision;
}

export function exportPortableDraft(draft: ParserDraft): string {
  return JSON.stringify({
    schema_revision: 'draft-preview-v0.1',
    product: 'XDR Labs Parser Studio',
    exported_at: new Date().toISOString(),
    parser: structuredClone(draft),
    sample_logs_included: false,
    compatibility: {
      engine: 'browser-preview',
      fluentd: 'not-verified',
      stellar_cyber: 'pending-evidence',
    },
  }, null, 2);
}
