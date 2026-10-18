import type { FieldProposal } from '../pattern';

export interface HighlightedCandidate {
  status: 'matched' | 'unmatched' | 'not-checked';
  start: number;
  end: number;
  fieldValue?: string;
}

export interface EventPreviewHighlight extends HighlightedCandidate {
  id: string;
  line: number;
  raw: string;
}

export interface HighlightSummary {
  rows: EventPreviewHighlight[];
  sampled: number;
  total: number;
  matches: number;
  omitted: number;
}

/**
 * Bounded, browser-only highlight for the structural starter expression returned by
 * createFieldProposal. The caller must NOT pass arbitrary user-supplied regex source.
 * The capture range is identified using ES2022 /d indices, never string search.
 */
export function locateCandidateCapture(raw: string, proposal: FieldProposal): HighlightedCandidate {
  if (raw.length > 4096 || proposal.pattern.length > 256 ||
      !/^[A-Za-z_][A-Za-z0-9_]{0,63}$/.test(proposal.field)) {
    return { status: 'not-checked', start: -1, end: -1 };
  }
  try {
    const expression = new RegExp(proposal.pattern, 'd');
    const result = expression.exec(raw);
    const indices = result?.indices?.groups?.[proposal.field];
    if (!indices || indices.length !== 2 || indices[0] < 0 || indices[1] <= indices[0]) {
      return { status: 'unmatched', start: -1, end: -1 };
    }
    return { status: 'matched', start: indices[0], end: indices[1], fieldValue: raw.slice(indices[0], indices[1]) };
  } catch {
    return { status: 'not-checked', start: -1, end: -1 };
  }
}

export function highlightPreview(
  events: readonly { id: string; line: number; raw: string }[],
  proposal: FieldProposal,
  limit = 20,
): HighlightSummary {
  const limited = events.slice(0, Math.min(Math.max(0, Math.floor(limit)), 20));
  const rows = limited.map((ev) => ({ ...ev, ...locateCandidateCapture(ev.raw, proposal) }));
  return {
    rows, sampled: rows.length, total: events.length,
    matches: rows.filter((x) => x.status === 'matched').length,
    omitted: events.length - rows.length,
  };
}

/**
 * Show just enough context around each match to help the user distinguish variants.
 * No raw sample is persisted or sent over a network by this helper.
 */
export function matchContext(
  row: Pick<EventPreviewHighlight, 'raw' | 'start' | 'end' | 'status'>,
  radius = 44,
): { before: string; selected: string; after: string } {
  if (row.status !== 'matched' || row.start < 0 || row.end <= row.start) {
    return { before: row.raw.slice(0, radius * 2) + (row.raw.length > radius * 2 ? '…' : ''), selected: '', after: '' };
  }
  const left = Math.max(0, row.start - radius);
  const right = Math.min(row.raw.length, row.end + radius);
  return {
    before: (left ? '…' : '') + row.raw.slice(left, row.start),
    selected: row.raw.slice(row.start, row.end),
    after: row.raw.slice(row.end, right) + (right < row.raw.length ? '…' : ''),
  };
}
