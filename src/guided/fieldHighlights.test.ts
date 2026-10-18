import { describe, expect, it } from 'vitest';
import { createFieldProposal } from '../pattern';
import { highlightPreview, locateCandidateCapture, matchContext } from './fieldHighlights';

function proposal(raw: string, value: string, field: string) {
  const p = createFieldProposal(raw, value, field);
  if ('error' in p) throw new Error(p.error);
  return p;
}

describe('privacy-safe sample field match highlighting', () => {
  it('locates the exact span for a JSON field without matching a same-named value elsewhere', () => {
    const p = proposal('{"src_ip":"198.51.100.4","device":"DEMO-FW"}', '198.51.100.4', 'source_ip');
    const event = '{"message":"198.51.100.4","src_ip":"203.0.113.5","device":"EXAMPLE"}';
    const capture = locateCandidateCapture(event, p);
    expect(capture.status).toBe('matched');
    expect(event.slice(capture.start, capture.end)).toBe('203.0.113.5');
    expect(p.pattern).not.toContain('198.51.100.4');
    expect(p.pattern).not.toContain('DEMO-FW');
  });

  it('finds a KV field with varied prefixes and discloses failed minority formats', () => {
    const p = proposal('src=10.0.0.1 status=ok', '10.0.0.1', 'source_ip');
    const rows = [
      { id: 'e1', line: 1, raw: 'src=203.0.113.8 action=allow' },
      { id: 'e2', line: 2, raw: '{"src":"10.0.0.2"}' },
      { id: 'e3', line: 3, raw: 'action=deny src=203.0.113.2' },
    ];
    const report = highlightPreview(rows, p);
    expect(report.total).toBe(3);
    expect(report.matches).toBe(2);
    expect(report.rows.map((row) => row.status)).toEqual(['matched', 'unmatched', 'matched']);
    expect(report.rows[0].fieldValue).toBe('203.0.113.8');
  });

  it('caps rendered rows to 20 and marks oversize samples as not checked', () => {
    const p = proposal('src=203.0.113.3', '203.0.113.3', 'src_ip');
    const all = Array.from({ length: 30 }, (_, i) => ({ id: 'event-' + i, line: i + 1, raw: 'src=10.0.0.' + i }));
    expect(highlightPreview(all, p)).toMatchObject({ sampled: 20, total: 30, omitted: 10 });
    expect(locateCandidateCapture('X'.repeat(4097), p).status).toBe('not-checked');
  });

  it('renders bounded context with highlight and never changes the underlying values', () => {
    const p = proposal('src=198.51.100.14 action=allow', '198.51.100.14', 'src_ip');
    const row = { raw: 'host=EXAMPLE src=203.0.113.13 action=deny', ...locateCandidateCapture('host=EXAMPLE src=203.0.113.13 action=deny', p) };
    expect(matchContext(row, 6)).toMatchObject({ selected: '203.0.113.13' });
    expect(matchContext(row, 6).before).toContain('src=');
    const without = matchContext({ raw: 'no matching field here', start: -1, end: -1, status: 'unmatched' });
    expect(without.selected).toBe('');
    expect(without.before).toContain('no matching');
  });

  it('rejects invalid or untrusted expressions before evaluating a capture', () => {
    const p = proposal('src=198.51.100.7', '198.51.100.7', 'safe');
    expect(locateCandidateCapture('src=x', { ...p, pattern: '(' }).status).toBe('not-checked');
    expect(locateCandidateCapture('src=x', { ...p, pattern: 'A'.repeat(257) }).status).toBe('not-checked');
    expect(locateCandidateCapture('src=x', { ...p, field: 'not a name' }).status).toBe('not-checked');
  });
});
