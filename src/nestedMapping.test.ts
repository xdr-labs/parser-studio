import { describe, expect, it } from 'vitest';
import { createDraft } from './model';
import { preview } from './parser';
import { toBackendProject } from './guided/backendAdapter';

function withMethod() {
  const draft = createDraft();
  draft.format = 'json';
  draft.mappings.push({ id: 'httpmethod', source: 'http.request.method', target: 'custom.http_method', type: 'string' });
  draft.guided={...draft.guided!,groups:{...draft.guided!.groups,httpmethod:'top_fields'}};
  return draft;
}

describe('browser nested JSON field mapping parity with backend dotted lookup', () => {
  it('maps a safe nested field without copying any raw event into backend project', () => {
    const draft = withMethod();
    const sample = '{"action":"allow","src_ip":"198.51.100.21","dst_port":443,"http":{"request":{"method":"GET"}}}';
    const result = preview(sample, draft);
    expect(result.counts).toMatchObject({ total: 1, matched: 1, normalized: 1, failures: 0 });
    expect((result.events[0].normalized.custom as Record<string,unknown>).http_method).toBe('GET');
    const project = toBackendProject(draft);
    expect(project.ok).toBe(true);
    if (project.ok) expect(JSON.stringify(project.project)).not.toContain('198.51.100.21');
  });

  it('rejects conflicting dotted and nested interpretations instead of choosing a wrong source value', () => {
    const draft = withMethod();
    const sample = JSON.stringify({
      action:'allow',src_ip:'198.51.100.22',dst_port:443,
      'http.request.method':'FLAT', http:{request:{method:'NESTED'}},
    });
    const result=preview(sample,draft);
    expect((result.events[0].normalized.custom as Record<string,unknown>|undefined)?.http_method).toBeUndefined();
    expect(result.events[0].diagnostics).toEqual(expect.arrayContaining([
      expect.objectContaining({code:'AMBIGUOUS_SOURCE_PATH',severity:'error'}),
    ]));
  });

  it('rejects traversal of prototype keys and array-index paths', () => {
    const draft = withMethod();
    draft.mappings.push({id:'unsafe', source:'http.__proto__.polluted', target:'custom.unsafe',type:'string'});
    draft.mappings.push({id:'index', source:'sessions.0.token', target:'custom.token',type:'string'});
    const sample = JSON.stringify({
      action:'allow',src_ip:'198.51.100.22',dst_port:443,
      http:{request:{method:'POST'}}, sessions:[{token:'secret'}],
    });
    const result = preview(sample, draft);
    expect(Object.prototype.hasOwnProperty.call(result.events[0].normalized, 'custom.unsafe')).toBe(false);
    expect(Object.prototype.hasOwnProperty.call(result.events[0].normalized, 'custom.token')).toBe(false);
    expect(result.events[0].diagnostics.some(x => x.code === 'SOURCE_NOT_FOUND')).toBe(true);
  });
});
