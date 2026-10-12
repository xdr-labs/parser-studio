import { describe, expect, it } from 'vitest';
import { createDraft } from '../model';
import { preview } from '../parser';
import { mappingCoverage } from './mappingCoverage';

describe('privacy-safe per-field mapping coverage for browser-only sample preview', () => {
  it('separates source-absent, type-error and successfully normalized event counts', () => {
    const draft = createDraft(); draft.format = 'json';
    const events = [
      '{"action":"allow","src_ip":"198.51.100.10","dst_port":443}',
      '{"action":"deny","src_ip":"invalid-ip","dst_port":22}',
      '{"action":"allow","dst_port":80}',
    ].join('\n');
    const coverage = mappingCoverage(preview(events, draft), draft.mappings[0]);
    expect(coverage).toEqual({
      total: 3, sourcePresent: 2, normalized: 1,
      missing: 1, typeFailures: 1, firstProblemEventId: 'event-2',
    });
  });

  it('counts dotted nested JSON fields without revealing raw sample values', () => {
    const draft = createDraft(); draft.format = 'json';
    const field = {id:'nested',source:'http.request.method',target:'custom.method',type:'string' as const};
    draft.mappings.push(field);
    const data = [
      '{"src_ip":"198.51.100.10","dst_port":443,"action":"allow","http":{"request":{"method":"GET"}}}',
      '{"src_ip":"198.51.100.11","dst_port":443,"action":"deny","http":{"request":{}}}',
    ].join('\n');
    const result = mappingCoverage(preview(data, draft), field);
    expect(result).toMatchObject({ total:2, sourcePresent:1, normalized:1, missing:1, typeFailures:0 });
    expect(JSON.stringify(result)).not.toContain('198.51.100.10');
    expect(JSON.stringify(result)).not.toContain('GET');
  });

  it('returns no false pass or failing event when there are no sample results', () => {
    const draft = createDraft();
    expect(mappingCoverage(undefined, draft.mappings[0])).toEqual({
      total:0,sourcePresent:0,normalized:0,missing:0,typeFailures:0,firstProblemEventId:null,
    });
  });
});
