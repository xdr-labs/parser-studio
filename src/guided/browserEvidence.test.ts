import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { webcrypto } from 'node:crypto';
import { createDraft } from '../model';
import { preview } from '../parser';
import { createBrowserEvidence } from './browserEvidence';

const sample = [
  '{"action":"allow","src_ip":"198.51.100.44","dst_port":443}',
  '{"action":"deny","src_ip":"TOP_SECRET_IP_VALUE","dst_port":22}',
].join('\n');

describe('explicit downloadable browser-only test evidence, with no source log bodies', () => {
  beforeEach(() => vi.stubGlobal('crypto', webcrypto));
  afterEach(() => vi.unstubAllGlobals());

  it('creates deterministic SHA-256 bound JSON report with only status/known codes, never raw customer content', async () => {
    const draft = createDraft(); draft.format = 'json';
    const suite = preview(sample, draft);
    const result = await createBrowserEvidence({sample, draft, suite});
    expect(result).toMatchObject({
      reportSchema: 'parser-studio.browser-test-evidence.v0.1',
      engine:'browser-preview',
      compatibility: {nativeFluentdVerified:false,stellarTargetVerified:false},
      privacy:{rawLogsIncluded:false,normalizedValuesIncluded:false,diagnosticMessagesIncluded:false},
      counts:{total:2,matched:2,extracted:2,normalized:1,failures:1},
    });
    expect(result.source.sampleSha256).toMatch(/^[a-f0-9]{64}$/);
    expect(result.source.draftSha256).toMatch(/^[a-f0-9]{64}$/);
    expect(result.events).toHaveLength(2);
    expect(Object.keys(result.events[0]).sort()).toEqual(['detectedFormat','diagnostics','effectiveFormat','extracted','line','matched','normalized','number','status']);
    expect(result.events[1]).toMatchObject({status:'fail',diagnostics:[{code:'TYPE_ERROR',stage:'normalize',severity:'error'}]});
    const text = JSON.stringify(result);
    for (const secret of ['198.51.100.44','TOP_SECRET_IP_VALUE','"raw"', 'deny', 'allow']) {
      expect(text).not.toContain(secret);
    }
    expect(await createBrowserEvidence({sample, draft, suite})).toEqual(result);
  });

  it('does not include arbitrary diagnostic messages/codes or event IDs as possible raw-value side channels',async()=>{
    const draft=createDraft();draft.format='json';
    const suite=preview(sample,draft);
    suite.events[0].diagnostics.push({
      stage:'validate',severity:'warning',code:'LEAK_CUSTOMER_VALUE',message:'secret-account-number-123',
    });
    suite.events[0].id='secret-event-value';
    const result=await createBrowserEvidence({sample,draft,suite});
    const text=JSON.stringify(result);
    expect(text).not.toContain('LEAK_CUSTOMER_VALUE');
    expect(text).not.toContain('secret-account');
    expect(text).not.toContain('secret-event');
    expect(result.events[0].diagnostics).toContainEqual({
      code:'UNSPECIFIED',stage:'validate',severity:'warning',
    });
  });

  it('recomputes provenance if the fixture or edited draft changes', async()=>{
    const draft=createDraft();draft.format='json';
    const one=await createBrowserEvidence({sample,draft,suite:preview(sample,draft)});
    const newSample=sample.replace('198.51.100.44','198.51.100.45');
    const two=await createBrowserEvidence({sample:newSample,draft,suite:preview(newSample,draft)});
    expect(one.source.sampleSha256).not.toBe(two.source.sampleSha256);
    const newDraft={...draft,name:'Altered synthetic demo'};
    const three=await createBrowserEvidence({sample,draft:newDraft,suite:preview(sample,newDraft)});
    expect(one.source.draftSha256).not.toBe(three.source.draftSha256);
  });

  it('rejects empty, oversized, contradictory or non-browser suite evidence', async()=>{
    const draft=createDraft();draft.format='json';
    const suite=preview(sample,draft);
    await expect(createBrowserEvidence({sample:'',draft,suite})).rejects.toThrow();
    await expect(createBrowserEvidence({sample:'x'.repeat(65537),draft,suite})).rejects.toThrow();
    const malformed=structuredClone(suite);
    malformed.counts.total=999;
    await expect(createBrowserEvidence({sample,draft,suite:malformed})).rejects.toThrow();
    const impostor={...suite,engine:'native-fluentd'} as unknown as typeof suite;
    await expect(createBrowserEvidence({sample,draft,suite:impostor})).rejects.toThrow();
  });

  it('fails closed if browser WebCrypto SHA-256 is not accessible', async()=>{
    vi.stubGlobal('crypto', null);
    const draft=createDraft();draft.format='json';
    await expect(createBrowserEvidence({sample,draft,suite:preview(sample,draft)})).rejects.toThrow(/SHA-256|secure/i);
  });
});
