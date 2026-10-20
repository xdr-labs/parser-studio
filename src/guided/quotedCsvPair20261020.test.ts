import {describe,it,expect} from 'vitest';
import {tokenizeCSV} from '../parser';
import {analyzeLogEnvelopes,assessEnvelopeCompilation} from './autoParserEnvelope';
import type {BackendCapabilities} from './backendCapabilities';

const cap={authoring:{extractionFormats:['csv','kv','json']},
  verification:{engineVerified:false,targetImportVerified:false}} as unknown as BackendCapabilities;

describe('strictly quoted two-column CSV source recognition is review-only',()=>{
  it.each([
    ['comma','"allow","198.51.100.10"',','],
    ['semicolon','"허용";"김민수"',';'],
    ['tab','"deny"\t"203.0.113.9"','\t'],
    ['double-quote escape','"allow ""rule""","demo=1"',','],
    ['embedded delimiter','"hello,there","allow"',','],
  ])('recognizes two strongly quoted %s CSV fields with no inferred names',(_,source,delimiter)=>{
    expect(tokenizeCSV(source,delimiter)).toHaveLength(2);
    const report=analyzeLogEnvelopes(source,'single-line');
    expect(report).toMatchObject({sourceCount:1,accounted:1,unsupported:0,complete:true});
    expect(report.events[0]).toMatchObject({body:'csv',status:'RECOGNIZED'});
    expect(assessEnvelopeCompilation(report,cap).status).toBe('COLUMNS_REQUIRED');
  });
  it('keeps ambiguous unquoted two-column text as review-only unsupported',()=>{
    const report=analyzeLogEnvelopes('allow,198.51.100.10','single-line');
    expect(report.unsupported).toBe(1);
    expect(report.events[0]?.status).not.toBe('RECOGNIZED');
  });
  it.each([
    '"hello"garbage,"allow"',
    '"hello","allow"garbage',
    '"hello,"allow"',
    '"hello","unterminated',
  ])('never promotes malformed quoted pairs: %s',source=>{
    const report=analyzeLogEnvelopes(source,'single-line');
    expect(report.unsupported).toBe(1);
    expect(report.events[0]?.status).not.toBe('RECOGNIZED');
  });
});
