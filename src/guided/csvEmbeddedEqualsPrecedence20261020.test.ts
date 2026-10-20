import {describe,it,expect} from 'vitest';
import {tokenizeCSV} from '../parser';
import {analyzeLogEnvelopes} from './autoParserEnvelope';

const csvWithEmbeddedEquals:[string,','|';'|'\t'][]=[
  ['allow,gw01,https://example.test/log?request_id=42&result=ok',','],
  ['gw01;허용;https://example.test/path?q=사용자&action=allow',';'],
  ['host\tallow\thttps://example.test/?user=sample&status=ok','\t'],
  ['node,"https://example.test/?q=a,b&result=ok",allow',','],
];

describe('CSV/KV grammar precedence for embedded equals in positional CSV',()=>{
  it.each(csvWithEmbeddedEquals)('recognizes lexically valid CSV with URL query equals: %s',(source,delimiter)=>{
    expect(tokenizeCSV(source,delimiter)).toHaveLength(3);
    const report=analyzeLogEnvelopes(source,'single-line');
    expect(report).toMatchObject({sourceCount:1,accounted:1,unsupported:0,complete:true});
    expect(report.events[0]).toMatchObject({body:'csv',status:'RECOGNIZED'});
  });
  it('preserves genuine KV precedence even if an unquoted value contains commas',()=>{
    expect(analyzeLogEnvelopes('action=allow note=a,b,c','single-line').events[0])
      .toMatchObject({body:'kv',status:'RECOGNIZED'});
  });
  it('does not promote malformed apparent KV with comma-delimited residue as valid CSV',()=>{
    const report=analyzeLogEnvelopes('action=allow bogus token,second,third','single-line');
    expect(report).toMatchObject({unsupported:1});
    expect(report.events[0]).toMatchObject({body:'kv',status:'BODY_MALFORMED'});
  });
  it('does not promote malformed CSV quotes with embedded URL equals',()=>{
    const report=analyzeLogEnvelopes('node,allow,https://example.test/?q=x"broken','single-line');
    expect(report.events[0]?.status).not.toBe('RECOGNIZED');
    expect(report.unsupported).toBe(1);
  });
});
