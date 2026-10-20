import {describe,it,expect} from 'vitest';
import {tokenizeCSV} from '../parser';
import {analyzeLogEnvelopes,assessEnvelopeCompilation} from './autoParserEnvelope';
import type {BackendCapabilities} from './backendCapabilities';

const cap={
  authoring:{extractionFormats:['csv','kv','json']},
  verification:{engineVerified:false,targetImportVerified:false},
} as unknown as BackendCapabilities;

describe('strict CSV envelope candidates reuse the verified browser/native-compatible CSV lexer',()=>{
  it.each([
    ['unexpected quote inside unquoted cell','left"middle",right,third',','],
    ['nonblank byte after closing quote','"first"garbage,second,third',','],
    ['unquoted tail after closing field quote','first,second,"third"garbage',','],
    ['invalid semicolon-quoted tail','first;second;"third"garbage',';'],
    ['invalid TAB-quoted tail','first\tsecond\t"third"garbage','\t'],
  ])('does not promote %s into a structurally recognized CSV candidate',(_name,source,delimiter)=>{
    expect(tokenizeCSV(source,delimiter)).toBeNull();
    const ledger=analyzeLogEnvelopes(source,'single-line');
    expect(ledger).toMatchObject({sourceCount:1,accounted:1,complete:true,unsupported:1});
    expect(ledger.events[0]).toMatchObject({
      envelope:'none',body:'csv',status:'BODY_MALFORMED',
    });
    expect(assessEnvelopeCompilation(ledger,cap).status).not.toBe('DRAFT_COMPILABLE');
  });

  it.each([
    ['quoted comma and equals in URL','"https://example.test/?key=a,b&value=c","ok","node" ',','],
    ['RFC4180 doubled quote','"quoted ""text""","allowed","node"',','],
    ['semicolon escaped quote','"quoted;cell";"second";"third"',';'],
    ['TAB quoted cell','"first\tpart"\t"second"\t"third"','\t'],
    ['unquoted three cells','alpha,beta,gamma',','],
  ])('preserves valid %s without losing a field',(_name,source,delimiter)=>{
    const parsed=tokenizeCSV(source,delimiter);
    expect(parsed).not.toBeNull();
    expect(parsed).toHaveLength(3);
    const report=analyzeLogEnvelopes(source,'single-line');
    expect(report.events[0]).toMatchObject({
      envelope:'none',body:'csv',status:'RECOGNIZED',
    });
    expect(assessEnvelopeCompilation(report,cap).status).toBe('COLUMNS_REQUIRED');
  });

  it('continues prioritizing key=value source over incidental commas',()=>{
    const source='action=allow note=a,b,c';
    const report=analyzeLogEnvelopes(source,'single-line');
    expect(report.events[0]).toMatchObject({body:'kv',status:'RECOGNIZED'});
  });
});
