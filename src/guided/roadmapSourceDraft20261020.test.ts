import {describe,expect,it} from 'vitest';
import {createDraft} from '../model';
import {preview} from '../parser';
import {analyzeLogEnvelopes,assessEnvelopeCompilation} from './autoParserEnvelope';
import {prepareAutoParserDraft} from './autoParserDraft';
import type {BackendCapabilities} from './backendCapabilities';

const capabilities={
  authoring:{extractionFormats:['syslog_rfc5424'],rfc5424BodyFormats:['raw','json','kv','cef','leef']},
  verification:{engineVerified:false,targetImportVerified:false},
} as unknown as BackendCapabilities;
const header='<134>1 2026-10-19T09:15:22.123Z fw01 application 12 audit ';
const structured='[meta@12345 action="deny" src="192.0.2.10"]';

describe('roadmap strict Syslog source to DRAFT handoff',()=>{
  it('uses the existing raw MSG compiler without discarding structured-data bytes',()=>{
    const source=header+structured+' firewall denied';
    const draft=createDraft();
    const ledger=analyzeLogEnvelopes(source,'single-line');
    const compiler=assessEnvelopeCompilation(ledger,capabilities);
    expect(ledger.unsupported).toBe(0);
    expect(compiler).toMatchObject({status:'DRAFT_COMPILABLE',format:'syslog_rfc5424',bodyFormat:'raw'});
    const next=prepareAutoParserDraft(source,draft,preview(source,draft),ledger,compiler);
    expect(next.ok).toBe(true);
    if(!next.ok)return;
    expect(next.draft.syslogBodyFormat).toBe('raw');
    expect(next.draft.mappings.map(item=>item.source)).toEqual(expect.arrayContaining(['message','syslog_structured_data']));
    const suite=preview(source,next.draft);
    expect(suite.counts).toMatchObject({total:1,matched:1,extracted:1,normalized:1,failures:0});
    expect(suite.events[0]?.fields).toMatchObject({message:'firewall denied',syslog_structured_data:structured});
    expect(suite.nativeFluentdVerified).toBe(false);
  });

  it('preserves leading and trailing MSG spaces and optional absent MSG',()=>{
    for(const suffix of ['  login denied  ','']){
      const source=header+structured+(suffix?' '+suffix:'');
      const ledger=analyzeLogEnvelopes(source,'single-line');
      expect(assessEnvelopeCompilation(ledger,capabilities).status).toBe('DRAFT_COMPILABLE');
      const fields=preview(source,createDraft()).events[0]!.fields;
      expect(fields.syslog_structured_data).toBe(structured);
      if(suffix)expect(fields.message).toBe(suffix);
      else expect(fields).not.toHaveProperty('message');
    }
  });

  it('retains typed body selection and never turns malformed structured bodies into raw success',()=>{
    for(const body of ['src="unterminated','CEF:0|missing','LEEF:2.0|missing','{"bad":']){
      const ledger=analyzeLogEnvelopes(header+'- '+body,'single-line');
      expect(ledger.unsupported).toBe(1);
      expect(assessEnvelopeCompilation(ledger,capabilities).status).toBe('MIXED_OR_UNKNOWN');
    }
    const ledger=analyzeLogEnvelopes(header+'- action=deny src=192.0.2.10','single-line');
    expect(assessEnvelopeCompilation(ledger,capabilities).bodyFormat).toBe('kv');
  });

  it('keeps malformed headers, duplicate SD and unframed plaintext blocked',()=>{
    for(const source of [header.replace('<134>','<999>')+structured+' denied',header+structured+structured+' denied','firewall denied']){
      const ledger=analyzeLogEnvelopes(source,'single-line');
      expect(ledger.unsupported).toBe(1);
      expect(assessEnvelopeCompilation(ledger,capabilities).status).not.toBe('DRAFT_COMPILABLE');
    }
  });

  it('requires an actual advertised raw-body compiler and does not add a mixed raw allowlist',()=>{
    const ledger=analyzeLogEnvelopes(header+structured+' denied','single-line');
    expect(assessEnvelopeCompilation(ledger,{...capabilities,authoring:{...capabilities.authoring,rfc5424BodyFormats:['kv']}}).status).toBe('COMPILER_UNSUPPORTED');
    const mixed=analyzeLogEnvelopes(header+structured+' denied\n{"action":"deny"}','single-line');
    expect(assessEnvelopeCompilation(mixed,capabilities).status).toBe('MIXED_OR_UNKNOWN');
  });
});
