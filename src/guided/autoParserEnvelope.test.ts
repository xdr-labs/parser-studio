import {describe,it,expect} from 'vitest';
import {analyzeLogEnvelopes,assessEnvelopeCompilation} from './autoParserEnvelope';
import type {BackendCapabilities} from './backendCapabilities';

const rfc3164='<34>Oct 12 13:14:15 fw01 security[22]: action="allow" src_ip=198.51.100.10 user=PRIVATE_USER';
const rfc5424Json='<34>1 2026-10-12T12:00:00Z fw app - - - {"action":"allow","user":{"name":"PRIVATE_USER"}}';
const wrap=(body:string)=>'<34>1 2026-10-12T12:00:00Z fw app - - - '+body;
const cef='CEF:0|Vendor|Product|1|100|Threat|6|src=198.51.100.10';
const leef='LEEF:1.0|Vendor|Product|1|Event|src=198.51.100.10';
const json='{"action":"allow","src_ip":"198.51.100.10"}';
const kv='action="allow" src_ip=198.51.100.10';
const cap={authoring:{extractionFormats:['json','kv','csv','syslog_rfc5424','cef','leef'],
  rfc5424BodyFormats:['raw','json','kv','cef','leef']},
  verification:{engineVerified:false,targetImportVerified:false}} as unknown as BackendCapabilities;
function noValues(data:unknown){
 const text=JSON.stringify(data);
 for(const secret of ['PRIVATE_USER','198.51.100.10','fw01','"action":"allow"'])
   expect(text).not.toContain(secret);
}
describe('P0-AP1 value-free envelope/body and compiler parity',()=>{
  it('RFC3164+quoted KV remains explicitly compiler unsupported and timezone ambiguous',()=>{
    const r=analyzeLogEnvelopes(rfc3164,'single-line');
    expect(r).toMatchObject({sourceCount:1,accounted:1,complete:true,unsupported:0});
    expect(r.events[0]).toMatchObject({line:1,envelope:'rfc3164',body:'kv',status:'RECOGNIZED',
      timePolicy:'YEAR_AND_ZONE_UNKNOWN'});
    expect(assessEnvelopeCompilation(r,cap)).toMatchObject({
      status:'COMPILER_UNSUPPORTED',format:null,nativeVerified:false});
    noValues(r);
  });
  it('RFC5424 JSON/CEF/LEEF body decomposition and draft-only compiler eligibility',()=>{
    for(const [source,kind] of [[rfc5424Json,'json'],[wrap(cef),'cef'],[wrap(leef),'leef']] as const){
      const r=analyzeLogEnvelopes(source,'single-line');
      expect(r.events[0]).toMatchObject({envelope:'rfc5424',body:kind,status:'RECOGNIZED'});
      expect(assessEnvelopeCompilation(r,cap)).toMatchObject({
        status:'DRAFT_COMPILABLE',format:'syslog_rfc5424',bodyFormat:kind,
        nativeVerified:false,targetVerified:false});
      noValues(r);
    }
  });
  it('standalone JSON, KV, CEF, LEEF and CSV keep distinct reviewed candidate families',()=>{
    for(const [source,kind] of [[json,'json'],[kv,'kv'],[cef,'cef'],[leef,'leef'],
      ['allow,198.51.100.10,443','csv']] as const){
      const r=analyzeLogEnvelopes(source,'single-line');
      expect(r.events[0]).toMatchObject({envelope:'none',body:kind,status:'RECOGNIZED'});
      expect(assessEnvelopeCompilation(r,cap).status).toBe(
        kind==='csv'?'COLUMNS_REQUIRED':'DRAFT_COMPILABLE');
      noValues(r);
    }
  });
  it('keeps strongly quoted CSV as CSV when a field contains an equals sign',()=>{
    const quoted='"2026-10-16 00:00:00","host","https://example.test/path?ext_id=demo","allow"';
    const r=analyzeLogEnvelopes(quoted,'single-line');
    expect(r.events[0]).toMatchObject({envelope:'none',body:'csv',status:'RECOGNIZED'});
    expect(assessEnvelopeCompilation(r,cap).status).toBe('COLUMNS_REQUIRED');
    const kvWithCommas='action=allow note=a,b,c';
    expect(analyzeLogEnvelopes(kvWithCommas,'single-line').events[0])
      .toMatchObject({envelope:'none',body:'kv',status:'RECOGNIZED'});
  });
  it('accepts wide bounded JSON up to the engine leaf budget without weakening depth safety',()=>{
    const wide=JSON.stringify(Object.fromEntries(
      Array.from({length:146},(_,index)=>['field_'+String(index+1),index])));
    const r=analyzeLogEnvelopes(wide,'single-line');
    expect(r.events[0]).toMatchObject({envelope:'none',body:'json',status:'RECOGNIZED'});
    expect(assessEnvelopeCompilation(r,cap).status).toBe('DRAFT_COMPILABLE');

    const atLimit=JSON.stringify({items:Array.from({length:4096},()=>0)});
    expect(analyzeLogEnvelopes(atLimit,'single-line').events[0]?.status).toBe('RECOGNIZED');
    const overLimit=JSON.stringify({items:Array.from({length:4097},()=>0)});
    expect(analyzeLogEnvelopes(overLimit,'single-line').events[0]?.status).not.toBe('RECOGNIZED');

    let deep:unknown='value';
    for(let i=0;i<9;i++)deep={level:deep};
    expect(analyzeLogEnvelopes(JSON.stringify(deep),'single-line').events[0]?.status).not.toBe('RECOGNIZED');
    noValues(r);
  });
  it('accounts for every mixed and unknown record without dropping a minority',()=>{
    const r=analyzeLogEnvelopes([json,rfc3164,kv,'UNRECOGNIZED_SECRET'].join('\n'),'single-line');
    expect(r).toMatchObject({sourceCount:4,accounted:4,unsupported:1,complete:true});
    expect(r.events.map(e=>e.line)).toEqual([1,2,3,4]);
    expect(r.families.reduce((s,v)=>s+v.count,0)).toBe(4);
    expect(assessEnvelopeCompilation(r,cap).status).toBe('MIXED_OR_UNKNOWN');
    noValues(r);
  });
  it('malformed/truncated RFC3164, RFC5424, CEF and JSON are not successful',()=>{
    const raw=['<34>Oct 40 99:00:00 fw app: action=allow',
      '<999>1 2026-10-12T12:00:00Z fw app - - - '+json,
      'CEF:0|Vendor|incomplete','{"action":"PRIVATE_USER"'].join('\n');
    const r=analyzeLogEnvelopes(raw,'single-line');
    expect(r).toMatchObject({sourceCount:4,accounted:4,unsupported:4,complete:true});
    expect(r.events.every(e=>e.status!=='RECOGNIZED')).toBe(true);
    expect(assessEnvelopeCompilation(r,cap).status).toBe('MIXED_OR_UNKNOWN');
    noValues(r);
  });
  it('physical multiline grouping is accounted for but not native-ready',()=>{
    const raw='{\n "action":"allow",\n "user":"PRIVATE_USER"\n}\n\n'+rfc3164;
    const r=analyzeLogEnvelopes(raw,'blank-line');
    expect(r.sourceCount).toBe(2);
    expect(r.events.map(e=>e.line)).toEqual([1,6]);
    expect(r.events[0].status).toBe('BOUNDARY_AMBIGUOUS');
    expect(assessEnvelopeCompilation(r,cap).status).toBe('BOUNDARY_REVIEW');
    noValues(r);
  });
  it('limits, unsupported compiler modes and forged verification cannot become PASS',()=>{
    expect(analyzeLogEnvelopes('x'.repeat(65537),'single-line').complete).toBe(false);
    expect(analyzeLogEnvelopes(Array(501).fill(json).join('\n'),'single-line').complete).toBe(false);
    const r=analyzeLogEnvelopes(wrap(cef),'single-line');
    expect(assessEnvelopeCompilation(r,null).status).toBe('BACKEND_UNAVAILABLE');
    expect(assessEnvelopeCompilation(r,{...cap,authoring:{...cap.authoring,rfc5424BodyFormats:['raw','json']}} as BackendCapabilities).status).toBe('COMPILER_UNSUPPORTED');
    expect(assessEnvelopeCompilation(r,{...cap,verification:{...cap.verification,targetImportVerified:true}} as unknown as BackendCapabilities).status).toBe('BACKEND_UNTRUSTED');
  });
});
