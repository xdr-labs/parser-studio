import {describe,expect,it} from 'vitest';
import {createDraft,type ParserDraft} from '../model';
import {preview} from '../parser';
import {matchRfc3164Header} from '../grammar/syslogHeader';
import {buildAutomaticGenericStructuralDraft} from './genericStructuralAutoDraft';
import {analyzeLogEnvelopes,assessEnvelopeCompilation} from './autoParserEnvelope';
import {prepareAutoParserDraft} from './autoParserDraft';
import type {BackendCapabilities} from './backendCapabilities';
import {toBackendProject} from './backendAdapter';
import {reconstructExactBackendDraft} from './pairProjectImport';

// Repro tests of the fourth independent audit (7874969, 2026-11-24). SYNTHETIC lines, except FGT (golden
// fortinet_cef, PUBLISHER_ORIGINAL).
const cap={authoring:{extractionFormats:['json','kv','csv','mixed','cef','leef','syslog_rfc3164','syslog_rfc5424'],
  rfc3164StrictTaggedMessageSubset:true,rfc3164TaglessStructuredSecuritySubset:true,
  rfc3164TimePolicy:'YEAR_AND_ZONE_UNKNOWN',rfc3164NativeTimeReconstruction:false,
  rfc3164BodyFormats:['raw','json','kv','cef','leef'],rfc5424BodyFormats:['raw','json','kv','cef','leef']},
  verification:{engineVerified:false,targetImportVerified:false}} as unknown as BackendCapabilities;
function journey(source:string){
  const draft=createDraft();
  const ledger=analyzeLogEnvelopes(source,'single-line');
  const ready=prepareAutoParserDraft(source,draft,preview(source,draft),ledger,assessEnvelopeCompilation(ledger,cap));
  if(!ready.ok)throw new Error(ready.reason);
  return ready.draft;
}
const FGT='Dec 27 11:07:55 FGT-A-LOG CEF: 0|Fortinet|Fortigate|v6.0.3|00013|traffic:forward close|3|deviceExternalId=FGT5HD3915800610 FTNTFGTlogid=0000000013 cat=traffic:forward FTNTFGTsubtype=forward src=10.1.100.11 spt=54190 dst=52.53.140.235 dpt=443 proto=6 act=close';
const FGT2=FGT.replace('11:07:55','11:12:30').replace('close|3|','accept|3|').replace('act=close','act=accept');

describe('A-1: an unmapped field never takes an enrichment target',()=>{
  it('keeps a new key whose name an enrichment writes in the vendor namespace, and the event stays OK',()=>{
    const base=journey(['srcip=10.1.1.1 dstip=10.2.2.2 action=allow user=bob','srcip=10.1.1.3 dstip=10.2.2.4 action=deny user=amy'].join('\n'));
    const draft:ParserDraft={...base,vendor:'acme',guided:{...base.guided!,
      enrichment:[{operator:'copy',source:'srcip',target:'acme.city'}] as never}};
    const [event]=preview('srcip=10.1.1.5 dstip=10.2.2.6 action=allow user=carl city=Seoul',draft).events;
    expect(event!.normalizedOk,JSON.stringify(event!.diagnostics)).toBe(true);
    const text=JSON.stringify(event!.normalized);
    expect(text).toContain('"Seoul"');
    expect((event!.normalized.acme as Record<string,unknown>).city).toBe('10.1.1.5');
  });
});

describe('A-4: a dotted key a mapping reads is written once',()=>{
  it('does not repeat policy.id under parserstudio_unmapped',()=>{
    const draft=journey(['policy.id=5 srcip=10.1.1.1 act=allow','policy.id=6 srcip=10.1.1.2 act=deny'].join('\n'));
    const [event]=preview('policy.id=7 srcip=10.1.1.3 act=allow',draft).events;
    expect(event!.parseStatus).toBe('FULL');
    expect(JSON.stringify(event!.normalized).split('"7"').length-1).toBe(1);
  });
});

describe('A-5: an unmapped field has one name in every event family',()=>{
  it('names a raw user the same in a family that maps uname to vendor user and in one that does not',()=>{
    const draft:ParserDraft={...createDraft(),format:'kv',vendor:'acme',preserveUnmapped:true,mappings:[],
      eventProfiles:{discriminator:'type',unknown:'reject',variants:[
        {name:'a',equals:'a',mappings:[{id:'fa',source:'uname',target:'user',type:'string',authoring:{version:1,origin:'AUTO'}}]},
        {name:'b',equals:'b',mappings:[{id:'fb',source:'zone',target:'zone',type:'string',authoring:{version:1,origin:'AUTO'}}]},
      ]}};
    const [a,b]=preview(['type=a uname=alice user=bob','type=b user=carol zone=z'].join('\n'),draft).events;
    const vendor=(event:typeof a)=>event!.normalized.acme as Record<string,Record<string,unknown>>;
    expect(vendor(a).user).toBe('alice');
    expect(vendor(a).parserstudio_unmapped!.user).toBe('bob');
    expect(vendor(b).parserstudio_unmapped!.user).toBe('carol');
    expect(vendor(b).user).toBeUndefined();
  });
});

describe('A-2: a FortiGate CEF record after an RFC 3164 header with PRI',()=>{
  it('is never read with the tag CEF',()=>{
    const header=matchRfc3164Header('<189>'+FGT);
    expect(header.ok&&header.rule==='rfc3164_tagged').toBe(false);
  });
  it('makes a parser that reads both spellings, each event FULL',()=>{
    const source=['<189>'+FGT,'<189>'+FGT2].join('\n');
    const draft=journey(source);
    const events=preview(['<189>'+FGT,'<189>'+FGT2.replace('CEF: 0|','CEF:0|')].join('\n'),draft).events;
    expect(events.map(event=>event.parseStatus)).toEqual(['FULL','FULL']);
    for(const event of events)expect(JSON.stringify(event.normalized)).toContain('"FGT5HD3915800610"');
  });
});

describe('A-3: a malformed CEF claim is declined by Generic Structural, never read as generic text',()=>{
  it.each(['CEF:  0|','CEF:\t0|','CEF :0|'])('declines %j',spelling=>{
    const built=buildAutomaticGenericStructuralDraft([FGT,FGT2].join('\n'),createDraft());
    const draft=built?.draft??createDraft();
    const [event]=preview(FGT.replace('CEF: 0|',spelling),draft).events;
    expect(event!.parseStatus).not.toBe('FULL');
  });
});

// Final independent audit (adf8d3d). SYNTHETIC lines.
describe('final audit F-1, F-2, F-3, F-5',()=>{
  const sample=['srcip=10.1.1.1 dstip=10.2.2.2 action=allow user=bob','srcip=10.1.1.3 dstip=10.2.2.4 action=deny user=amy'].join('\n');
  it('F-1: reserves the outputs of a split enrichment',()=>{
    const base=journey(sample);
    const draft:ParserDraft={...base,vendor:'acme',guided:{...base.guided!,
      enrichment:[{operator:'split_field',source:'action',delimiter:'_',targets:['acme.o1','acme.o2']}] as never}};
    const [event]=preview('srcip=10.1.1.5 dstip=10.2.2.6 action=al_low user=carl o1=zzz',draft).events;
    expect(event!.normalizedOk,JSON.stringify(event!.diagnostics)).toBe(true);
    expect(JSON.stringify(event!.normalized)).toContain('"zzz"');
  });
  it('F-2: a nested-kind mapping does not take a literal dotted key',()=>{
    const base=journey(['{"srcip":"10.1.1.1","dstip":"10.2.2.2","action":"allow"}','{"srcip":"10.1.1.3","dstip":"10.2.2.4","action":"deny"}'].join('\n'));
    const draft:ParserDraft={...base,mappings:[...base.mappings,{id:'mn',source:'m.n',target:'mn',type:'string',
      sourcePathKind:'nested',authoring:{version:1,origin:'AUTO'}}]};
    const [event]=preview('{"srcip":"10.1.1.5","dstip":"10.2.2.6","action":"allow","m.n":"10"}',draft).events;
    expect(JSON.stringify(event!.normalized)).toContain('"10"');
  });
  it('F-3: an Auto Parser project imports back exactly',()=>{
    const converted=toBackendProject(journey(sample));
    expect(converted.ok).toBe(true);
    if(!converted.ok)return;
    const restored=reconstructExactBackendDraft(converted.project,'customized_'+converted.project.slug);
    expect(restored).not.toBeNull();
  });
  it('F-5: a mapping may not write the reserved parserstudio_unmapped object',()=>{
    const base=journey(sample);
    const draft:ParserDraft={...base,mappings:base.mappings.map(rule=>rule.source==='user'?{...rule,target:'parserstudio_unmapped'}:rule)};
    const [event]=preview('srcip=10.1.1.5 dstip=10.2.2.6 action=allow user=carl',draft).events;
    expect(event!.diagnostics.map(item=>item.code)).toContain('TARGET_COLLISION');
  });
});
