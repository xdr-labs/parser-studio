import {describe,it,expect} from 'vitest';
import corpus from '../contracts/conformance-cases.v1.json';
import policy from '../runtime/multipass/semantic-policy.v1.json';
import {createDraft} from './model';
import {preview} from './parser';
import {strictKeyValues} from './structuredFamilies';
import {suggestNormalizationCandidates} from './guided/normalizationCandidates';
import {prepareAutoParserDraft} from './guided/autoParserDraft';
import {analyzeLogEnvelopes,assessEnvelopeCompilation} from './guided/autoParserEnvelope';
import {toBackendProject} from './guided/backendAdapter';
import {validatePreviewRegexPattern} from './regexSafety';
import type {BackendCapabilities} from './guided/backendCapabilities';

const cap={
  authoring:{extractionFormats:['kv','json'],rfc5424BodyFormats:['raw','kv']},
  verification:{engineVerified:false,targetImportVerified:false},
} as unknown as BackendCapabilities;
const raw=(entry:{proto?:string;proto_name?:string})=>
  (entry.proto!==undefined?'proto='+entry.proto:'proto_name='+entry.proto_name)+
  ' srcport=594 dstport=10400 srcip=192.0.2.1 dstip=198.51.100.2';
function prepare(input:string):ReturnType<typeof prepareAutoParserDraft>{
  const draft=createDraft();
  const ledger=analyzeLogEnvelopes(input,'single-line');
  const assessment=assessEnvelopeCompilation(ledger,cap);
  return prepareAutoParserDraft(input,draft,preview(input,draft),ledger,assessment);
}

describe('Canonical conformance contract — deterministic browser and authored IR',()=>{
  it('uses explicit versioned synthetic fixtures and one shared policy',()=>{
    expect(corpus.contract).toBe('parser-studio.cross-engine-corpus.v1');
    expect(corpus.origin).toBe('independently-authored-synthetic');
    expect(policy.contract).toBe('parser-studio.semantic-policy.v1');
    expect(policy.transportPortProtocols.numeric).toEqual([6,17]);
    const ids=[...corpus.portEvidence,...corpus.explicitPortAliasEvidence,
      ...corpus.kvWhitespace,...corpus.regexSafety].map(x=>x.id);
    expect(new Set(ids).size).toBe(ids.length);
    expect(ids.length).toBeGreaterThanOrEqual(30);
  });
  it.each(corpus.portEvidence)('$id: no unsupported protocol creates automatic ports',
    entry=>{
      const fields=Object.fromEntries(Object.entries(entry).filter(([key])=>
        key==='proto'||key==='proto_name')) as Record<string,unknown>;
      fields.srcport='594';fields.dstport='10400';
      fields.srcip='192.0.2.1';fields.dstip='198.51.100.2';
      const candidates=suggestNormalizationCandidates(fields,[]);
      for(const target of ['srcport','dstport']){
        const candidate=candidates.find(item=>item.target===target);
        expect(candidate,target).toBeDefined();
        expect(candidate!.safeForBulk,entry.id+' '+target).toBe(entry.allow);
        expect(candidate!.confidence,entry.id+' '+target).toBe(entry.allow?'HIGH':'REVIEW');
      }
      const prepared=prepare(raw(entry));
      expect(prepared.ok,entry.id).toBe(true);
      if(!prepared.ok)return;
      expect(toBackendProject(prepared.draft).ok).toBe(true);
      for(const source of ['srcport','dstport']){
        const mapping=prepared.draft.mappings.find(m=>m.source===source)!;
        const official=prepared.draft.guided?.groups[mapping.id]==='top_fields';
        expect(official,entry.id+' '+source).toBe(entry.allow);
      }
      const after=preview(raw(entry),prepared.draft).events[0]!;
      expect(after.fields.srcport,entry.id).toBe('594');
      expect(after.fields.dstport,entry.id).toBe('10400');
      expect(after.raw,entry.id).toBe(raw(entry));
    });
  it.each(corpus.explicitPortAliasEvidence)('$id: named-port aliases preserve types and source bytes',entry=>{
    const source='proto='+entry.proto+' source-port='+entry.sourcePort+
      ' destination-port='+entry.destinationPort+' srcip=192.0.2.1';
    const fields={'proto':entry.proto,'source-port':entry.sourcePort,
      'destination-port':entry.destinationPort,'srcip':'192.0.2.1'};
    const proposed=suggestNormalizationCandidates(fields,[]);
    for(const [leaf,target,expected] of [
      ['source-port','srcport',entry.srcport],
      ['destination-port','dstport',entry.dstport],
    ] as const){
      const candidate=proposed.find(item=>item.source===leaf);
      expect(candidate?.target,entry.id+' '+leaf).toBe(target);
      expect(candidate?.safeForBulk,entry.id+' '+leaf).toBe(expected!==null);
    }
    const prepared=prepare(source);
    expect(prepared.ok,entry.id).toBe(true);
    if(!prepared.ok)return;
    expect(toBackendProject(prepared.draft).ok).toBe(true);
    const event=preview(source,prepared.draft).events[0]!;
    expect(event.raw).toBe(source);
    expect(event.fields['source-port']).toBe(entry.sourcePort);
    expect(event.fields['destination-port']).toBe(entry.destinationPort);
    expect(event.normalized.srcport).toBe(entry.srcport===null?undefined:entry.srcport);
    expect(event.normalized.dstport).toBe(entry.dstport===null?undefined:entry.dstport);
  });
  it.each(corpus.kvWhitespace)('$id: exact KV bytes, no false green',
    entry=>{
      const source='action=allow srcip='+
        (entry.quoted?'"'+(entry.internal??'192.0.2.1')+'"':'192.0.2.1')+
        entry.trailer;
      const extracted=strictKeyValues(source);
      if(entry.quoted&&entry.trailer){
        expect(extracted.errors.length,entry.id).toBeGreaterThan(0);
      }else{
        expect(extracted.errors,entry.id).toEqual([]);
        expect(extracted.fields.srcip,entry.id).toBe(entry.srcip);
      }
      const draft=createDraft();
      draft.format='kv';
      const event=preview(source,draft).events[0]!;
      expect(event.raw,entry.id).toBe(source);
      if(entry.quoted&&entry.trailer)expect(event.status,entry.id).toBe('fail');
      const prepared=prepare(source);
      if(entry.accept&&entry.srcip==='192.0.2.1'){
        expect(prepared.ok,entry.id).toBe(true);
        if(!prepared.ok)return;
        const mapped=preview(source,prepared.draft).events[0]!;
        expect(mapped.normalized.srcip,entry.id).toBe('192.0.2.1');
        expect(mapped.status,entry.id).not.toBe('fail');
      }else if(!entry.quoted&&entry.trailer){
        const candidate=suggestNormalizationCandidates({srcip:extracted.fields.srcip},[])
          .find(item=>item.target==='srcip');
        expect(candidate?.safeForBulk,entry.id).toBe(false);
      }
    });
  it.each(corpus.regexSafety)('$id: deny unsafe capture adjacency',entry=>{
    expect(validatePreviewRegexPattern(entry.pattern)===null,entry.id).toBe(entry.accept);
  });
  it('metamorphic mutations never promote non-transport official ports',()=>{
    let seed=0x512042;
    const next=()=>{seed=(Math.imul(seed,1664525)+1013904223)>>>0;return seed;};
    const illegal=['1','2','47','50','58','89','132','253'];
    for(let i=0;i<128;i++){
      const proto=illegal[next()%illegal.length]!;
      const fields:Record<string,unknown>={proto,srcport:String(1+next()%65535),dstport:'443'};
      if(next()%2)fields.srcip='192.0.2.1';
      const approved=suggestNormalizationCandidates(fields,[]).filter(x=>
        (x.target==='srcport'||x.target==='dstport')&&x.safeForBulk);
      expect(approved,'mutation '+i+' '+proto).toEqual([]);
    }
  });
});
