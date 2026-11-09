import {describe,it,expect} from 'vitest';
import {mappingWhenApplies} from '../fieldPaths';
import {readFileSync} from 'node:fs';
import {resolve} from 'node:path';
import {createDraft} from '../model';
import {preview} from '../parser';
import {prepareAutoParserDraft} from './autoParserDraft';
import {analyzeLogEnvelopes,assessEnvelopeCompilation} from './autoParserEnvelope';
import type {BackendCapabilities} from './backendCapabilities';
import {toBackendProject} from './backendAdapter';
import {suggestNormalizationCandidatesFromSuite} from './normalizationCandidates';
import {reviewNormalizationMappings} from './normalizationValidation';

const input=readFileSync(resolve('tests/fixtures/docs-practice-20261104/01-juniper-srx.log'),'utf8').trimEnd();
const source='syslog_sd.element_1.params.';
const capabilities={authoring:{extractionFormats:['syslog_rfc5424'],
  rfc5424BodyFormats:['raw']},verification:{engineVerified:false,targetImportVerified:false}
} as unknown as BackendCapabilities;

/** Independent semantic oracle for the published original sample; not a
 * claim of genuine device/firmware attestation or Stellar DP verification.
 */
const gold=[
  {protocol:1,official:{srcport:null,dstport:null},raw:{srcport:'594',dstport:'10400'},
    eligibleOfficialTargets:0},
  {protocol:17,official:{srcport:37233,dstport:161},raw:{srcport:'37233',dstport:'161'},
    eligibleOfficialTargets:2},
] as const;
const labels={source:'published Parser Studio Juniper tutorial fixture',
  originalCaptureAttested:false,stellarTargetAttested:false,reference:'docs-practice-20261104/01-juniper-srx.log'};

describe('Issue #232 mixed-protocol semantic normalization',()=>{
  it('defines an evidence-labeled, per-event applicability oracle before measuring coverage',()=>{
    expect(labels.originalCaptureAttested).toBe(false);
    expect(gold).toHaveLength(2);
    expect(gold.map(item=>item.eligibleOfficialTargets)).toEqual([0,2]);
  });

  it('uses the full original sample to infer bounded, transparent conditional port evidence',()=>{
    const initial=createDraft();
    const scan=preview(input,initial);
    const candidates=suggestNormalizationCandidatesFromSuite(scan,[],{});
    for(const [name,target] of [['source-port','srcport'],['destination-port','dstport']] as const){
      expect(candidates.find(item=>item.source===source+name)).toMatchObject({
        target,confidence:'HIGH',safeForBulk:true,observed:2,eligibleObserved:1,
        skippedForSemantics:1,when:{operator:'in',sourcePath:source+'protocol-id',values:['6','17']},
      });
    }
  });

  it('autogenerates official TCP/UDP ports without false ICMP ports or loss of vendor evidence',()=>{
    const initial=createDraft();
    const ledger=analyzeLogEnvelopes(input,'single-line');
    const compiler=assessEnvelopeCompilation(ledger,capabilities);
    const outcome=prepareAutoParserDraft(input,initial,preview(input,initial),ledger,compiler);
    expect(outcome.ok).toBe(true);
    if(!outcome.ok)return;
    const groups=outcome.draft.guided?.groups??{};
    const official=outcome.draft.mappings.filter(mapping=>groups[mapping.id]!=='vendor_fields');
    const sourcePort=source+'source-port',destinationPort=source+'destination-port';
    const portOfficials=official.filter(mapping=>[sourcePort,destinationPort].includes(mapping.source));
    expect(portOfficials.map(mapping=>mapping.target).sort()).toEqual(['dstport','srcport']);
    for(const port of [sourcePort,destinationPort]){
      expect(outcome.draft.mappings.some(mapping=>mapping.source===port&&
        groups[mapping.id]==='vendor_fields')).toBe(true);
    }
    expect(official.some(mapping=>mapping.target==='username')).toBe(false);
    expect(official.some(mapping=>mapping.source.includes('nat-source-address'))).toBe(false);
    expect(toBackendProject(outcome.draft).ok).toBe(true);
    const suite=preview(input,outcome.draft);
    expect(suite.counts).toMatchObject({total:2,extracted:2,normalized:2,failures:0});
    expect(reviewNormalizationMappings(suite,outcome.draft.mappings,groups).totalBlocking).toBe(0);
    const result=suite.events.map(event=>event.normalized);
    let truePositive=0,falsePositive=0,falseNegative=0;
    for(const [i,g] of gold.entries()){
      const actual=result[i]!;
      expect(actual.proto).toBe(g.protocol);
      expect(actual).toMatchObject({srcip:i===0?'10.0.0.1':'10.0.0.26',dstip:'67.43.156.13'});
      const vendor=actual[outcome.draft.vendor] as Record<string,unknown>;
      expect(vendor['source-port']).toBe(g.raw.srcport);
      expect(vendor['destination-port']).toBe(g.raw.dstport);
      for(const field of ['srcport','dstport'] as const){
        const expected=g.official[field],actualValue=actual[field];
        if(expected===null){
          if(actualValue!==undefined)falsePositive++;
          expect(actualValue).toBeUndefined();
        }else{
          if(actualValue===expected)truePositive++;else falseNegative++;
          expect(actualValue).toBe(expected);
        }
      }
    }
    expect({mappingPrecision:truePositive/(truePositive+falsePositive),
      eligibleRecall:truePositive/(truePositive+falseNegative),
      falsePositive,unhandledEligible:falseNegative}).toEqual({
      mappingPrecision:1,eligibleRecall:1,falsePositive:0,unhandledEligible:0});
    // Reuse the approved rules against an unseen TCP event and a future
    // unknown protocol. Do not reject either entire event or guess a port.
    const rawLines=input.split('\n');
    const tcp=rawLines[1]!.replace('protocol-id="17"','protocol-id="6"');
    const unknown=rawLines[1]!.replace('protocol-id="17"','protocol-id="253"');
    const holdout=preview(tcp+'\n'+unknown,outcome.draft);
    expect(holdout.counts.failures).toBe(0);
    expect(holdout.events[0]?.normalized).toMatchObject({srcport:37233,dstport:161,proto:6});
    expect(holdout.events[1]?.normalized).toMatchObject({proto:253});
    expect(holdout.events[1]?.normalized.srcport).toBeUndefined();
    expect(holdout.events[1]?.normalized.dstport).toBeUndefined();
  });

  it('guards semantic precision across independent synthetic security-vendor families',()=>{
    // Test-only source-shape controls, not original vendor captures. These
    // prevent the new Juniper protocol rule from leaking into other families.
    const syntheticCases=[
      {vendor:'Fortinet FortiOS',fields:{logid:'0001',vd:'root',type:'traffic',
        srcip:'192.0.2.11',srcport:51230,dstip:'198.51.100.15',dstport:443},
        yes:{srcip:'srcip',srcport:'srcport',dstip:'dstip',dstport:'dstport'},
        no:['type']},
      {vendor:'Cisco ASA',fields:{src:'192.0.2.12',dst:'198.51.100.22',
        spt:'51520',dpt:'22',act:'deny'},
        yes:{src:'srcip',dst:'dstip',spt:'srcport',dpt:'dstport',act:'action'},
        no:[]},
      {vendor:'Cloudflare WAF',fields:{ClientIP:'192.0.2.13',WAFAction:'block',
        RuleID:'test-rule'},
        yes:{ClientIP:'srcip'},no:['WAFAction','RuleID']},
      {vendor:'Palo Alto category',fields:{generic:{fields:{type:'TRAFFIC',
        src:'192.0.2.14',dst:'198.51.100.24',sport:'52311',dport:'443'}}},
        yes:{'generic.fields.src':'srcip','generic.fields.dst':'dstip',
          'generic.fields.sport':'srcport','generic.fields.dport':'dstport'},
        no:['generic.fields.type']},
      {vendor:'Okta audit',fields:{actor:{alternateId:'alice@example.test'},
        client:{ipAddress:'192.0.2.15'},outcome:{result:'SUCCESS'}},
        yes:{'client.ipAddress':'srcip'},no:['actor.alternateId','outcome.result']},
    ] as const;
    let expectedPositive=0,actualPositive=0,falsePositive=0;
    for(const scenario of syntheticCases){
      const suite={events:[{fields:scenario.fields}]} as unknown as import('../model').SuiteResult;
      const suggestions=suggestNormalizationCandidatesFromSuite(suite,[]);
      const expected=scenario.yes as Record<string,string>;
      for(const [sourceField,target] of Object.entries(expected)){
        const suggestion=suggestions.find(c=>c.source===sourceField&&c.target===target);
        expect(suggestion,scenario.vendor+' '+sourceField).toBeDefined();
        expect(suggestion?.confidence,scenario.vendor+' '+sourceField).toBe('HIGH');
        expect(suggestion?.when,scenario.vendor+' must not inherit Juniper protocol gate').toBeUndefined();
        expectedPositive++;
        if(suggestion?.confidence==='HIGH')actualPositive++;
      }
      for(const sourceField of scenario.no){
        const suggested=suggestions.find(c=>c.source===sourceField&&c.confidence==='HIGH');
        if(suggested)falsePositive++;
        expect(suggested,scenario.vendor+' false friend '+sourceField).toBeUndefined();
      }
    }
    expect({positivePrecision:actualPositive/(actualPositive+falsePositive),
      eligibleRecall:actualPositive/expectedPositive,falsePositive}).toEqual({
      positivePrecision:1,eligibleRecall:1,falsePositive:0});
  });

  it('fails closed on ambiguous predicate source paths without discarding another field',()=>{
    const predicate={sourcePath:'proto.id',operator:'in' as const,values:['6','17']};
    const event={proto:{id:'6'},'proto.id':'1',user:'alice'};
    expect(mappingWhenApplies(event,predicate)).toBe(false);
    expect(mappingWhenApplies({proto:{id:'6'},user:'alice'},predicate)).toBe(true);
    expect(mappingWhenApplies({'proto.id':'6',user:'alice'},predicate)).toBe(true);
    expect(event.user).toBe('alice');
  });

  it('retains source values and rejects invalid injected conditional expressions',()=>{
    const initial=createDraft();
    const ledger=analyzeLogEnvelopes(input,'single-line');
    const compiler=assessEnvelopeCompilation(ledger,capabilities);
    const result=prepareAutoParserDraft(input,initial,preview(input,initial),ledger,compiler);
    expect(result.ok).toBe(true);
    if(!result.ok)return;
    expect(toBackendProject(result.draft).ok).toBe(true);
    const unsafe={...result.draft,mappings:result.draft.mappings.map(mapping=>
      mapping.when?{...mapping,when:{sourcePath:'__proto__.foo',
        operator:'in' as const,values:['6']}}:mapping)};
    expect(toBackendProject(unsafe).ok).toBe(false);
  });
});
