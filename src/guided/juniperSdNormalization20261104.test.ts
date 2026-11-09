import {describe,expect,it} from 'vitest';
import {createDraft} from '../model';
import type {SuiteResult} from '../model';
import {extractFields,preview} from '../parser';
import {toBackendProject} from './backendAdapter';
import {prepareAutoParserDraft} from './autoParserDraft';
import {analyzeLogEnvelopes,assessEnvelopeCompilation} from './autoParserEnvelope';
import type {BackendCapabilities} from './backendCapabilities';
import {suggestNormalizationCandidatesFromSuite} from './normalizationCandidates';

const source=(protocol:string,service:string,action:'CREATE'|'DENY')=>
  '<14>1 2019-11-14T11:12:46.573+01:00 SRX-GW1 RT_FLOW - RT_FLOW_SESSION_'+action+' '+
  '[junos@67.43.156.15 source-address="10.0.0.26" source-port="37233" '+
  'destination-address="67.43.156.13" destination-port="161" '+
  'protocol-id="'+protocol+'" service-name="'+service+'" '+
  'policy-name="MgmtAccess-trust-cleanup" username="N/A" '+
  'nat-source-address="10.10.10.1" nat-destination-address="192.0.2.11" '+
  'source-zone-name="trust" destination-zone-name="untrust"]';
const prefix='syslog_sd.element_1.params.';
const cap={authoring:{extractionFormats:['syslog_rfc5424'],
  rfc5424BodyFormats:['raw']},verification:{engineVerified:false,targetImportVerified:false}
} as unknown as BackendCapabilities;

function extracted(raw:string){
  const draft=createDraft();
  draft.format='syslog_rfc5424';
  draft.syslogBodyFormat='raw';
  const result=extractFields(raw,'syslog_rfc5424',draft);
  expect(result.errors).toEqual([]);
  return result.fields;
}
function candidates(...raw:string[]){
  return suggestNormalizationCandidatesFromSuite(
    {events:raw.map(item=>({fields:extracted(item)}))} as unknown as SuiteResult,[]);
}
describe('Juniper RFC5424 SD semantic mappings with Stellar 7.0 catalog evidence',()=>{
  it('maps the true IP tuple, transport protocol and rule name, leaving NAT and application names intact',()=>{
    const suggestions=candidates(source('6','junos-http','CREATE'),source('17','junos-udp','DENY'));
    const official=[
      ['source-address','srcip','ip','top_fields'],
      ['destination-address','dstip','ip','top_fields'],
      ['source-port','srcport','integer','top_fields'],
      ['destination-port','dstport','integer','top_fields'],
      ['protocol-id','proto','integer','top_fields'],
      ['policy-name','rule.name','string','ns_fields'],
    ] as const;
    for(const [sourceField,target,type,group] of official){
      expect(suggestions).toEqual(expect.arrayContaining([
        expect.objectContaining({source:prefix+sourceField,target,type,group,
          confidence:'HIGH',safeForBulk:true,catalogRelease:'7.0.xs'}),
      ]));
    }
    expect(suggestions.some(candidate=>candidate.source.endsWith('service-name'))).toBe(false);
    expect(suggestions.some(candidate=>candidate.source.includes('nat-source-address'))).toBe(false);
    expect(suggestions.some(candidate=>candidate.source.includes('nat-destination-address'))).toBe(false);
    expect(suggestions.find(candidate=>candidate.source===prefix+'username'))
      .toMatchObject({target:'username',confidence:'REVIEW',safeForBulk:false});
  });

  it('maps exactly named port fields using validated integers even for an ICMP event',()=>{
    const suggestions=candidates(source('1','icmp','CREATE'));
    for(const [field,target] of [['source-address','srcip'],['destination-address','dstip'],['protocol-id','proto']]){
      expect(suggestions.find(candidate=>candidate.source===prefix+field))
        .toMatchObject({target,confidence:'HIGH',safeForBulk:true});
    }
    for(const [field,target] of [['source-port','srcport'],['destination-port','dstport']]){
      expect(suggestions.find(candidate=>candidate.source===prefix+field))
        .toMatchObject({target,confidence:'HIGH',safeForBulk:true,type:'integer'});
      expect(suggestions.find(candidate=>candidate.source===prefix+field)?.when).toBeUndefined();
    }
    expect(suggestions.some(candidate=>candidate.source===prefix+'service-name')).toBe(false);
  });

  it('applies the same named-port contract without a vendor-specific rule',()=>{
    const other=extracted(source('1','icmp','CREATE')
      .replace('junos@67.43.156.15','another@67.43.156.15'));
    const accepted=suggestNormalizationCandidatesFromSuite(
      {events:[{fields:other}]} as unknown as SuiteResult,[]);
    expect(accepted.find(c=>c.source===prefix+'source-port')).toMatchObject({
      target:'srcport',confidence:'HIGH',safeForBulk:true,
    });
    // Abbreviated port labels without transport semantics remain review-only.
    const ambiguous=suggestNormalizationCandidatesFromSuite(
      {events:[{fields:{proto:'1',sport:'594',dport:'10400'}}]} as unknown as SuiteResult,[]);
    expect(ambiguous.find(c=>c.source==='sport')).toMatchObject({
      target:'srcport',confidence:'REVIEW',safeForBulk:false,
    });
    expect(ambiguous.find(c=>c.source==='dport')).toMatchObject({
      target:'dstport',confidence:'REVIEW',safeForBulk:false,
    });
    const invalid=suggestNormalizationCandidatesFromSuite(
      {events:[{fields:{'source-port':'65536','destination-port':'-1'}}]} as unknown as SuiteResult,[]);
    expect(invalid.every(c=>!c.safeForBulk)).toBe(true);
    // A nested NAT field with the same final label is a different semantic
    // source, not a competing original network tuple.
    const scoped=suggestNormalizationCandidatesFromSuite(
      {events:[{fields:{'source-port':'594',nat:{'source-port':'45000'},
        translated:{'destination-port':'8443'}}}]} as unknown as SuiteResult,[]);
    expect(scoped.find(c=>c.source==='source-port')).toMatchObject({
      target:'srcport',confidence:'HIGH',safeForBulk:true,
    });
    expect(scoped.some(c=>c.source==='nat.source-port')).toBe(false);
    expect(scoped.some(c=>c.source==='translated.destination-port')).toBe(false);

  });

  it('offers sparse ICMP type only for manual review while preserving unrelated event types',()=>{
    const s1=source('1','icmp','DENY').replace('service-name="icmp"',
      'service-name="icmp" icmp-type="8"');
    const suggestions=candidates(s1,source('6','junos-https','CREATE'));
    const icmp=suggestions.find(item=>item.source===prefix+'icmp-type');
    expect(icmp).toMatchObject({target:'icmp_type',confidence:'REVIEW',safeForBulk:false,
      observed:1,total:2,type:'string'});
  });

  it('keeps distinct competing structured-data elements review-only instead of overwriting the IP target',()=>{
    const fields={syslog_sd:{
      element_1:{params:{'source-address':'10.0.0.1'}},
      element_2:{params:{'source-address':'198.51.100.21'}},
    }};
    const suggestions=suggestNormalizationCandidatesFromSuite(
      {events:[{fields}]} as unknown as SuiteResult,[]);
    expect(suggestions).toHaveLength(2);
    expect(suggestions.every(candidate=>candidate.target==='srcip'&&
      candidate.confidence==='REVIEW'&&!candidate.safeForBulk)).toBe(true);
  });

  it('takes the novice Auto Parser path to actual Stellar field mappings in a compilable draft',()=>{
    const raw=[source('6','junos-http','CREATE'),source('17','junos-udp','DENY')].join('\n');
    const initial=createDraft();
    const ledger=analyzeLogEnvelopes(raw,'single-line');
    const compiler=assessEnvelopeCompilation(ledger,cap);
    const result=prepareAutoParserDraft(raw,initial,preview(raw,initial),ledger,compiler);
    expect(result).toMatchObject({ok:true});
    if(!result.ok)return;
    const official=(suffix:string)=>{
      const rule=result.draft.mappings.find(mapping=>mapping.source===prefix+suffix&&
        result.draft.guided?.groups[mapping.id]!=='vendor_fields');
      expect(rule).toBeDefined();
      return rule!;
    };
    expect(official('source-address')).toMatchObject({target:'srcip',type:'ip'});
    expect(official('destination-address')).toMatchObject({target:'dstip',type:'ip'});
    expect(official('source-port')).toMatchObject({target:'srcport',type:'integer'});
    expect(official('source-port').when).toBeUndefined();
    expect(official('destination-port')).toMatchObject({target:'dstport',type:'integer'});
    expect(official('destination-port').when).toBeUndefined();
    expect(official('protocol-id')).toMatchObject({target:'proto',type:'integer'});
    expect(official('policy-name')).toMatchObject({target:'rule.name',type:'string'});
    expect(result.draft.guided?.groups[official('policy-name').id]).toBe('ns_fields');
    const vendor=result.draft.mappings.find(mapping=>mapping.source===prefix+'service-name');
    expect(vendor).toBeDefined();
    expect(result.draft.guided?.groups[vendor!.id]).toBe('vendor_fields');
    expect(toBackendProject(result.draft)).toMatchObject({ok:true});
    const replay=preview(raw,result.draft);
    expect(replay.counts).toMatchObject({total:2,matched:2,extracted:2,normalized:2,failures:0});
    expect(replay.events[0].normalized).toMatchObject({srcip:'10.0.0.26',dstip:'67.43.156.13'});
    expect(replay.events[0].normalized.rule).toMatchObject({name:'MgmtAccess-trust-cleanup'});
  });
});
