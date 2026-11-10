/** Independent contract oracle; receives a compiled, in-memory mutant on stdin. */
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
const mod=await import('data:text/javascript;base64,'+readFileSync(0,'utf8').trim());
const suggest=(events,existing=[],groups={},options={})=>
  mod.suggestNormalizationCandidatesFromSuite({events:events.map(fields=>({fields}))},
    existing,groups,options);
const row=(fields,source,existing=[])=>suggest([fields],existing).find(c=>c.source===source);
const high=(fields,source,target,type)=>{
  const r=row(fields,source);
  assert.equal(r?.source,source,'source identity '+source);
  assert.equal(r?.target,target,'official destination '+source);
  assert.equal(r?.type,type,'Stellar type '+source);
  assert.equal(r?.confidence,'HIGH','high-confidence '+source);
  assert.equal(r?.safeForBulk,true,'safe bulk '+source);
  assert.equal(r?.catalogVerified,true,'catalog evidence '+source);
  assert.equal(r?.observed,1,'observed '+source);
  assert.equal(r?.compatibleObserved,1,'compatible '+source);
  assert.equal(r?.total,1,'total '+source);
};
const review=(fields,source,target)=>{
  const r=row(fields,source);
  assert.equal(r?.target,target,'review target '+source);
  assert.equal(r?.confidence,'REVIEW','review required '+source);
  assert.equal(r?.safeForBulk,false,'no auto-approve '+source);
};
const absent=(fields,source)=>
  assert.equal(row(fields,source),undefined,'forbidden inference '+source);
high({src_ip:'192.0.2.1'},'src_ip','srcip','ip');
high({src_ip:'2001:db8::1'},'src_ip','srcip','ip');
high({sourceIPAddress:'192.0.2.5'},'sourceIPAddress','srcip','ip');
high({httpRequest:{clientIp:'192.0.2.6'}},'httpRequest.clientIp','srcip','ip');
high({'source-port':594,proto:1},'source-port','srcport','integer');
high({'destination-port':'10400'},'destination-port','dstport','integer');
high({destination_port:65535},'destination_port','dstport','integer');
high({spt:443,protocol:'tcp'},'spt','srcport','integer');
high({event_time:'2026-10-16T12:30:00Z'},'event_time','timestamp','timestamp');
high({severity:100},'severity','severity','integer');
high({duration_ms:1200},'duration_ms','duration','integer');
high({proto:6},'proto','proto','integer');
high({protocol:'tcp'},'protocol','proto_name','string');
high({action:'block'},'action','action','string');
high({hostname:'sensor1'},'hostname','hostname','string');
review({src_ip:'invalid-ip'},'src_ip','srcip');
review({'source-port':65536},'source-port','srcport');
review({'source-port':-1},'source-port','srcport');
review({spt:443,protocol:'icmp'},'spt','srcport');
review({spt:443,protocol:'undocumented'},'spt','srcport');
review({spt:443,proto:6,protocol:'icmp'},'spt','srcport');
review({destination_port:'invalid'},'destination_port','dstport');
review({protocol:'HTTPS'},'protocol','proto_name');
review({proto:256},'proto','proto');
review({proto:-1},'proto','proto');
review({event_time:'2026-10-16T12:30:00'},'event_time','timestamp');
review({severity:101},'severity','severity');
review({src_ip:''},'src_ip','srcip');
review({src_ip:'N/A'},'src_ip','srcip');
absent({post_nat:{'source-port':443}},'post_nat.source-port');
absent({nat_source:{'source-port':443}},'nat_source.source-port');
absent({translated_source:{'source-port':443}},'translated_source.source-port');
absent({event_type:'alert'},'event_type');
absent({duration:2000},'duration');
absent({action:'admin-login'},'action');
absent({syslog:{severity:4}},'syslog.severity');
absent({unknown_vendor_field:42},'unknown_vendor_field');
absent({type:'TRAFFIC',logid:'0001',vd:'root'},'type');
absent({eventtype:'traffic',logid:'0001',vd:'root',type:'traffic'},'eventtype');
absent({direction:'inbound',logid:'0001',vd:'root',type:'traffic'},'direction');
absent({type:'traffic'},'type');
high({type:4,provider_guid:'abc'},'type','type','string');
absent({event_type:'alert',alert:{signature_id:1,severity:2}},'alert.severity');
// Generic Structural space_kv: an unquoted value runs to the next key, so a
// destination port followed by free text is stored whole under kv and as
// whitespace-separated pieces under atoms. A port/IP cannot contain whitespace,
// hence ONLY the first piece of a port/IP key is a valid official source.
const spaced=(key,pieces)=>({generic:{mode:'space_kv',
  kv:{[key]:pieces.join(' ')},
  atoms:Object.fromEntries(pieces.map((p,i)=>[key+'_'+String(i+1).padStart(3,'0'),p]))}});
high(spaced('dport',['53','pattern:','allow','all']),'generic.atoms.dport_001','dstport','integer');
high(spaced('sport',['55719','extra']),'generic.atoms.sport_001','srcport','integer');
high(spaced('src',['192.0.2.7','trailing']),'generic.atoms.src_001','srcip','ip');
high(spaced('dst',['198.51.100.7','trailing']),'generic.atoms.dst_001','dstip','ip');
review(spaced('dport',['abc','def']),'generic.atoms.dport_001','dstport');
review(spaced('dport',['65536','x']),'generic.atoms.dport_001','dstport');
review(spaced('dport',['53','pattern:','allow','all']),'generic.kv.dport','dstport');
absent(spaced('dport',['x','53']),'generic.atoms.dport_002');
absent(spaced('dport',['53','80']),'generic.atoms.dport_002');
absent(spaced('severity',['3','of','5']),'generic.atoms.severity_001');
absent(spaced('action',['allow','now']),'generic.atoms.action_001');
absent(spaced('hostname',['fw01','edge']),'generic.atoms.hostname_001');
absent(spaced('time',['2026-01-01','10:00:00']),'generic.atoms.time_001');
absent(spaced('post_nat_sport',['443','x']),'generic.atoms.post_nat_sport_001');
absent(spaced('unknown_vendor',['53','x']),'generic.atoms.unknown_vendor_001');
{
  // The two carriers of one key do not compete: only the atom can be approved.
  const both=suggest([spaced('dport',['53','pattern:','allow','all'])]);
  assert.deepEqual(both.filter(r=>r.confidence==='HIGH').map(r=>r.source),
    ['generic.atoms.dport_001'],'only the first atom is auto-approved');
  const kv=both.find(r=>r.source==='generic.kv.dport');
  assert.equal(kv?.safeForBulk,false,'whole-text kv value is never auto-approved');
}
const noMapping=[{id:'owner',source:'custom',target:'srcip',type:'ip'}];
assert.equal(suggest([{src_ip:'192.0.2.1'}],noMapping).length,0,'occupied target');
const current={id:'auto-1',source:'src_ip',target:'custom.src_ip',type:'string',
  authoring:{version:1,origin:'AUTO'}};
const generated=row({src_ip:'192.0.2.1'},'src_ip',[current]);
assert.equal(generated?.safeForBulk,true,'trusted generated mapping');
assert.equal(generated?.replacesMappingId,'auto-1','source identity provenance');
assert.equal(generated?.currentTarget,'custom.src_ip','destination provenance');
for(const origin of ['USER_EDITED','APPROVED']){
  const owned=row({src_ip:'192.0.2.1'},'src_ip',
    [{...current,authoring:{version:1,origin}}]);
  assert.equal(owned?.safeForBulk,false,'manual edit protected '+origin);
}
assert.equal(row({src_ip:'192.0.2.1'},'src_ip',
  [{id:'auto-1',source:'src_ip',target:'custom.src_ip',type:'string'}])?.safeForBulk,
  false,'legacy unmarked provenance');
assert.equal(suggest([{src_ip:'192.0.2.1'}],
  [{id:'auto-1',source:'src_ip',target:'srcip',type:'ip',
    authoring:{version:1,origin:'AUTO'}}],{'auto-1':'top_fields'}).length,
  0,'identical official mapping and group');
assert.equal(row({src_ip:'192.0.2.1'},'src_ip',
  [{id:'r2',source:'other',target:'srcip.extra',type:'string'}]),undefined,
  'nested target collision');
const sparse=suggest([{src_ip:'192.0.2.1'},{dst_ip:'198.51.100.1'}]);
assert.deepEqual(sparse.map(r=>r.source).sort(),['dst_ip','src_ip']);
assert.ok(sparse.every(r=>r.confidence==='REVIEW'&&!r.safeForBulk&&
  r.observed===1&&r.total===2),'heterogeneous family scope');
const mixed=suggest([{src_ip:'192.0.2.1'},{src_ip:'invalid-ip'}]);
assert.equal(mixed[0]?.compatibleObserved,1,'mixed type evidence');
assert.equal(mixed[0]?.confidence,'REVIEW','invalid event');
const competing=suggest([{source_ip:'192.0.2.1',src_ip:'198.51.100.1'}]);
assert.equal(competing.length,2,'both ambiguous sources retained');
assert.ok(competing.every(r=>r.confidence==='REVIEW'&&!r.safeForBulk));
assert.equal(suggest([{source_ip:'192.0.2.1',src_ip:'198.51.100.1'}],
  [],{},{skipAmbiguousTargets:true}).length,0,'ambiguous skip');
assert.deepEqual(suggest([{src_ip:'192.0.2.1',srcport:443}]).map(r=>r.source),
  ['src_ip','srcport'],'single-event insertion order');
const reversed=[{dst_ip:'192.0.2.1',src_ip:'198.51.100.1'},
  {src_ip:'198.51.100.2',dst_ip:'192.0.2.2'}];
assert.deepEqual(suggest(reversed),suggest([...reversed].reverse()),
  'multi-event deterministic');
assert.deepEqual(mod.suggestNormalizationCandidatesFromSuite(undefined,[]),[],
  'missing suite');
assert.deepEqual(suggest([]),[],'empty suite');
const scan=mod.normalizationCandidateScanStatus({events:[{fields:{
  unknown:1,src_ip:'192.0.2.1',dst_port:443}}]});
assert.equal(scan.eligiblePaths,2,'eligible paths');
assert.equal(scan.exceeded,false,'within budget');
assert.deepEqual(scan.paths,['src_ip','dst_port'],'stable order');
const many=Object.fromEntries(Array.from({length:1025},(_,i)=>
  ['node'+i,{src_ip:'192.0.2.1'}]));
const over=mod.normalizationCandidateScanStatus({events:[{fields:many}]});
assert.equal(over.sourceScanTruncated,true,'single-event over 1024 paths flagged');
assert.equal(over.exceeded,true,'large event fails closed');
assert.deepEqual(over.paths,[],'no truncated auto-approve');
assert.deepEqual(suggest([many]),[],'no partial official suggestions');
const exactly1024=Object.fromEntries(Array.from({length:1024},(_,i)=>
  ['node'+i,{src_ip:'192.0.2.1'}]));
const within=mod.normalizationCandidateScanStatus({events:[{fields:exactly1024}]});
assert.equal(within.sourceScanTruncated,false,'exact scan bound is allowed');
assert.equal(within.eligiblePaths,1024,'last scanned path not lost');
const late={src_ip:'192.0.2.1',
  ...Object.fromEntries(Array.from({length:99},(_,i)=>['vendor_'+i,i])),
  source_ip:'198.51.100.1'};
const complete=suggest([late]);
assert.equal(complete.length,2,'late official alias must not be missed');
assert.ok(complete.every(r=>r.target==='srcip'&&r.confidence==='REVIEW'&&
  !r.safeForBulk),'no auto-approval of early alias with late competitor');
const distributed=Array.from({length:21},(_,i)=>Object.fromEntries(
  Array.from({length:50},(_,j)=>['product_'+(i*50+j),{srcip:'192.0.2.1'}])));
const multi=mod.normalizationCandidateScanStatus({
  events:distributed.map(fields=>({fields}))});
assert.equal(multi.eligiblePaths,1050,'cross-event eligible census');
assert.equal(multi.exceeded,true,'aggregate budget fails closed');
assert.equal(multi.sourceScanTruncated,false,'per-event not truncated');
assert.equal(mod.MAX_OFFICIAL_CANDIDATE_SCAN,1024,'bounded scan');
assert.equal(mod.valueFitsMappingType('integer',443),true);
assert.equal(mod.valueFitsMappingType('integer','not-an-integer'),false);
assert.equal(mod.valueFitsNormalizationTarget('srcport','integer',65535),true);
assert.equal(mod.valueFitsNormalizationTarget('srcport','integer',65536),false);
assert.equal(mod.valueFitsNormalizationTarget('srcport','integer',null),true);
// Additional independently stated decision and explanation contracts.
high({vendor:{url:'https://example.com/a'}},'vendor.url','url','string');
high({rule:{name:'policy-1'}},'rule.name','rule.name','string');
review({flow:{spt:443,protocol:'icmp'}},'flow.spt','srcport');
high({flow:{spt:443,protocol:'tcp'}},'flow.spt','srcport','integer');
review({action:'N/A'},'action','action');
absent({hostname:'fg',logid:'001',vd:'root',type:'traffic'},'hostname');
high({hostname:'fg',vd:'root',type:'traffic'},'hostname','hostname','string');
absent({'icmp-type':8,'protocol-id':6},'icmp-type');
high({'icmp-type':8,'protocol-id':1},'icmp-type','icmp_type','string');
const sparseIcmp=suggest([{'icmp-type':8,'protocol-id':1},
  {'protocol-id':6}]);
assert.equal(sparseIcmp.find(r=>r.source==='icmp-type')?.confidence,'REVIEW',
  'missing event cannot negate present ICMP evidence');
absent({event_type:'alert',alert:{signature_id:99,severity:2}},'alert.severity');
high({event_type:'flow',alert:{signature_id:99,severity:2}},
  'alert.severity','severity','integer');
const policyCandidate=row({'policy-name':'policy-1'},'policy-name');
assert.equal(policyCandidate?.target,'rule.name','policy-name official alias');
assert.equal(row({'policy-name':'policy-1'},'policy-name',
  [{id:'taken',source:'other',target:'rule',type:'string'}]),undefined,
  'parent destination overlap');
const descriptions=[
  [row({'source-port':594},'source-port'),'explicitly names a port'],
  [row({src_ip:'192.0.2.1'},'src_ip'),'Reviewed source alias'],
  [row({srcip:'192.0.2.1'},'srcip'),'Source name matches'],
  [row({spt:443,protocol:'icmp'},'spt'),'abbreviated port field'],
  [suggest([{src_ip:'192.0.2.1'},{dst_ip:'192.0.2.2'}])[0],
    'missing from some events'],
  [row({src_ip:''},'src_ip'),'no informative values'],
  [row({src_ip:'invalid-ip'},'src_ip'),'incompatible'],
  [suggest([{source_ip:'192.0.2.1',src_ip:'192.0.2.2'}])[0],
    'multiple source fields'],
];
for(const [candidate,part] of descriptions)
  assert.ok(candidate?.explanation.includes(part),
    'independent UI reason: '+part);
assert.equal(row({srcip:'192.0.2.1'},'srcip')?.method,
  'EXACT_DICTIONARY_NAME','exact catalog identity');
assert.equal(row({src_ip:'192.0.2.1'},'src_ip')?.method,
  'DOCUMENTED_ALIAS','documented alias identity');
assert.equal(multi.paths.length,0,'aggregate-overflow candidates unavailable');
assert.equal(mod.valueFitsMappingType('integer','N/A'),true);
assert.equal(mod.valueFitsMappingType('ip',null),true);
// Per-container protocol evidence must not disappear when root fields differ.
review({flow:{spt:443,'protocol-id':1}},'flow.spt','srcport');
review({flow:{spt:443,proto:1}},'flow.spt','srcport');
review({flow:{spt:443,proto_name:'icmp'}},'flow.spt','srcport');
high({flow:{spt:443,'protocol-id':6}},'flow.spt','srcport','integer');
absent({post_nat:{'destination-port':443}},'post_nat.destination-port');
absent({translated_source:{'destination-port':443}},'translated_source.destination-port');
high({icmp_type:'8','protocol-id':6},'icmp_type','icmp_type','string');
const mismatch={id:'auto-1',source:'src_ip',target:'srcip',type:'string',
  authoring:{version:1,origin:'AUTO'}};
const mismatchCandidate=row({src_ip:'192.0.2.1'},'src_ip',[mismatch]);
assert.equal(mismatchCandidate?.target,'srcip','incorrect type needs review');
assert.equal(mismatchCandidate?.replacesMappingId,'auto-1');
const wrongGroup=suggest([{src_ip:'192.0.2.1'}],
  [{...mismatch,type:'ip'}],{'auto-1':'vendor_fields'});
assert.equal(wrongGroup.length,1,'incorrect group needs review');
const scoped=suggest([{src_ip:'192.0.2.1'}],
  [{...mismatch,type:'ip',when:{sourcePath:'event',operator:'in',values:['login']}}],
  {'auto-1':'top_fields'});
assert.equal(scoped.length,1,'scoped rules do not suppress global official mapping');
console.log('INDEPENDENT_ORACLE_PASS');
