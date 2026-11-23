/** Independent source-level fault probes for official Stellar mapping
 * candidates. Every mutant is a real source change; the independent oracle
 * includes positive/negative semantic examples and manual provenance.
 * Synthetic values only. This is a selected policy-gate mutation inventory,
 * not an exhaustive AST mutation score of the complete candidate provider.
 */
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import * as esbuild from 'esbuild';
const path='src/guided/normalizationCandidates.ts';
const source=readFileSync(path,'utf8');
async function load(text){
  const result=await esbuild.build({entryPoints:[path],bundle:true,platform:'node',
    format:'esm',write:false,logLevel:'silent',plugins:[{
      name:'semantic-candidate-mutant',setup(build){
        build.onLoad({filter:/normalizationCandidates\.ts$/},()=>({contents:text,loader:'ts'}));
      },
    }]});
  return import('data:text/javascript;base64,'+
    Buffer.from(result.outputFiles[0].text).toString('base64'));
}
const examples=[
  ['src_ip','srcip',{src_ip:'192.0.2.9'},true],
  ['src_ip','srcip',{src_ip:'invalid-ip'},false],
  ['source-port','srcport',{'source-port':594,proto:1},true],
  ['destination-port','dstport',{'destination-port':10400},true],
  ['source-port','srcport',{'source-port':65536},false],
  ['action','action',{action:'block'},true],
  ['proto','proto',{proto:256},false],
  ['proto','proto',{proto:6},true],
  ['duration_ms','duration',{duration_ms:2000},true],
];
const forbidden=[
  ['post_nat.source-port',{post_nat:{'source-port':4411}}],
  ['nat_source.source-port',{nat_source:{'source-port':4411}}],
  ['translated_source.source-port',{translated_source:{'source-port':4411}}],
  ['event_type',{event_type:'alert'}],
  ['duration',{duration:2000}],
  ['action',{action:'admin-login'}],
  ['syslog.severity',{syslog:{severity:4}}],
];
function runSuite(mod,events,existing=[],options={}){
  return mod.suggestNormalizationCandidatesFromSuite({events:events.map(fields=>({fields}))},
    existing,{},options);
}
function oracle(mod){
  for(const [source,target,fields,high] of examples){
    const row=runSuite(mod,[fields]).find(c=>c.source===source);
    assert.equal(row?.target,target,'independent target '+source);
    assert.equal(row?.confidence,high?'HIGH':'REVIEW','confidence '+source+' '+high);
    assert.equal(row?.safeForBulk,high,'bulk permission '+source);
    assert.equal(row?.catalogVerified,true,'Stellar catalog gate '+source);
  }
  for(const [source,fields] of forbidden)
    assert.equal(runSuite(mod,[fields]).some(c=>c.source===source),false,
      'vendor false friend '+source);
  const alias=runSuite(mod,[{src_ip:'192.0.2.1',source_ip:'198.51.100.1'}]);
  const competition=alias.filter(c=>c.target==='srcip');
  assert.equal(competition.length,2,'both ambiguous aliases retained');
  assert.equal(competition.every(c=>c.confidence==='REVIEW'&&!c.safeForBulk),true,
    'neither ambiguous alias may be bulk-applied');
  assert.equal(runSuite(mod,[{src_ip:'192.0.2.1',source_ip:'198.51.100.1'}],[],
    {skipAmbiguousTargets:true}).some(c=>c.target==='srcip'),false,
    'explicit skip should exclude ambiguous official target');
  const sparse=runSuite(mod,[{src_ip:'192.0.2.1'},{dst_ip:'198.51.100.1'}]);
  assert.equal(sparse.filter(c=>['srcip','dstip'].includes(c.target))
    .every(c=>c.confidence==='REVIEW'&&!c.safeForBulk),true,
    'sparse event family must not bulk-approve');
  const abbreviation=runSuite(mod,[{sport:443,protocol:'icmp'}])
    .find(c=>c.source==='sport');
  assert.equal(abbreviation?.safeForBulk,false,'nontransport abbreviated port');
  const manual={id:'auto-1',source:'src_ip',target:'custom.srcip',type:'string',
    authoring:{version:1,origin:'USER_EDITED'}};
  const edited=runSuite(mod,[{src_ip:'192.0.2.1'}],[manual])[0];
  assert.equal(edited?.safeForBulk,false,'explicit user edit protected');
  assert.equal(edited?.replacesMappingId,'auto-1');
  assert.equal(runSuite(mod,[{src_ip:'192.0.2.1'}],[
    {id:'custom',source:'old',target:'srcip',type:'ip'}]).some(c=>c.target==='srcip'),
    false,'occupied destination cannot get a competing candidate');
  // Mixed record families: an endpoint field that carries the official name itself is approved although one
  // family lacks it; an official name of another kind is not.
  const families=runSuite(mod,[{srcport:51544,proto:6,md5:'69630e4574ec6798239b091cda43dca0'},{note:'system record'}]);
  // Found by the independent audit of 2026-11-21: none of these may be approved.
  const icmpFamily=runSuite(mod,[{srcport:51234,dstport:443,ipproto:6},{srcport:8,dstport:0,ipproto:1},{note:'system record'}]);
  assert.equal(icmpFamily.filter(c=>['srcport','dstport'].includes(c.target)).every(c=>!c.safeForBulk),true,
    'sparse port beside an ICMP record that names its protocol ipproto');
  const noProtocol=runSuite(mod,[{srcport:8,dstport:0},{note:'system record'}]);
  assert.equal(noProtocol.filter(c=>['srcport','dstport'].includes(c.target)).every(c=>!c.safeForBulk),true,
    'sparse port without any protocol in the record');
  const nested=runSuite(mod,[{xlate:{srcip:'203.0.113.5',srcport:40002},proto:6},{note:'system record'}]);
  assert.equal(nested.filter(c=>['srcip','srcport'].includes(c.target)).every(c=>!c.safeForBulk),true,
    'sparse endpoint inside a nested object');
  assert.equal(families.find(c=>c.source==='srcport')?.safeForBulk,true,'sparse official-name endpoint field');
  assert.equal(families.find(c=>c.source==='md5')?.safeForBulk,false,'sparse official name of another kind');
  // A host field carried only by events that describe an HTTP request (a value is a method, a request line or
  // an HTTP version) is offered for review, whatever its fields are called; a record whose field called method
  // holds another value keeps its host name.
  for(const fields of [{host:'shop.example.com',request:'GET /cart HTTP/1.1',status:200},
    {http:{hostname:'example.com',http_method:'GET',protocol:'HTTP/1.1'}},{host:'example.com',verb:'POST',path:'/x'}]){
    const hosts=runSuite(mod,[fields]).filter(c=>c.target==='hostname');
    assert.equal(hosts.length===1&&hosts[0].confidence==='REVIEW'&&!hosts[0].safeForBulk,true,
      'host field of an HTTP request record '+JSON.stringify(fields));
  }
  assert.equal(runSuite(mod,[{host:'api-node-3',method:'GetUser',status_code:0}]).find(c=>c.source==='host')?.safeForBulk,true,
    'host field beside a method that is not an HTTP method');
  // Neither a method nor a version: a host inside an object of the record, and a host beside an absolute web URL.
  for(const fields of [{agent:{hostname:'collector-7'},message:'started'},
    {client:'10.0.0.5',host:'example.com',url:'http://example.com/a',status:200}]){
    const hosts=runSuite(mod,[fields]).filter(c=>c.target==='hostname');
    assert.equal(hosts.length===1&&hosts[0].confidence==='REVIEW'&&!hosts[0].safeForBulk,true,
      'host field without request words '+JSON.stringify(fields));
  }
  assert.equal(runSuite(mod,[{host:'fw01',url:'/admin',action:'login'}]).find(c=>c.source==='host')?.safeForBulk,true,
    'host field beside a path, which is not a web URL');
  // A URL of another host says nothing about the host beside it; the host of request events is confirmed only by
  // another record family that carries the same value; one event with an unusual method confirms nothing.
  assert.equal(runSuite(mod,[{client_ip:'192.0.2.70',action:'deny',host_name:'edge-01',url:'https://shop.example.invalid/login'}])
    .find(c=>c.source==='host_name')?.safeForBulk,true,'device host beside a web URL of another host');
  const hostOf=events=>runSuite(mod,events).find(c=>c.source==='host');
  assert.equal(hostOf([{method:'GET',host:'a.example',uri:'/'},{method:'-',host:'a.example',uri:'/'}])?.confidence,'REVIEW',
    'requested host beside a placeholder method');
  assert.equal(hostOf([{host:'fw01',type:'webfilter',method:'GET',url:'/x'},{host:'fw02',type:'webfilter',method:'GET',url:'/y'},
    {host:'fw01',type:'traffic',action:'allow'}])?.confidence,'REVIEW','one request host that no other record family carries');
  assert.equal(hostOf([{host:'fw01',type:'webfilter',method:'GET',url:'/x'},{host:'fw01',type:'traffic',action:'allow'}])?.safeForBulk,true,
    'device host confirmed by another record family');
  // A literal dotted protocol key is read in the object that holds the port (the body of a Syslog reading).
  const inBody=kv=>({fields:{body:kv},effectiveFormat:'syslog_rfc3164'});
  assert.equal(mod.suggestNormalizationCandidatesFromSuite({events:[
    inBody({'flow.sport':51234,'flow.dport':443,'flow.proto':'tcp'}),inBody({'flow.sport':8,'flow.dport':0,'flow.proto':'icmp'})]},[])
    .find(c=>c.source==='body.flow.sport')?.confidence,'REVIEW','ICMP named by a literal dotted key in a Syslog body');
  assert.deepEqual(runSuite(mod,[]),[],'empty data has no candidates');
}
const variants=[
  ['allow NAT-derived source port',
    'if((target===\'srcport\'||target===\'dstport\')&&sourceHasExcludedPortSegment(source))return null;',
    'if(false)return null;'],
  ['allow vendor false friend',
    'if(incompatibleVendorMeaning(source,target,events))return null;',
    'if(false)return null;'],
  ['pretend no type-compatible observations',
    'const compatibleObserved=informativeValues.filter(result=>',
    'const compatibleObserved=informativeValues.filter(result=>false&&'],
  ['approve a host field of an HTTP request record as the official hostname',
    "const unconfirmedHost=target==='hostname'&&hostNameUnconfirmed(source,events,formats);",
    'const unconfirmedHost=false;'],
  ['approve a host field that lives inside an object of the record',
    'if(!recordLevelSource(local,carrierFormats))return true;',
    ''],
  ['ignore a URL of the record that names the host',
    'if(carriers.some(({host,leaves})=>leaves.some(([,text])=>urlHost(text)===host)))return true;',
    ''],
  ['take any web URL beside a host for a request to that host',
    'leaves.some(([,text])=>urlHost(text)===host)',
    'leaves.some(([,text])=>urlHost(text)!==undefined)'],
  ['take a field called method for an HTTP request whatever its value says',
    'HTTP_METHOD_TOKENS.has(targeted?text.toUpperCase():text)).map(([path])=>path);',
    'text.length>0).map(([path])=>path);'],
  ['approve the requested host when one event carries no known method',
    'return carriers.some(({host,leaves})=>ofRequest(leaves)&&!elsewhere.has(host));',
    'return carriers.length>0&&carriers.every(({leaves})=>requestEvidencePaths(leaves).length>0);'],
  ['let any event of another family confirm the host of a request',
    'ofRequest(leaves)&&!elsewhere.has(host));',
    'ofRequest(leaves)&&elsewhere.size===0);'],
  ['look for the protocol of a literal dotted key at the root of the event only',
    'const containers=new Map<Record<string,unknown>,string>([[holder.container,holder.written]]);',
    "const containers=new Map<Record<string,unknown>,string>([[fields,source.slice(0,source.lastIndexOf('.')+1).toLowerCase()]]);"],
  ['ignore a non-transport protocol beside the port',
    'informative>0&&!nonTransportPort&&!lacksTransportEvidence;',
    'informative>0&&!lacksTransportEvidence;'],
  ['ignore complete event evidence',
    'compatibleObserved===informative&&(values.length===events.length||namedAsTarget)&&',
    'compatibleObserved===informative&&'],
  ['approve every sparse source',
    'const namedAsTarget=SPARSE_SAFE_TARGETS.has(target)&&\n    (leaf.toLowerCase()===target||specDefinedTargets(source,events,readings).includes(target))&&\n    sparseSafeSource(source,target,informativeValues,carrierFormats);',
    'const namedAsTarget=true;'],
  ['approve a sparse source for any official name',
    'const namedAsTarget=SPARSE_SAFE_TARGETS.has(target)&&\n    (leaf.toLowerCase()===target||specDefinedTargets(source,events,readings).includes(target))&&\n    sparseSafeSource(source,target,informativeValues,carrierFormats);',
    'const namedAsTarget=(leaf.toLowerCase()===target||specDefinedTargets(source,events,readings).includes(target))&&\n    sparseSafeSource(source,target,informativeValues,carrierFormats);'],
  ['approve a sparse alias of an endpoint field',
    'const namedAsTarget=SPARSE_SAFE_TARGETS.has(target)&&\n    (leaf.toLowerCase()===target||specDefinedTargets(source,events,readings).includes(target))&&\n    sparseSafeSource(source,target,informativeValues,carrierFormats);',
    'const namedAsTarget=SPARSE_SAFE_TARGETS.has(target)&&sparseSafeSource(source,target,informativeValues,carrierFormats);'],
  ['approve a sparse port without TCP or UDP named by the record',
    'informative>0&&!nonTransportPort&&!lacksTransportEvidence;',
    'informative>0&&!nonTransportPort;'],
  ['approve a sparse endpoint inside a nested object or a sparse url of any shape',
    'if(!recordLevelSource(source,formats)||sourceHasExcludedPortSegment(source))return false;',
    'if(false)return false;'],
  ['never approve a sparse official-name endpoint field',
    'const namedAsTarget=SPARSE_SAFE_TARGETS.has(target)&&\n    (leaf.toLowerCase()===target||specDefinedTargets(source,events,readings).includes(target))&&\n    sparseSafeSource(source,target,informativeValues,carrierFormats);',
    'const namedAsTarget=false;'],
  ['ignore abnormal port protocol',
    'const nonTransportPort=!explicitPort&&(target===\'srcport\'||target===\'dstport\')&&',
    'const nonTransportPort=false&&(target===\'srcport\'||target===\'dstport\')&&'],
  ['ignore existing destination collisions',
    'if(existing.some(rule=>rule.id!==current?.id&&overlaps(rule.target,target)))return null;',
    'if(false)return null;'],
  ['allow manual owner edits to auto-promote',
    'safeForBulk:high&&(!current||replaceIsGenerated),',
    'safeForBulk:high,'],
  ['declare every candidate high confidence',
    "confidence:high?'HIGH':'REVIEW',method,",
    "confidence:'HIGH',method,"],
  ['never flag competing aliases',
    '.filter(([,candidates])=>candidates.filter(candidate=>candidate.compatibleObserved>0).length>1)',
    '.filter(([,candidates])=>false)'],
  ['bulk-approve competing aliases',
    "?{...candidate,confidence:'REVIEW' as const,safeForBulk:false,",
    "?{...candidate,confidence:'HIGH' as const,safeForBulk:true,"],
  ['ignore suppression of ambiguous targets',
    '?reviewed.filter(candidate=>!ambiguousTargets.has(candidate.target)):reviewed;',
    '?reviewed:reviewed;'],
];
oracle(await load(source));
let killed=0;
for(const [label,anchor,replace] of variants){
  assert.equal(source.split(anchor).length,2,'mutation anchor changed: '+label);
  const mod=await load(source.replace(anchor,replace));
  let detected=false;
  try{oracle(mod);}catch(error){
    if(error instanceof assert.AssertionError)detected=true;
    else throw error;
  }
  assert.equal(detected,true,'SEMANTIC_MUTANT_SURVIVED '+label);
  killed++;
}
console.log('MCV2_SEMANTIC_CANDIDATE_MUTATION_PASS killed='+killed+'/'+variants.length+
  ' selected source mutations; not comprehensive AST coverage');
