/**
 * Source-level mutation sensitivity of the MappingPlan orchestrator. The
 * production module and its real dependency graph are bundled for each
 * independent faulty variant. No source files or caches are modified.
 * Mutants here are hand-selected semantic mutations, not an exhaustive
 * mutation-score assertion for every mapping package statement.
 */
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import * as esbuild from 'esbuild';
const file='src/guided/canonicalMappingPlan.ts';
const canonical=readFileSync(file,'utf8');
async function load(source){
  const out=await esbuild.build({entryPoints:[file],bundle:true,platform:'node',format:'esm',
    write:false,logLevel:'silent',plugins:[{name:'mcv2-mutation',setup(build){
      build.onLoad({filter:/canonicalMappingPlan\.ts$/},()=>({contents:source,loader:'ts'}));
    }}]});
  return import('data:text/javascript;base64,'+Buffer.from(out.outputFiles[0].text).toString('base64'));
}
const draft=(mappings=[],groups={})=>({name:'Test',vendor:'Test',version:'1.0',
  format:'json',mappings,guided:{groups,classification:{defaultIndex:'Syslog',rules:[]}}});
const suite=(fields)=>({events:[{fields}],counts:{total:1,matched:1,extracted:1,normalized:1,
  failures:0,warnings:0},engine:'browser-preview',nativeFluentdVerified:false,
  stellarExportVerified:false});
function entry(plan,source){
  const found=plan.entries.filter(row=>row.source===source);
  assert.equal(found.length,1,'one decision per source: '+source);
  return found[0];
}
function check(mod){
  const m=mod.createCanonicalMappingPlan;
  assert.equal(typeof m,'function');
  const raw={src_ip:'192.0.2.1','source-port':'594',
    post_nat:{'source-port':'4411'},vendor:{reason:'SECRET_ALPHA'}};
  const all=m(suite(raw),draft());
  assert.equal(all.contract,'parser-studio.mapping-plan.v1');
  assert.deepEqual(all.entries.map(e=>e.source).sort(),[
    'post_nat.source-port','source-port','src_ip','vendor.reason'].sort());
  assert.equal(all.sourceCount,4);
  assert.equal(all.mappedCount,0);
  assert.equal(all.unresolvedCount,0);
  assert.equal(entry(all,'src_ip').disposition,'SUGGESTED_OFFICIAL');
  assert.equal(entry(all,'src_ip').target,'srcip');
  assert.equal(entry(all,'source-port').disposition,'SUGGESTED_OFFICIAL');
  assert.equal(entry(all,'source-port').target,'srcport');
  assert.equal(entry(all,'src_ip').origin,'REVIEW_REQUIRED');
  assert.deepEqual(entry(all,'src_ip').reviewReasons,[]);
  assert.equal(entry(all,'src_ip').evidence?.catalogVerified,true);
  assert.equal(entry(all,'post_nat.source-port').disposition,'SUGGESTED_VENDOR');
  assert.notEqual(entry(all,'post_nat.source-port').target,'srcport');
  assert.equal(entry(all,'vendor.reason').disposition,'SUGGESTED_VENDOR');
  assert.equal(JSON.stringify(all).includes('SECRET_ALPHA'),false,'never send raw value in plan');
  assert.equal(all.vendorSuggestions.some(x=>x.source==='vendor.reason'),true);
  assert.equal(all.officialCandidates.some(x=>x.source==='post_nat.source-port'),false);
  const edited={id:'auto-1',source:'http.status',target:'owner.status',type:'string',
    authoring:{version:1,origin:'USER_EDITED'}};
  const manual=m(suite({http:{status:200}}),draft([edited],{'auto-1':'vendor_fields'}));
  assert.equal(manual.sourceCount,1);
  assert.equal(manual.mappedCount,1);
  assert.equal(entry(manual,'http.status').target,'owner.status');
  assert.equal(entry(manual,'http.status').disposition,'MAPPED');
  assert.equal(entry(manual,'http.status').origin,'USER_EDITED');
  assert.equal(entry(manual,'http.status').mappingId,'auto-1');
  assert.equal(entry(manual,'http.status').group,'vendor_fields');
  const legacy=m(suite({http:{status:200}}),draft([{...edited,authoring:undefined}],{'auto-1':'vendor_fields'}));
  assert.equal(entry(legacy,'http.status').origin,'LEGACY_UNKNOWN');
  const duplicate=m(suite({http:{status:200}}),draft([
    {id:'m1',source:'http.status',target:'status_one',type:'string'},
    {id:'m2',source:'http.status',target:'status_two',type:'string'},
  ],{m1:'vendor_fields',m2:'vendor_fields'}));
  assert.equal(entry(duplicate,'http.status').disposition,'REVIEW_REQUIRED');
  assert.equal(entry(duplicate,'http.status').reviewReasons.includes('TARGET_COLLISION'),true);
  const conflicting=m(suite({http:{status:403}}),draft([
    {id:'old-one',source:'old-a',target:'status',type:'string'},
    {id:'old-two',source:'old-b',target:'http.status',type:'string'},
  ],{'old-one':'vendor_fields','old-two':'vendor_fields'}));
  assert.equal(entry(conflicting,'http.status').disposition,'REVIEW_REQUIRED');
  assert.equal(conflicting.unresolvedCount,1);
  const wrongType=m(suite({src_ip:'not-an-ip'}),draft([
    {id:'wrong',source:'src_ip',target:'srcip',type:'ip'},
  ],{wrong:'top_fields'}));
  assert.equal(entry(wrongType,'src_ip').disposition,'REVIEW_REQUIRED');
  assert.equal(entry(wrongType,'src_ip').reviewReasons.includes('TYPE_ERROR'),true);
  const verified=m(suite({src_ip:'192.0.2.44'}),draft([
    {id:'valid',source:'src_ip',target:'srcip',type:'ip'},
  ],{valid:'top_fields'}));
  assert.equal(entry(verified,'src_ip').group,'top_fields');
  const occupied=m(suite({src_ip:'192.0.2.2'}),draft([
    {id:'existing',source:'old',target:'srcip',type:'ip'},
  ],{existing:'top_fields'}));
  assert.notEqual(entry(occupied,'src_ip').disposition,'SUGGESTED_OFFICIAL');
  assert.equal(entry(occupied,'src_ip').reviewReasons.includes('EXISTING_TARGET_CONFLICT'),true);
  // Both ancestor and descendant target collisions must be recognized, not
  // only exact string identity; these are independent negative cases.
  const ancestor=m(suite({host:{ip:'192.0.2.7'}}),draft([
    {id:'parent',source:'old',target:'host',type:'string'},
  ],{parent:'vendor_fields'}));
  assert.equal(entry(ancestor,'host.ip').reviewReasons.includes('EXISTING_TARGET_CONFLICT'),true);
  const descendant=m(suite({src_ip:'192.0.2.8'}),draft([
    {id:'child',source:'old',target:'srcip.child',type:'string'},
  ],{child:'vendor_fields'}));
  assert.equal(entry(descendant,'src_ip').reviewReasons.includes('EXISTING_TARGET_CONFLICT'),true);
  const invalid=m(suite({src_ip:'invalid-ip'}),draft());
  assert.notEqual(entry(invalid,'src_ip').disposition,'SUGGESTED_OFFICIAL');
  assert.equal(entry(invalid,'src_ip').reviewReasons.includes('CATALOG_AMBIGUITY'),true);
  const nested=m(suite({headers:[{name:'Agent',value:'SECRET_BETA'}],action:'deny'}),draft());
  assert.equal(nested.unaddressableValues>0,true);
  // A bounded 100-field suggestion cap must be recorded as an unresolved
  // decision rather than pretending all wide vendor paths were mapped.
  const wide=m({events:[{fields:Object.fromEntries(Array.from({length:100},(_,i)=>[
    'vendor_'+String(i).padStart(3,'0'),String(i)]))},
    {fields:Object.fromEntries(Array.from({length:22},(_,i)=>[
    'alt_'+String(i).padStart(3,'0'),String(i)]))}]},draft());
  assert.equal(wide.sourceCount,122);
  assert.equal(wide.unresolvedCount,22);
  assert.equal(wide.entries.filter(e=>e.reviewReasons.includes('SUGGESTION_BUDGET')).length,22);
  // >1,024 eligible official source paths have no safe partial catalog scan.
  const many={events:Array.from({length:11},(_,event)=>({fields:Object.fromEntries(
    Array.from({length:100},(_,i)=>['namespace_'+event+'_'+i,{srcip:'192.0.2.1'}]))}))};
  const over=m(many,draft());
  assert.equal(over.sourceCount,1100);
  assert.equal(over.entries.every(e=>e.reviewReasons.includes('OFFICIAL_SCAN_LIMIT')),true);
  assert.equal(over.officialCandidates.length,0);
  assert.equal(JSON.stringify(nested).includes('SECRET_BETA'),false);
  const empty=m({events:[]},draft());
  assert.equal(empty.sourceCount,0);
  assert.equal(empty.entries.length,0);
}
const mutations=[
  ['discard extracted source census','paths.add(source);','void source;'],
  ['report source count as zero','sourceCount:entries.length','sourceCount:0'],
  ['pretend existing mappings do not exist','if(mapped.length){','if(false){'],
  ['ignore duplicate source-mapping detection','if(mapped.length>1)codes.push(\'TARGET_COLLISION\');','if(false)codes.push(\'TARGET_COLLISION\');'],
  ['lose user edit origin','rule.authoring?.version===1?rule.authoring.origin:\'LEGACY_UNKNOWN\'','\'AUTO\''],
  ['misclassify valid mapped field as review','?\'REVIEW_REQUIRED\':\'MAPPED\'','?\'REVIEW_REQUIRED\':\'REVIEW_REQUIRED\''],
  ['replace mapped target','target:mapping.target','target:source'],
  ['wipe mapping id','mappingId:mapping.id','mappingId:undefined'],
  ['ignore official candidate map','official.set(candidate.source,candidate);','void candidate;'],
  ['ignore vendor fallback candidates','const vendor=new Map(proposed.suggestions.map(item=>[item.source,item]));','const vendor=new Map();'],
  ['ignore occupied normalized destination','const collision=Boolean(evidenceCandidate&&occupied.some(target=>','const collision=Boolean(false&&occupied.some(target=>'],
  ['do not record occupied normalized destination','if(collision)reviewReasons.push(\'EXISTING_TARGET_CONFLICT\');','if(false)reviewReasons.push(\'EXISTING_TARGET_CONFLICT\');'],
  // Candidate safeForBulk is itself only true for high-confidence compatible
  // values. Mutating the redundant confidence/predicate terms would be
  // observationally equivalent, so select independent executable decisions.
  ['discard actual mapped value-type validation',
    'const errors=reviewNormalizationMappings(suite,draft.mappings,groups).findings;',
    'const errors=[];'],
  ['forget explicit source group assignments',
    'const groups=draft.guided?.groups??{};',
    'const groups={};'],
  ['hide collision evidence from suppressed official candidates',
    'const diagnosticOfficial=occupied.length',
    'const diagnosticOfficial=false'],
  ['pretend official catalog suggestion is vendor-only','disposition:\'SUGGESTED_OFFICIAL\' as const','disposition:\'SUGGESTED_VENDOR\' as const'],
  ['pretend vendor-only key is verified official','disposition:\'SUGGESTED_VENDOR\' as const','disposition:\'SUGGESTED_OFFICIAL\' as const'],
  ['silently lose vendor fallback','if(suggestion){','if(false){'],
  ['hide ambiguous source semantics','if(!approved&&candidate)reviewReasons.push(\'CATALOG_AMBIGUITY\');','if(false)reviewReasons.push(\'CATALOG_AMBIGUITY\');'],
  ['mask unresolved count','unresolvedCount:entries.filter(entry=>entry.disposition===\'REVIEW_REQUIRED\').length','unresolvedCount:0'],
  ['misrepresent emitted mapped source count','mappedCount,unresolvedCount:','mappedCount:0,unresolvedCount:'],
  ['discard nested unaddressable source census','sum+countUnaddressableSourceValues(event.fields),0','sum+0,0'],
  ['hardcode approved catalog evidence','catalogVerified:candidate!.catalogVerified','catalogVerified:false'],
  ['hide vendor suggestions from UI','vendorSuggestions:proposed.suggestions','vendorSuggestions:[]'],
];
check(await load(canonical));
let killed=0;
const survived=[];
for(const [label,from,to] of mutations){
  assert.equal(canonical.split(from).length,2,'unique source mutation anchor: '+label);
  const source=canonical.replace(from,to);
  let mutant;
  try{mutant=await load(source);}catch(error){throw Error('Invalid/noncompiling mutant '+label+' '+error);}
  let rejected=false;
  try{check(mutant);}catch(error){
    if(error instanceof assert.AssertionError)rejected=true;
    else throw error;
  }
  if(rejected)killed++;else survived.push(label);
}
console.log('MCV2_CANONICAL_MUTATION_PASS '+killed+'/'+mutations.length+
  ' semantically distinct orchestrator mutants killed; selected scope only');
if(survived.length)throw Error('MCV2_SURVIVING_MUTANTS '+JSON.stringify(survived));

// Export the independent oracle for an optional broad AST-based diagnostic
// campaign. Importing this module still executes its required curated gates.
export {check,load};
