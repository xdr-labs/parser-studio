/**
 * Narrow, deterministic SOURCE mutation probes for the MCV2 decision core.
 * Actual production TypeScript is mutated in memory, transpiled, imported in
 * isolation, and evaluated against independent negative/positive oracles.
 * The working tree is NEVER changed. This is NOT a comprehensive Stryker
 * mutation score for the repository; the scope is explicitly 10 chosen faults.
 */
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import ts from 'typescript';

const base={
  names:readFileSync('src/guided/vendorFieldNames.ts','utf8'),
  ports:readFileSync('src/guided/sourcePortPolicy.ts','utf8'),
};
const policy=JSON.parse(readFileSync('runtime/multipass/semantic-policy.v1.json','utf8'));

async function load(kind,source){
  if(kind==='ports'){
    const expected="import policy from '../../runtime/multipass/semantic-policy.v1.json';";
    assert.equal(source.split(expected).length,2,'policy source import must be exact');
    source=source.replace(expected,`const policy=${JSON.stringify(policy)};`);
  }
  const transpiled=ts.transpileModule(source,{fileName:kind+'.ts',reportDiagnostics:true,
    compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext}});
  const errors=transpiled.diagnostics?.filter(d=>d.category===ts.DiagnosticCategory.Error)??[];
  assert.equal(errors.length,0,'mutant must compile; syntax-invalid mutants are not counted');
  return import('data:text/javascript;base64,'+Buffer.from(transpiled.outputText).toString('base64'));
}
const overlap=(a,b)=>a===b||a.startsWith(b+'.')||b.startsWith(a+'.');
function assertNames(mod){
  const inputs=['src.ip','dst.ip','meta.src'];
  const plan=mod.planVendorFieldNames(inputs);
  assert.equal(plan.names.size,inputs.length,'a source field disappeared');
  const outputs=[...plan.names.values()];
  for(let i=0;i<outputs.length;i++)for(let j=i+1;j<outputs.length;j++)
    assert.equal(overlap(outputs[i],outputs[j]),false,'conflicting normalized targets');
  assert.deepEqual(plan.unresolved,[]);
  const duplicate=['syslog_sd.element_1.params.source-port',
    'syslog_sd.element_2.params.source-port'];
  const dupe=mod.planVendorFieldNames(duplicate);
  for(const source of duplicate)assert.equal(dupe.names.get(source),source,
    'unambiguous full path must be preferred for competing source leaves');
  const occupied=mod.planVendorFieldNames(['http.status'],['status','http.status']);
  assert.equal(occupied.names.size,0,'occupied target collision');
  assert.deepEqual(occupied.unresolved,['http.status'],'unresolved must be explicit');
  const three=mod.planVendorFieldNames(['one.a','two.b','three.c']);
  assert.equal(three.names.size,3,'bounded capacity must not drop modest inputs');
  assert.equal(mod.planVendorFieldNames(['__proto__.danger']).names.size,0,
    'dangerous source path must be rejected');
  const manual={id:'auto-1',source:'http.status',target:'http.status',type:'string',
    authoring:{version:1,origin:'USER_EDITED'}};
  assert.deepEqual(mod.compactLegacyAutoVendorMappings([manual],{'auto-1':'vendor_fields'}),
    [manual],'manual destination was overwritten');
}
function assertPorts(mod){
  const blocked=['nat.source-port','nat_source.source-port','post_nat.source-port',
    'translated_source.source-port','postNat.source-port','sourceTranslation.source-port'];
  for(const source of blocked){
    assert.equal(mod.sourceHasExcludedPortSegment(source),true,'NAT identity '+source);
    assert.equal(mod.explicitPortSourceAlias(source,'srcport'),false,
      'translated value promoted to original source port: '+source);
  }
  for(const source of ['source-port','syslog_sd.element_1.params.source-port','national.source-port']){
    assert.equal(mod.explicitPortSourceAlias(source,'srcport'),true,
      'a valid explicit original source port was rejected: '+source);
  }
}
const mutations=[
  ['names','ignore occupied destination',
    'if(occupied.some(other=>overlaps(candidates[i]![mode],other)))forbid(i,mode);',
    'if(false)forbid(i,mode);'],
  ['names','skip inter-source overlap constraint',
    'if(!overlaps(candidates[i]![a],candidates[j]![b]))continue;',
    'if(true)continue;'],
  ['names','claim impossible allocation was complete',
    'if(!result)return {names:new Map(),unresolved:inputs};',
    'if(!result)return {names:new Map(),unresolved:[]};'],
  ['names','remove repeated-leaf full-path preference',
    'if(strictDuplicateLeaves&&leafCounts.get(candidates[i]![1])!>1){',
    'if(false){'],
  ['names','overwrite user edits by trusting an auto-like target',
    "mapping.authoring?.origin==='AUTO'&&",
    'true&&'],
  ['names','shrink safety budget below normal field counts',
    'if(n>256)return {names:new Map(),unresolved:inputs};',
    'if(n>2)return {names:new Map(),unresolved:inputs};'],
  ['names','disable forbidden prototype path check',
    '!UNSAFE_SEGMENTS.has(part)',
    'true'],
  ['ports','permit post-translation original port aliases',
    '!sourceHasExcludedPortSegment(source)&&leaf!==undefined&&',
    'leaf!==undefined&&'],
  ['ports','ignore mixed-case NAT token boundaries',
    "segment.replace(/([a-z0-9])([A-Z])/g,'$1_$2').toLowerCase()",
    'segment.toLowerCase()'],
  ['ports','ignore underscore NAT tokenization',
    'return words.some(word=>TRANSLATED.has(word));',
    'return false;'],
  ['ports','reject every valid original source port',
    '!sourceHasExcludedPortSegment(source)&&leaf!==undefined&&',
    'false&&!sourceHasExcludedPortSegment(source)&&leaf!==undefined&&'],
];

await assertNames(await load('names',base.names));
await assertPorts(await load('ports',base.ports));
let killed=0;
for(const [kind,label,needle,replacement] of mutations){
  const source=base[kind];
  assert.equal(source.split(needle).length,2,'mutation anchor lost: '+label);
  const mod=await load(kind,source.replace(needle,replacement));
  let detected=false;
  try{
    if(kind==='names')assertNames(mod);else assertPorts(mod);
  }catch(error){
    if(error instanceof assert.AssertionError)detected=true;
    else throw error;
  }
  assert.equal(detected,true,'surviving production mutant: '+label);
  killed++;
}
console.log('MCV2_MUTATION_SENSITIVITY_PASS killed='+killed+'/'+mutations.length+
  ' selected source faults; NOT a full repository mutation score');
