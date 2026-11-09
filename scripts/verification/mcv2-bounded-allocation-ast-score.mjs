/**
 * Opt-in broad AST census for the source-name allocator and NAT policy.
 * Each mutant runs in its OWN bounded child process, so a corrupt SCC/loop
 * condition cannot hang the test host or CI. Diagnostic only until reviewed.
 * No source file is changed on disk; all test cases are synthetic.
 */
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {readFileSync} from 'node:fs';
import ts from 'typescript';
const policy=JSON.parse(readFileSync('runtime/multipass/semantic-policy.v1.json','utf8'));
const swaps=new Map([
  [ts.SyntaxKind.EqualsEqualsEqualsToken,'!=='],
  [ts.SyntaxKind.ExclamationEqualsEqualsToken,'==='],
  [ts.SyntaxKind.AmpersandAmpersandToken,'||'],
  [ts.SyntaxKind.BarBarToken,'&&'],
  [ts.SyntaxKind.QuestionQuestionToken,'||'],
  [ts.SyntaxKind.GreaterThanToken,'<='],
  [ts.SyntaxKind.GreaterThanEqualsToken,'<'],
  [ts.SyntaxKind.LessThanToken,'>='],
  [ts.SyntaxKind.LessThanEqualsToken,'>'],
]);
const oracle=String.raw`
import assert from 'node:assert/strict';
const mod=await import('data:text/javascript;base64,'+process.argv[1]);
const kind=process.argv[2];
const overlaps=(a,b)=>a===b||a.startsWith(b+'.')||b.startsWith(a+'.');
const available=(s,occupied)=>{
  for(let mask=0;mask<2**s.length;mask++){
    const targets=s.map((p,i)=>(mask&(1<<i))?p.split('.').at(-1):p);
    if(targets.some(t=>occupied.some(o=>overlaps(t,o))))continue;
    if(targets.some((t,i)=>targets.some((u,j)=>i!==j&&overlaps(t,u))))continue;
    return true;
  }
  return false;
};
// Independent enumerative shortest-leaf oracle. For n<=8 it enumerates every
// possible destination assignment, enforces no collisions, prioritizes the
// duplicate-leaf identity rule when feasible and chooses the lexicographically
// first maximum set of leaf aliases. The production solver does not supply
// the expected answer.
const optimal=(sources,occupied)=>{
 const sorted=[...new Set(sources)].sort();
 const counts=new Map();for(const source of sorted){const leaf=source.split('.').at(-1);
   counts.set(leaf,(counts.get(leaf)||0)+1)}
 const choices=[];
 for(let mask=0;mask<2**sorted.length;mask++){
   const targets=sorted.map((source,i)=>(mask&(1<<i))?source.split('.').at(-1):source);
   if(targets.some(target=>occupied.some(x=>overlaps(x,target))))continue;
   if(targets.some((target,i)=>targets.some((other,j)=>i!==j&&overlaps(target,other))))continue;
   const strict=sorted.every((source,i)=>counts.get(source.split('.').at(-1))===1||!(mask&(1<<i)));
   const priority=sorted.map((_,i)=>mask&(1<<i)?1:0).join('');
   choices.push({targets,strict,priority});
 }
 if(!choices.length)return null;
 choices.sort((a,b)=>Number(b.strict)-Number(a.strict)||b.priority.localeCompare(a.priority));
 return new Map(sorted.map((source,i)=>[source,choices[0].targets[i]]));
};
if(kind==='ports'){
 const positive=['source-port','destination-port','national.source-port',
   'syslog_sd.element_1.params.source-port'];
 for(const s of positive){
   const target=s.endsWith('destination-port')?'dstport':'srcport';
   assert.equal(mod.explicitPortSourceAlias(s,target),true,'valid '+s);
   assert.equal(mod.sourceHasExcludedPortSegment(s),false,'false NAT '+s);
 }
 for(const s of ['nat.source-port','nat_source.source-port',
   'post_nat.source-port','translated_source.source-port','postNat.source-port',
   'sourceTranslation.source-port']){
   assert.equal(mod.sourceHasExcludedPortSegment(s),true,'NAT '+s);
   assert.equal(mod.explicitPortSourceAlias(s,'srcport'),false,'no NAT promotion '+s);
 }
}else{
 const duplicates=['a.source-port','b.source-port'];
 const unique=mod.planVendorFieldNames(duplicates);
 assert.equal(unique.names.size,2);
 for(const source of duplicates)assert.equal(unique.names.get(source),source);
 const occupied=mod.planVendorFieldNames(['http.status'],['status','http.status']);
 assert.equal(occupied.names.size,0);
 assert.deepEqual(occupied.unresolved,['http.status']);
 const bad=mod.planVendorFieldNames(['__proto__.attack']);
 assert.equal(bad.names.size,0);
 const manual={id:'auto-1',source:'src.foo',target:'src_foo',type:'string',
   authoring:{version:1,origin:'USER_EDITED'}};
 assert.deepEqual(mod.compactLegacyAutoVendorMappings([manual],{'auto-1':'vendor_fields'}),[manual]);
 const autogen={...manual,authoring:{version:1,origin:'AUTO'}};
 assert.equal(mod.compactLegacyAutoVendorMappings([autogen],{'auto-1':'vendor_fields'})[0].target,'foo');
 // Exercise the independent large-source SCC branch (129..256) and
 // enforce that full-path vs leaf allocation remains collision-free.
 const broad=Array.from({length:129},(_,i)=>'root_'+i+'.leaf_'+i);
 const many=mod.planVendorFieldNames(broad);
 assert.equal(many.names.size,129,'129-source allocation');
 for(let i=0;i<129;i++)assert.equal(many.names.get(broad[i]),'leaf_'+i,'large-source leaf '+i);
 const largeBlocked=mod.planVendorFieldNames(broad,['leaf_0']);
 assert.equal(largeBlocked.names.size,129);
 assert.equal(largeBlocked.names.get(broad[0]),broad[0],
   'occupied large-source leaf preserves original full source path');
 // A unique leaf must not become a parent of another still-full path.
 const connected=['a.b','b.c',...Array.from({length:127},(_,i)=>'filler_'+i+'.value_'+i)];
 const connectedPlan=mod.planVendorFieldNames(connected,['c']);
 assert.equal(connectedPlan.names.size,connected.length);
 assert.equal(connectedPlan.names.get('b.c'),'b.c');
 assert.equal(connectedPlan.names.get('a.b'),'a.b');
 const targets=[...connectedPlan.names.values()];
 for(let i=0;i<targets.length;i++)for(let j=i+1;j<targets.length;j++)
   assert.equal(overlaps(targets[i],targets[j]),false,'129-source path boundary');
 const duplicates129=Array.from({length:129},(_,i)=>'root_'+i+'.same');
 const largeDupe=mod.planVendorFieldNames(duplicates129);
 assert.equal(largeDupe.names.size,129);
 for(const source of duplicates129)assert.equal(largeDupe.names.get(source),source,
   'ambiguous large-source leaf must preserve full path');
 // A manual rule may share a source with an auto mapping. The identity is
 // the rule ID, never its name or the presence of a same-source allocation.
 const autoDup={id:'auto-duplicate',source:'src.foo',target:'src_foo',type:'string',
   authoring:{version:1,origin:'AUTO'}};
 const manualDup={id:'manual-duplicate',source:'src.foo',target:'manual_field',type:'string',
   authoring:{version:1,origin:'USER_EDITED'}};
 const both=mod.compactLegacyAutoVendorMappings([autoDup,manualDup],
   {'auto-duplicate':'vendor_fields','manual-duplicate':'vendor_fields'});
 assert.deepEqual(both[1],manualDup,'manual mapping must not be overwritten');
 const untouched={id:'auto-stable',source:'action',target:'action',type:'string',
   authoring:{version:1,origin:'AUTO'}};
 const duplicateGenerated=[
   {id:'auto-dup-1',source:'src.foo',target:'src_foo',type:'string',authoring:{version:1,origin:'AUTO'}},
   {id:'auto-dup-2',source:'src.foo',target:'src_foo',type:'string',authoring:{version:1,origin:'AUTO'}},
 ];
 assert.strictEqual(mod.compactLegacyAutoVendorMappings(duplicateGenerated,
   {'auto-dup-1':'vendor_fields','auto-dup-2':'vendor_fields'}),duplicateGenerated,
   'nonunique generated source must not compact into duplicate target');
 const stable=[untouched];
 assert.strictEqual(mod.compactLegacyAutoVendorMappings(stable,
   {'auto-stable':'vendor_fields'}),stable,'idempotent mapping must preserve reference');
 const authored={id:'auto-original',source:'src.foo',target:'src.foo',type:'string',
   authoring:{version:1,origin:'AUTO'}};
 assert.equal(mod.compactLegacyAutoVendorMappings([authored],
   {'auto-original':'vendor_fields'})[0].target,'foo',
   'old exact full-path target must be compacted');
 const tooMany=Array.from({length:257},(_,i)=>'field_'+i);
 assert.equal(mod.planVendorFieldNames(tooMany).names.size,0);
 assert.equal(mod.planVendorFieldNames(tooMany).unresolved.length,257);
 let state=1;
 function random(){state^=state<<13;state^=state>>>17;state^=state<<5;return state>>>0;}
 const fragments=['a','b','c','src','dst','meta','ip'];
 for(let seed=1;seed<=48;seed++){
   const n=2+random()%6,fields=new Set();
   while(fields.size<n){const a=fragments[random()%fragments.length],b=fragments[random()%fragments.length];
      fields.add(random()%3===0?a:a+'.'+b);}
   const source=[...fields],blocked=seed%3===0?[source[random()%source.length]]:[];
   const possible=available(source,blocked);
   const expected=optimal(source,blocked);
   const p=mod.planVendorFieldNames(source,blocked);
   if(!expected)assert.equal(p.names.size,0,'enumerated impossible allocation '+seed);
   else assert.deepEqual([...p.names].sort(),[...expected].sort(),
     'lexicographically preferred minimal assignment '+seed);
   const reversed=mod.planVendorFieldNames([...source].reverse(),blocked);
   assert.deepEqual([...p.names].sort(),[...reversed.names].sort(),'determinism '+seed);
   assert.deepEqual(p.unresolved,reversed.unresolved,'unresolved determinism '+seed);
   if(!possible){assert.equal(p.names.size,0,'fail closed '+seed);continue;}
   assert.equal(p.names.size,source.length,'account all '+seed);
   assert.deepEqual(p.unresolved,[],'no loss '+seed);
   const targets=[...p.names.values()];
   for(let i=0;i<targets.length;i++){
      assert.equal(blocked.some(o=>overlaps(targets[i],o)),false,'occupied '+seed);
      for(let j=i+1;j<targets.length;j++)assert.equal(overlaps(targets[i],targets[j]),false,'collision '+seed);
   }
 }
}
console.log('ORACLE_PASS');
`;
function run(kind,code){
 const result=ts.transpileModule(code,{fileName:kind+'.ts',reportDiagnostics:true,
   compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext}});
 const parseErrors=(result.diagnostics||[]).filter(d=>d.category===ts.DiagnosticCategory.Error);
 if(parseErrors.length)return {pass:false,invalid:true,timeout:false,status:null,
   error:'Typescript transpilation syntax error'};
 const child=spawnSync(process.execPath,['--max-old-space-size=128','--stack_size=512',
   '--input-type=module','-e',oracle,Buffer.from(result.outputText).toString('base64'),kind],{
   timeout:2000,encoding:'utf8',maxBuffer:256*1024});
 return {pass:child.status===0&&child.stdout.includes('ORACLE_PASS'),
   timeout:child.error?.code==='ETIMEDOUT',status:child.status,
   error:(child.stderr||'').slice(-180)};
}
const outcomes=[];
for(const [kind,file] of [['names','src/guided/vendorFieldNames.ts'],
                         ['ports','src/guided/sourcePortPolicy.ts']]){
 const raw=readFileSync(file,'utf8');
 const prep=s=>kind==='ports'?s.replace(
   "import policy from '../../runtime/multipass/semantic-policy.v1.json';",
   `const policy=${JSON.stringify(policy)};`):s;
 assert.ok(run(kind,prep(raw)).pass,'production baseline fails independent oracle: '+kind);
 const tree=ts.createSourceFile(file,raw,ts.ScriptTarget.Latest,true);
 const changes=[];
 function walk(n){
   if(ts.isBinaryExpression(n)&&swaps.has(n.operatorToken.kind)){
     const t=n.operatorToken;
     changes.push({start:t.getStart(tree),end:t.getEnd(),old:t.getText(tree),
       next:swaps.get(t.kind),line:tree.getLineAndCharacterOfPosition(t.getStart(tree)).line+1});
   }
   if(ts.isIfStatement(n))changes.push({start:n.expression.getStart(tree),
     end:n.expression.getEnd(),old:n.expression.getText(tree),next:'false',
     line:tree.getLineAndCharacterOfPosition(n.expression.getStart(tree)).line+1});
   ts.forEachChild(n,walk);
 }
 walk(tree);
 let killed=0,survived=0,timedOut=0,invalid=0;
 const missing=[];
 for(const change of changes){
   assert.equal(raw.slice(change.start,change.end),change.old);
   const fault=raw.slice(0,change.start)+change.next+raw.slice(change.end);
   const r=run(kind,prep(fault));
   if(r.invalid){invalid++;continue;}
   if(!r.pass){killed++;if(r.timeout)timedOut++;}
   else{survived++;missing.push({line:change.line,old:change.old.slice(0,50),next:change.next});}
 }
 const rawScorePct=Math.round(killed/(killed+survived)*10000)/100;
 outcomes.push({kind,total:changes.length,killed,survived,invalid,timedOut,
   rawScorePct,missing});
 assert.equal(changes.length,killed+survived+invalid,'Every AST change is accounted for');
 assert.ok(rawScorePct>=90,'MCV2 non-equivalent candidate baseline below 90% for '+kind);
}
console.log(JSON.stringify({contract:'parser-studio.mcv2.bounded-ast-diagnostic.v1',outcomes},null,2));
