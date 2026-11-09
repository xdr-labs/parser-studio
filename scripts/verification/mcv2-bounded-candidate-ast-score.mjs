/**
 * AST-wide source mutation census of normalizationCandidates.ts.
 * Each compiled variant executes in a separate capped child process against
 * a human-specified independent policy oracle, not a production snapshot.
 * Syntax-invalid variants are NEVER counted as killed; unexplained
 * survivors remain visible instead of being silently waived as equivalent.
 */
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {readFileSync} from 'node:fs';
import * as esbuild from 'esbuild';
import ts from 'typescript';
const file='src/guided/normalizationCandidates.ts';
const raw=readFileSync(file,'utf8');
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
  [ts.SyntaxKind.PlusToken,'-'],
]);
const tree=ts.createSourceFile(file,raw,ts.ScriptTarget.Latest,true);
const changes=[];
function walk(node){
  if(ts.isBinaryExpression(node)&&swaps.has(node.operatorToken.kind)){
    const token=node.operatorToken;
    changes.push({start:token.getStart(tree),end:token.getEnd(),
      old:token.getText(tree),next:swaps.get(token.kind),kind:'binary',
      expression:node.getText(tree)});
  }
  if(ts.isIfStatement(node)){
    changes.push({start:node.expression.getStart(tree),end:node.expression.getEnd(),
      old:node.expression.getText(tree),next:'false',kind:'if'});
  }
  if(ts.isConditionalExpression(node)){
    changes.push({start:node.condition.getStart(tree),end:node.condition.getEnd(),
      old:node.condition.getText(tree),next:'false',kind:'ternary'});
  }
  ts.forEachChild(node,walk);
}
walk(tree);
// These operands are documented and exhaustively constrained to nonempty
// strings, arrays, or nonnegative integers. No falsy non-nullish value can
// change the semantic outcome of their nullish-coalescing expression.
const equivalentNullish=new Map([
  ["source.split('.').at(-1)??source",
    'A valid canonical nonempty field path always has a nonempty last segment'],
  ["ALIASES[source.toLowerCase()]??ALIASES[leaf.toLowerCase()]",
    'Alias table values are nonempty official target strings or undefined'],
  ["existingGroups[current.id]??'vendor_fields'",
    'FieldGroup is a nonempty enum string or undefined'],
  ["suite?.events??[]",
    'events is an array (truthy even if empty) or undefined'],
  ["suite?.events.length??0",
    'events.length is a nonnegative integer; both ?? and || return 0 at zero'],
  ["candidatesByTarget.get(candidate.target)??[]",
    'Map values are arrays (truthy even if empty) or undefined'],
]);
if(process.argv.includes('--count')){
  console.log('CANDIDATE_AST_MUTANTS='+changes.length);
  process.exit(0);
}
const start=Number(process.env.MCV2_FROM??0);
const end=Number(process.env.MCV2_TO??changes.length);
assert.ok(Number.isInteger(start)&&Number.isInteger(end)&&
  start>=0&&end<=changes.length&&start<end,'valid bounded AST slice');
async function compile(code){
  try{
    const result=await esbuild.build({entryPoints:[file],bundle:true,
      platform:'node',format:'esm',write:false,logLevel:'silent',plugins:[{
        name:'mcv2-in-memory-candidate-mutant',setup(build){
          build.onLoad({filter:/normalizationCandidates\.ts$/},()=>({
            contents:code,loader:'ts'}));
        },
      }]});
    return {bundle:Buffer.from(result.outputFiles[0].text).toString('base64')};
  }catch(error){return {invalid:true,reason:String(error).slice(0,180)};}
}
function run(bundle){
  const child=spawnSync(process.execPath,['--max-old-space-size=192',
    '--stack_size=768','scripts/verification/mcv2-candidate-independent-oracle.mjs'],{
      input:bundle,timeout:3500,encoding:'utf8',maxBuffer:256*1024});
  return {pass:child.status===0&&child.stdout.includes('INDEPENDENT_ORACLE_PASS'),
    timeout:child.error?.code==='ETIMEDOUT',
    error:(child.stderr||'').slice(-210)};
}
const original=await compile(raw);
assert.ok(!original.invalid,'baseline compilation');
const baseline=run(original.bundle);
assert.ok(baseline.pass,'production fails independent oracle: '+JSON.stringify(baseline));
if(process.argv.includes('--baseline')){console.log('BASELINE_ORACLE_PASS');process.exit(0);}
const result={contract:'parser-studio.mcv2.candidate-ast-census.v1',
  file,globalTotal:changes.length,slice:[start,end],total:end-start,killed:0,survived:0,invalid:0,equivalent:0,timedOut:0,
  survivors:[],equivalentMutants:[],invalidMutants:[]};
for(const change of changes.slice(start,end)){
  assert.equal(raw.slice(change.start,change.end),change.old,'source position');
  const compiled=await compile(raw.slice(0,change.start)+change.next+raw.slice(change.end));
  const line=tree.getLineAndCharacterOfPosition(change.start).line+1;
  if(compiled.invalid){result.invalid++;result.invalidMutants.push({
    line,kind:change.kind,reason:compiled.reason});continue;}
  const outcome=run(compiled.bundle);
  if(!outcome.pass){result.killed++;if(outcome.timeout)result.timedOut++;}
  else if(change.old==='??'&&change.next==='||'&&
    equivalentNullish.has(change.expression)){
    result.equivalent++;
    result.equivalentMutants.push({line,expression:change.expression,
      proof:equivalentNullish.get(change.expression)});
  }else{result.survived++;result.survivors.push({
    line,kind:change.kind,old:change.old.slice(0,75),next:change.next});}
}
const valid=result.killed+result.survived+result.equivalent;
const nonEquivalent=result.killed+result.survived;
result.rawScorePct=valid?Math.round(result.killed*10000/valid)/100:0;
result.nonEquivalentCount=nonEquivalent;
result.nonEquivalentScorePct=nonEquivalent
  ?Math.round(result.killed*10000/nonEquivalent)/100:0;
assert.equal(result.total,result.killed+result.survived+
  result.equivalent+result.invalid,'all AST mutations classified');
console.log(JSON.stringify(result,null,2));
if(process.argv.includes('--require-90')){
  assert.ok(start===0&&end===changes.length,
    'mutation gate must cover the complete module, not a selected slice');
  // A new syntax-invalid variant requires human review; do not exclude it
  // from the denominator by silently interpreting compilation failure as a kill.
  assert.equal(result.invalid,0,'candidate AST mutation compilation invalid');
  assert.equal(result.equivalent,8,'equivalence catalog must be re-reviewed');
  assert.ok(result.nonEquivalentScorePct>=90,
    'independent candidate core mutation effectiveness below 90%');
}
