/**
 * Deterministic AST-wide mutation baseline over the single CanonicalMappingPlan
 * orchestrator module: every binary operator / conditional branch is visited
 * once, not just test-selected anchors. This is a diagnostic score, not the
 * release gate for all decision modules. Compile-invalid variants are counted
 * separately and never inflated into successful mutant kills.
 */
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import ts from 'typescript';
import {check,load} from './mcv2-canonical-mutants.mjs';
const raw=readFileSync('src/guided/canonicalMappingPlan.ts','utf8');
const tree=ts.createSourceFile('canonicalMappingPlan.ts',raw,ts.ScriptTarget.Latest,true);
const swap=new Map([
  [ts.SyntaxKind.EqualsEqualsEqualsToken,'!=='],
  [ts.SyntaxKind.ExclamationEqualsEqualsToken,'==='],
  [ts.SyntaxKind.AmpersandAmpersandToken,'||'],
  [ts.SyntaxKind.BarBarToken,'&&'],
  [ts.SyntaxKind.QuestionQuestionToken,'||'],
  [ts.SyntaxKind.GreaterThanToken,'<='],
  [ts.SyntaxKind.GreaterThanEqualsToken,'<'],
  [ts.SyntaxKind.PlusToken,'-'],
]);
// These six `??` operands can only be a truthy Array, Map result (Array),
// object, non-empty FieldGroup union string, or null/undefined under the
// checked domain contracts. The corresponding `||` mutants are therefore
// equivalent for ALL well-typed inputs; record them without treating them as
// either detected or as missed security defects. No other survivor is waived.
const equivalentNullish=new Set([
  "group??'vendor_fields'",
  'suite?.events??[]',
  'draft.guided?.groups??{}',
  'existingBySource.get(mapping.source)??[]',
  'existingBySource.get(source)??[]',
  'candidate??diagnosticOfficial.get(source)',
]);
const mutants=[];
function traverse(node){
  if(ts.isBinaryExpression(node)&&swap.has(node.operatorToken.kind)){
    const token=node.operatorToken;
    mutants.push({kind:'op',from:token.getStart(tree),until:token.getEnd(),
      original:token.getText(tree),replacement:swap.get(token.kind),
      expression:node.getText(tree),
      line:tree.getLineAndCharacterOfPosition(token.getStart(tree)).line+1});
  }
  if(ts.isIfStatement(node)){
    mutants.push({kind:'branch',from:node.expression.getStart(tree),
      until:node.expression.getEnd(),original:node.expression.getText(tree),
      replacement:'false',line:tree.getLineAndCharacterOfPosition(node.expression.getStart(tree)).line+1});
  }
  ts.forEachChild(node,traverse);
}
traverse(tree);
check(await load(raw));
const stats={total:mutants.length,killed:0,survived:0,invalid:0,equivalent:0};
const survivors=[],invalid=[],equivalent=[];
for(const change of mutants){
  assert.equal(raw.slice(change.from,change.until),change.original);
  const modified=raw.slice(0,change.from)+change.replacement+raw.slice(change.until);
  let mutation;
  try{mutation=await load(modified);}catch(error){
    stats.invalid++;invalid.push({line:change.line,kind:change.kind,error:String(error).slice(0,80)});
    continue;
  }
  let detected=false;
  try{check(mutation);}catch(error){detected=true;}
  if(detected)stats.killed++;
  else if(change.original==='??'&&change.replacement==='||'&&
      equivalentNullish.has(change.expression)){
    stats.equivalent++;
    equivalent.push({line:change.line,expression:change.expression,
      proof:'Truthy nonnullish operand under static contract'});
  }else{stats.survived++;survivors.push({line:change.line,kind:change.kind,
    before:change.original.slice(0,85),after:change.replacement});}
}
const compileValid=stats.killed+stats.survived+stats.equivalent;
const percent=compileValid?Math.round(10000*stats.killed/compileValid)/100:0;
const scored=stats.killed+stats.survived;
const effective= scored?Math.round(10000*stats.killed/scored)/100:0;
const result={contract:'parser-studio.mcv2.ast-mutation-baseline.v1',
  path:'src/guided/canonicalMappingPlan.ts',...stats,compileValid,
  mutationScorePctRaw:percent,nonEquivalentCount:scored,
  mutationScorePctNonEquivalent:effective,survivors,
  equivalentMutants:equivalent,invalidMutants:invalid};
console.log(JSON.stringify(result,null,2));

// On this measured orchestrator scope, every surviving non-equivalent AST
// mutant is a quality regression. Distinguish invalid and equivalent subsets.
assert.equal(stats.total,stats.killed+stats.survived+stats.invalid+stats.equivalent);
assert.equal(stats.survived,0,'A non-equivalent Canonical MappingPlan AST mutant survived');
assert.ok(effective>=90,'Canonical MappingPlan non-equivalent mutation score <90%');
