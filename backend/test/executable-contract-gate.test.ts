import assert from 'node:assert/strict';
import {readFileSync,existsSync} from 'node:fs';
import test from 'node:test';
import {BACKEND_CAPABILITIES} from '../src/capabilities.js';
import {validateProject,validateBoundedRegexPattern} from '../src/validate.js';
import {sampleProject} from './fixture.js';
import {compilePair} from '../src/compiler.js';
import {inspectPair} from '../src/import.js';
import {buildArtifactPackage} from '../src/artifact-package.js';

const read=(path:string)=>readFileSync(new URL('../../'+path,import.meta.url),'utf8');
test('new compiler grammars or removed operators cannot bypass independent execution coverage',()=>{
 const manifest=JSON.parse(read('contracts/execution-coverage.v1.json'));
 assert.deepEqual([...BACKEND_CAPABILITIES.authoring.extractionFormats].sort(),
  [...manifest.extractionFormats].sort(),'Every shipping grammar needs an independent native oracle');
 const truth=JSON.parse(read(manifest.operatorTruth));
 assert.ok(truth.cases.length>=60,'The independently authored boundary corpus was reduced');
 const operations=new Set(truth.cases.flatMap((c:any)=>(c.enrichment??[]).map((e:any)=>e.operator)));
 const types=new Set(truth.cases.flatMap((c:any)=>c.mappings.map((m:any)=>m.type)));
 assert.deepEqual([...operations].sort(),[...manifest.operators].sort());
 assert.deepEqual([...types].sort(),[...manifest.types].sort());
 assert.equal(manifest.nativeMismatchAllowance,0);assert.equal(manifest.nativeSkipAllowance,0);
 for(const key of ['standardGrammarOracle','compoundGrammarOracle','operatorOracle','sourceByteOracle','sourceBoundaryOracle'])
  assert.ok(existsSync(new URL('../../'+manifest[key],import.meta.url)),key+' missing');
 const workflow=read('.github/workflows/quality.yml');
 for(const key of ['operatorOracle','compoundGrammarOracle'])
  assert.ok(workflow.includes('node backend/node_modules/tsx/dist/cli.mjs '+manifest[key]),key+' not mandatory in CI');
 assert.ok(read(manifest.standardGrammarOracle).includes('for(const family of [false,true])'));
});

test('direct backend generation rejects unsupported regex bytes and source-depth contracts',()=>{
 for(const pattern of ['^'+'가'.repeat(90)+'(?<field>x)$',String.raw`(?<field>\xFF)`,
  String.raw`(?<field>\bvalue\b)`,String.raw`(?<field>[a&&b])`,
  '(?<field>'+String.fromCharCode(0xd800)+')']){
  assert.notEqual(validateBoundedRegexPattern(pattern),null);
  const p=sampleProject();p.extraction={format:'regex',pattern};p.classification.rules=[];
  assert.equal(validateProject(p).ok,false);
 }
 const p=sampleProject();p.normalization.topFields={
  'a.b.c.d.e.f.g.h.i':{normalized_name:'message',data_type:'string'},
 };
 p.normalization.nsFields={};p.classification.rules=[];
 assert.equal(validateProject(p).ok,false);
});

test('project import selects its own assignment while independently verifying pinned operator data',()=>{
 const pair=compilePair(sampleProject());
 const fragment=pair.files.find(file=>!file.name.endsWith('.conf'))!;
 const conf=pair.files.find(file=>file.name.endsWith('.conf'))!;
 const payloads=[...fragment.content.matchAll(/Base64\.strict_decode64\('([A-Za-z0-9+/=]+)'\)/g)];
 assert.equal(payloads.length,2,'Project metadata and pinned policy data are distinct payloads');
 const input={name:fragment.name,fragmentContent:fragment.content,confContent:conf.content};
 assert.equal(inspectPair(input).importStatus,'EDITABLE_EXACT');
 assert.ok(buildArtifactPackage(pair,'1.0.0').zip.length>0);
 const original=payloads[1]![1]!;
 const changed=(original[0]==='A'?'B':'A')+original.slice(1);
 assert.equal(inspectPair({...input,fragmentContent:fragment.content.replace(original,changed)})
  .importStatus,'OPAQUE_READ_ONLY','A valid project must not approve modified execution policy');
});
