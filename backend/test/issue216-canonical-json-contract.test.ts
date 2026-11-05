import assert from 'node:assert/strict';
import test from 'node:test';
import {canonicalJson,validateProject} from '../src/validate.js';
import {compilePair,inspectPair} from '../src/index.js';
import {sampleProject} from './fixture.js';

const invalidCases=[
  ['own optional productVersion', (p:Record<string,any>)=>{p.productVersion=undefined;}],
  ['own optional receiver delimiter', (p:Record<string,any>)=>{p.receiver.delimiter=undefined;}],
  ['own optional event profile', (p:Record<string,any>)=>{p.normalization.eventProfiles=undefined;}],
  ['nested field rule option', (p:Record<string,any>)=>{p.normalization.topFields.action.source_path_kind=undefined;}],
  ['own optional omit flag', (p:Record<string,any>)=>{p.extraction.omitSourceRaw=undefined;}],
] as const;

for(const [name,apply] of invalidCases){
  test('Issue #216 rejects non-JSON '+name+' before DRAFT generation',()=>{
    const p=sampleProject() as unknown as Record<string,any>;
    apply(p);
    assert.throws(()=>canonicalJson(p),/Non-JSON project value/);
    const checked=validateProject(p);
    assert.equal(checked.ok,false,name);
    assert.equal(checked.issues[0]?.code,'invalid_input',name);
    assert.throws(()=>compilePair(p),/Invalid parser project/,name);
  });
}

test('Issue #216 rejects nonfinite and sparse array inputs at the canonical boundary',()=>{
  for(const value of [undefined,NaN,Infinity,-Infinity,BigInt(1),[1,undefined],[1,,3]]){
    assert.throws(()=>canonicalJson(value));
  }
});

test('Issue #216 JSON-safe project remains exact through compile, inspect and recompile',()=>{
  const p=sampleProject();
  const encoded=canonicalJson(p);
  assert.deepEqual(JSON.parse(encoded),p);
  assert.equal(validateProject(p).ok,true);
  const pair=compilePair(p);
  const ruby=pair.files.find(file=>!file.name.endsWith('.conf'))!.content;
  const base64=/Base64\.strict_decode64\('([A-Za-z0-9+/=]+)'\)/.exec(ruby)?.[1];
  assert.ok(base64);
  assert.deepEqual(JSON.parse(Buffer.from(base64,'base64').toString('utf8')),p);
  const checked=inspectPair({
    name:'customized_sample_firewall',
    confContent:pair.files[0]!.content,
    fragmentContent:pair.files[1]!.content,
  });
  assert.equal(checked.importStatus,'EDITABLE_EXACT');
  assert.equal(checked.roundTripVerified,true);
  assert.ok(checked.portableProject);
  const second=compilePair(checked.portableProject);
  assert.deepEqual(second.files.map(file=>file.sha256),pair.files.map(file=>file.sha256));
});