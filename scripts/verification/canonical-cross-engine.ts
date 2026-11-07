/**
 * Canonical same-source authoring → Ruby differential acceptance.
 * Non-customer synthetic fixtures only; zero network or deployment actions.
 * CLI fails closed if Ruby is missing, and compares normalized fields and
 * error stages, never a DRAFT manifest as proof of native correctness.
 */
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {spawnSync} from 'node:child_process';
import {createDraft} from '../../src/model';
import {preview} from '../../src/parser';
import {analyzeLogEnvelopes,assessEnvelopeCompilation}
  from '../../src/guided/autoParserEnvelope';
import {prepareAutoParserDraft} from '../../src/guided/autoParserDraft';
import {toBackendProject} from '../../src/guided/backendAdapter';
import {compilePair} from '../../backend/src/compiler';

interface PortCase{
  id:string;proto?:string;proto_name?:string;allow:boolean;
}
interface KvCase{
  id:string;trailer:string;quoted:boolean;accept:boolean;
  srcip?:string;internal?:string;
}
interface Corpus{contract:string;portEvidence:PortCase[];kvWhitespace:KvCase[]}
const corpus=JSON.parse(readFileSync(
  new URL('../../contracts/conformance-cases.v1.json',import.meta.url),'utf8')) as Corpus;
assert.equal(corpus.contract,'parser-studio.cross-engine-corpus.v1');
const rubyCheck=spawnSync('ruby',['-v'],{encoding:'utf8',timeout:3000});
assert.equal(rubyCheck.status,0,'A real Ruby runtime is mandatory for differential conformance');
const cap={
  authoring:{extractionFormats:['kv','json'],rfc5424BodyFormats:['raw','kv']},
  verification:{engineVerified:false,targetImportVerified:false},
} as any;
const runner=[
  "require 'json'","require 'base64'","require 'time'","require 'date'",
  "require 'ipaddr'","require 'csv'",
  "input=JSON.parse(STDIN.read)","klass=Class.new",
  "klass.class_eval(Base64.strict_decode64(input.fetch('ruby')),'canonical-harness',1)",
  "parser=klass.new","rows=[]",
  "input.fetch('lines').each{|line|parser.parse(line){|_time,record|rows << record}}",
  "STDOUT.write(JSON.generate(rows))",
].join('\n');
function native(ruby:string,lines:string[]):Array<Record<string,any>>{
  const out=spawnSync('ruby',['-e',runner],{
    encoding:'utf8',timeout:15000,maxBuffer:1024*1024,
    input:JSON.stringify({ruby:Buffer.from(ruby).toString('base64'),lines}),
  });
  assert.equal(out.status,0,out.stderr||String(out.error));
  return JSON.parse(out.stdout);
}
function prepare(raw:string){
  const original=createDraft();
  const ledger=analyzeLogEnvelopes(raw,'single-line');
  const assessment=assessEnvelopeCompilation(ledger,cap);
  assert.equal(assessment.status,'DRAFT_COMPILABLE');
  const draft=prepareAutoParserDraft(raw,original,preview(raw,original),ledger,assessment);
  assert.equal(draft.ok,true,JSON.stringify(draft));
  if(!draft.ok)throw new Error('NO_DRAFT');
  const backend=toBackendProject(draft.draft);
  assert.equal(backend.ok,true,JSON.stringify(backend));
  if(!backend.ok)throw new Error('NO_BACKEND');
  const pair=compilePair(backend.project);
  assert.equal(pair.manifest.status,'DRAFT');
  const source=pair.files.find(x=>!x.name.endsWith('.conf'))!.content;
  return {draft:draft.draft,source,project:backend.project};
}

let verified=0;
for(const item of corpus.portEvidence){
  const raw=(item.proto===undefined?'proto_name='+item.proto_name:'proto='+item.proto)+
    ' srcport=594 dstport=10400 srcip=192.0.2.1 dstip=198.51.100.2';
  const {draft,source}=prepare(raw);
  const browser=preview(raw,draft).events[0]!;
  const row=native(source,[raw])[0]!;
  assert.equal(browser.raw,raw,item.id);
  assert.equal(row.parser_err_stage,undefined,item.id+' '+JSON.stringify(row));
  assert.equal(row.srcip,'192.0.2.1',item.id);
  assert.equal(row.dstip,'198.51.100.2',item.id);
  for(const target of ['srcport','dstport'] as const){
    assert.equal(Object.prototype.hasOwnProperty.call(row,target),item.allow,item.id);
    assert.equal(Object.prototype.hasOwnProperty.call(browser.normalized,target),
      item.allow,item.id);
    if(item.allow){
      assert.equal(row[target],browser.normalized[target],item.id+' '+target);
    }
  }
  verified++;
}
// Reuse the *same approved authoring draft* for adversarial input mutations.
const clean='action=allow srcip=192.0.2.1';
const {draft:typedDraft,source:typedRuby}=prepare(clean);
const inputs=corpus.kvWhitespace.map(x=>
  'action=allow srcip='+(x.quoted?'"'+(x.internal??'192.0.2.1')+'"':'192.0.2.1')+
    x.trailer);
const rows=native(typedRuby,inputs);
assert.equal(rows.length,inputs.length);
for(let i=0;i<inputs.length;i++){
  const item=corpus.kvWhitespace[i]!;
  const raw=inputs[i]!;
  const event=preview(raw,typedDraft).events[0]!;
  const row=rows[i]!;
  assert.equal(event.raw,raw,item.id);
  const stage=item.srcip==='192.0.2.1'?undefined:
    item.quoted&&item.trailer?'extraction':'normalization';
  const browserStage=event.diagnostics.some(d=>d.severity==='error'&&
    d.stage==='extract')?'extraction':
    event.diagnostics.some(d=>d.severity==='error'&&d.stage==='normalize')
      ?'normalization':undefined;
  assert.equal(browserStage,stage,item.id+' browser '+JSON.stringify(event.diagnostics));
  assert.equal(row.parser_err_stage,stage,item.id+' native '+JSON.stringify(row));
  if(stage===undefined){
    assert.equal(row.srcip,event.normalized.srcip,item.id);
    assert.equal(row.srcip,'192.0.2.1',item.id);
  }else{
    assert.equal(row.srcip,undefined,item.id);
    assert.equal(event.normalized.srcip,undefined,item.id);
  }
  verified++;
}
console.log('CANONICAL_CROSS_ENGINE_CONFORMANCE_PASS '+verified+'/'+
  (corpus.portEvidence.length+corpus.kvWhitespace.length)+
  ' exact-source authored Ruby DRAFT cases; no target import claim');
