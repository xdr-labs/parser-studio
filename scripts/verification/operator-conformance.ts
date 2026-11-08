/** Required same-source browser -> authoring -> exact native fragment matrix.
 * Fixed synthetic fixtures only; the console receipt contains counts/hashes. */
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {OPERATOR_GOLDENS,OPERATOR_MATRIX_CONTRACT,operatorGoldenFixture,expectedWireRecord}
 from '../../contracts/operator-conformance';
import {preview} from '../../src/parser';
import {toBackendProject} from '../../src/guided/backendAdapter';
import {validateProject} from '../../backend/src/validate';
import {compilePair} from '../../backend/src/compiler';

assert.equal(spawnSync('ruby',['-v'],{timeout:3000}).status,0,
 'Native execution is mandatory; absence cannot become a passing skip');
const harness=[
 "require 'json'","require 'base64'","require 'date'","require 'time'","require 'ipaddr'","require 'csv'",
 "input=JSON.parse(STDIN.read)","klass=Class.new",
 "klass.class_eval(Base64.strict_decode64(input.fetch('ruby')).force_encoding('UTF-8'))",
 "parser=klass.new","rows=[]",
 "input.fetch('lines').each{|line|parser.parse(line){|_time,record|rows << record}}",
 "STDOUT.write(JSON.generate(rows))",
].join('\n');
let compiled=0,rejected=0,records=0;
const hashes:string[]=[];
for(const item of OPERATOR_GOLDENS){
 for(const family of item.format==='regex'?[false]:[false,true]){
  const {draft,raw,expected}=operatorGoldenFixture(item,family);
  const id=item.id+(family?' family':' ordinary');
  const adapted=toBackendProject(draft);
  if(item.rejected){assert.equal(adapted.ok,false,id);rejected++;continue;}
  assert.equal(adapted.ok,true,id);if(!adapted.ok)throw new Error(id);
  assert.equal(validateProject(adapted.project).ok,true,id);
  const browser=preview(raw,draft).events[0]!;
  assert.equal(browser.raw,raw,id);
  assert.deepEqual(browser.normalized,expected,id+' independent browser truth');
  assert.equal(browser.diagnostics.some(d=>d.severity==='error'),Boolean(item.stage),id);
  const pair=compilePair(adapted.project);
  assert.equal(pair.manifest.status,'DRAFT');
  const ruby=pair.files.find(f=>!f.name.endsWith('.conf'))!;
  hashes.push(ruby.sha256,pair.files.find(f=>f.name.endsWith('.conf'))!.sha256);
  // Three calls on the same parser object expose stale partial-record state:
  // valid/invalid source ordering must not copy a previous event into errors.
  const lines=[raw,'\r',raw];
  const result=spawnSync('ruby',['-e',harness],{encoding:'utf8',timeout:12000,
   maxBuffer:1024*1024,input:JSON.stringify({ruby:Buffer.from(ruby.content).toString('base64'),lines})});
  assert.equal(result.status,0,id+' native process failed');
  const rows=JSON.parse(result.stdout) as Record<string,unknown>[];
  assert.equal(rows.length,3,id);
  assert.equal(rows[1]!.parser_err_stage,'extraction',id+' invalid record');
  for(const [key] of Object.entries(expected))
   assert.equal(Object.hasOwn(rows[1]!,key),false,id+' stale field leaked');
  for(const row of [rows[0]!,rows[2]!]){
   const stage=item.stage==='normalize'?'normalization':item.stage==='extract'?'extraction':item.stage;
   assert.equal(row.parser_err_stage,stage,id+' independent phase truth');
   const actual=Object.fromEntries(Object.entries(row).filter(([key])=>
    !['stellar_log_index','msg_origin','parser_err_msg','parser_err_stage','parser_err_field'].includes(key)));
   assert.deepEqual(actual,expectedWireRecord(expected),id+' independent native truth');
   records++;
  }
  compiled++;
 }
}
assert.ok(compiled>=40&&rejected>=2,'Unexpectedly reduced operator/template inventory');
console.log(JSON.stringify({contract:OPERATOR_MATRIX_CONTRACT,compiled,rejected,records,
 pairHashSetSha256:createHash('sha256').update(hashes.join('\n')).digest('hex'),
 nativeExecuted:true,targetVerified:false,rawValuesReturned:false}));
