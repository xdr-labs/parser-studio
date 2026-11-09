/**
 * Exact-source authored Parser Studio draft -> Ruby differential acceptance.
 * Original-path vendor fixtures are test data, not instructions. It is an
 * offline DRAFT verification and does not claim Stellar DP import/receive.
 * The independent expected tuples defend against browser/native shared bugs.
 */
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {spawnSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {createDraft} from '../../src/model';
import {preview} from '../../src/parser';
import {analyzeLogEnvelopes,assessEnvelopeCompilation} from '../../src/guided/autoParserEnvelope';
import {prepareAutoParserDraft} from '../../src/guided/autoParserDraft';
import {createCanonicalMappingPlan} from '../../src/guided/canonicalMappingPlan';
import {toBackendProject} from '../../src/guided/backendAdapter';
import {compilePair} from '../../backend/src/compiler';

const cases=[
  {filename:'01-juniper-srx.log',sha:'',portPairs:[[594,10400],[37233,161]],
    src:['10.0.0.1','10.0.0.26'],dst:['67.43.156.13','67.43.156.13']},
  {filename:'04-fortigate-traffic.log',sha:'',portPairs:[[44258,80],[58012,80]],
    src:['10.1.100.11','10.1.100.11'],dst:['185.244.31.158','23.59.154.35']},
  {filename:'04-fortigate-threat.log',sha:'',portPairs:[[44258,80],[46810,80]],
    src:['10.1.100.11','10.1.100.22'],dst:['185.244.31.158','172.16.200.55']},
];
const rubyRunner=["require 'json'","require 'base64'","require 'time'","require 'date'",
  "require 'ipaddr'","require 'csv'","input=JSON.parse(STDIN.read)",
  "klass=Class.new","klass.class_eval(Base64.strict_decode64(input.fetch('ruby')),'mcv2-native',1)",
  "parser=klass.new","rows=[]",
  "input.fetch('lines').each{|line|parser.parse(line){|_time,record|rows << record}}",
  "STDOUT.write(JSON.generate(rows))"].join('\n');
if(spawnSync('ruby',['-v'],{encoding:'utf8',timeout:3000}).status!==0)
  throw Error('MCV2_NATIVE_RUBY_REQUIRED: no optional skip');
const capability={authoring:{extractionFormats:['kv','json','syslog_rfc5424'],rfc5424BodyFormats:['raw','kv']},
  verification:{engineVerified:false,targetImportVerified:false}} as any;
let events=0;
for(const c of cases){
  const raw=readFileSync('tests/fixtures/docs-practice-20261104/'+c.filename,'utf8').trimEnd();
  const lines=raw.split(/\r?\n/).filter(Boolean);
  assert.equal(lines.length,c.portPairs.length,c.filename+' fixture count changed');
  const draft=createDraft();
  const original=preview(raw,draft);
  const ledger=analyzeLogEnvelopes(raw,'single-line');
  const assessment=assessEnvelopeCompilation(ledger,capability);
  assert.equal(assessment.status,'DRAFT_COMPILABLE',c.filename+' envelope');
  const prepared=prepareAutoParserDraft(raw,draft,original,ledger,assessment);
  assert.equal(prepared.ok,true,c.filename+' '+JSON.stringify(prepared));
  if(!prepared.ok)throw Error('MCV2_NO_DRAFT');
  const plan=createCanonicalMappingPlan(original,prepared.draft);
  assert.equal(plan.contract,'parser-studio.mapping-plan.v1');
  assert.equal(plan.entries.length,plan.sourceCount);
  assert.equal(new Set(plan.entries.map(e=>e.source)).size,plan.entries.length);
  const browser=preview(raw,prepared.draft);
  const adapter=toBackendProject(prepared.draft);
  assert.equal(adapter.ok,true,c.filename+' backend compiler mapping');
  if(!adapter.ok)throw Error('MCV2_NO_BACKEND');
  const pair=compilePair(adapter.project);
  assert.equal(pair.manifest.status,'DRAFT');
  const ruby=pair.files.find(f=>!f.name.endsWith('.conf'))?.content;
  assert.ok(ruby,'Ruby generated from the current MappingPlan');
  const process=spawnSync('ruby',['-e',rubyRunner],{
    encoding:'utf8',timeout:15000,maxBuffer:2*1024*1024,
    input:JSON.stringify({ruby:Buffer.from(ruby).toString('base64'),lines}),
  });
  assert.equal(process.status,0,c.filename+' '+String(process.stderr||process.error));
  const native=JSON.parse(process.stdout) as Array<Record<string,unknown>>;
  assert.equal(native.length,lines.length,c.filename+' emitted event count');
  for(let i=0;i<lines.length;i++){
    const normalized=browser.events[i]?.normalized;
    const record=native[i]!;
    assert.ok(normalized,c.filename+' browser original event accounting');
    assert.equal(browser.events[i]?.raw,lines[i],c.filename+' raw log unchanged');
    assert.equal(record.parser_err_stage,undefined,c.filename+' native error stage');
    const expected={srcip:c.src[i],dstip:c.dst[i],
      srcport:c.portPairs[i]?.[0],dstport:c.portPairs[i]?.[1]};
    for(const [field,value] of Object.entries(expected)){
      assert.equal(normalized[field],value,c.filename+' independent browser oracle '+field+' row '+i);
      assert.equal(record[field],value,c.filename+' independent native oracle '+field+' row '+i);
    }
    events++;
  }
  console.log('MCV2_NATIVE_VENDOR_CASE_PASS fixture='+c.filename+
    ' source_sha256='+createHash('sha256').update(raw).digest('hex')+
    ' events='+lines.length+' source_fields='+plan.sourceCount);
}
assert.equal(events,6);
console.log('MCV2_NATIVE_VENDOR_PARITY_PASS 3/3 original-source fixture families 6/6 events; DRAFT only');
