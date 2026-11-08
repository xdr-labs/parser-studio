import test from 'node:test';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {sampleProject} from './fixture.js';
import {validateProject} from '../src/validate.js';
import {compilePair} from '../src/compiler.js';

const rubyBin = process.env.PARSER_RUBY_BIN || 'ruby';
const nativeAvailable = spawnSync(rubyBin, ['-v'], {encoding:'utf8'}).status === 0;

function fixture(vendor:string) {
  const project=sampleProject();
  project.vendor=vendor;
  project.normalization.topFields={action:{normalized_name:'action',data_type:'string'}};
  project.normalization.nsFields={};
  project.normalization.vendorFields={note:{normalized_name:'note',data_type:'string'}};
  project.classification.rules=[];
  return project;
}

test('backend refuses noncanonical manufacturer identities before Ruby export',()=>{
  for(const vendor of [' Audit','Audit ',' Audit ', '\u00a0Audit\u00a0','\u2003Audit\u2003']){
    const result=validateProject(fixture(vendor));
    assert.equal(result.ok,false,vendor);
    assert.ok(result.issues.some(issue=>issue.code==='noncanonical_vendor_namespace'),vendor);
  }
  assert.equal(validateProject(fixture('Audit')).ok,true);
  assert.equal(validateProject(fixture('Palo Alto')).ok,true);
});

test('exact generated native Ruby preserves canonical manufacturer namespace',
  {skip:!nativeAvailable},()=>{
    const project=fixture('Audit');
    const pair=compilePair(project);
    const ruby=pair.files.find(file=>!file.name.endsWith('.conf'))!.content;
    const runner=[
      "require 'json'", "require 'base64'", "require 'csv'", "require 'time'", "require 'ipaddr'",
      'klass=Class.new',
      'klass.class_eval(Base64.strict_decode64(ARGV.fetch(0)))',
      'klass.new.parse(STDIN.read){|_time,record| puts JSON.generate(record)}',
    ].join('\n');
    const result=spawnSync(rubyBin,['-e',runner,Buffer.from(ruby).toString('base64')],{
      input:JSON.stringify({action:'allow',note:'exact source'}),encoding:'utf8',timeout:12000});
    assert.equal(result.status,0,result.stderr||String(result.error));
    const record=JSON.parse(result.stdout);
    assert.equal(record.Audit?.note,'exact source');
    assert.equal(Object.hasOwn(record,'Audit '),false);
  });
