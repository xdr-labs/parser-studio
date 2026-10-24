import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import test from 'node:test';
import {sampleProject} from './fixture.js';
import {compilePair} from '../src/compiler.js';
import {validateProject} from '../src/validate.js';

const capturePattern="^\\[(?<month_day>\\d{2}\\.\\d{2}) (?<clock>\\d{2}:\\d{2}:\\d{2})\\] (?<application>[A-Za-z.]+) - (?<message>.+)$";
const rubyBinary=process.env.PARSER_STUDIO_RUBY_BINARY||'ruby';
const nativeAvailable=spawnSync(rubyBinary,['-v'],{encoding:'utf8'}).status===0;
function project(){
 const p=sampleProject();
 p.projectId='draft_temporal_review';
 p.slug='temporal_review';
 p.vendor='Public Synthetic';
 p.product='Temporal negative-holdout review';
 p.extraction={format:'regex',pattern:capturePattern};
 p.normalization.topFields={};
 p.normalization.nsFields={};
 p.normalization.vendorFields={message:{normalized_name:'custom.message',data_type:'string'}};
 p.classification.rules=[];
 return p;
}
function native(raw:string){
 const p=project();
 assert.equal(validateProject(p).ok,true);
 const fragment=compilePair(p).files.find(x=>!x.name.endsWith('.conf'))!.content;
 const source=[
  "require 'json'", "require 'base64'", "require 'csv'", "require 'ipaddr'", "require 'time'",
  'klass=Class.new',
  "klass.class_eval(Base64.strict_decode64('"+Buffer.from(fragment).toString('base64')+"'))",
  'parser=klass.new',
  'parser.parse(STDIN.read) {|_time,record| puts JSON.generate(record)}',
 ].join('\n');
 const result=spawnSync(rubyBinary,['-e',source],{
  input:raw,encoding:'utf8',timeout:15000,maxBuffer:1024*1024,
 });
 assert.equal(result.status,0,result.stderr||String(result.error));
 return JSON.parse(result.stdout) as Record<string,unknown>;
}

test('generated Ruby includes a constrained lexical check only for explicit temporal named fields',()=>{
 const p=project();assert.equal(validateProject(p).ok,true);
 const files=compilePair(p).files;
 const fragment=files.find(x=>!x.name.endsWith('.conf'))!.content;
 assert.ok(fragment.includes('def parserstudio_valid_month_day_capture?'));
 assert.ok(fragment.includes('def parserstudio_valid_clock_capture?'));
 assert.ok(fragment.includes("result.key?('month_day')"));
 assert.ok(fragment.includes("result.key?('clock')"));
 assert.ok(!fragment.includes('13.30'));
 // The code never hardcodes a source example or sensitive field value.
 assert.ok(!fragment.includes('proxy opened'));
 const other=sampleProject();
 const baseline=compilePair(other).files.find(x=>!x.name.endsWith('.conf'))!.content;
 assert.ok(!baseline.includes('parserstudio_valid_month_day_capture?'));
});

test('native validated Regex keeps supported yearless source without inferring year/timezone',
 {skip:!nativeAvailable},()=>{
 for(const raw of [
  '[10.30 16:49:06] chrome.exe - proxy opened',
  '[02.29 23:59:59] firefox.exe - session closed',
 ]){
  const got=native(raw);
  assert.ok(!('parser_err_msg' in got),JSON.stringify(got));
  assert.equal(got.stellar_log_index,'syslog');
 }
});

test('native Regex refuses impossible day/month/clock despite a matching named regex',
 {skip:!nativeAvailable},()=>{
 for(const raw of [
  '[13.30 16:49:06] chrome.exe - proxy opened',
  '[02.31 16:49:06] chrome.exe - proxy opened',
  '[04.31 16:49:06] chrome.exe - proxy opened',
  '[10.30 25:49:06] chrome.exe - proxy opened',
  '[10.30 16:61:06] chrome.exe - proxy opened',
  '[10.30 16:49:66] chrome.exe - proxy opened',
 ]){
  const got=native(raw);
  assert.equal(got.parser_err_stage,'extraction');
  assert.equal(got.parser_err_msg,'ArgumentError');
  assert.equal(JSON.stringify(got).includes(raw),false);
 }
});
