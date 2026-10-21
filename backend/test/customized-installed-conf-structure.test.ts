import assert from 'node:assert/strict';
import test from 'node:test';
import {compilePair} from '../src/compiler.js';
import {sampleProject} from './fixture.js';

/** Public-structure-only oracle from read-only rickmodular inspection 2026-10-21.
 * Four installed, paired customized parsers each have UDP/TCP source, a
 * customized <parse> reference, an optional transport settings include for
 * TCP, a rewrite_tag_filter match and a final invert:true Syslog rule.
 * These tests never copy installed plugins, private rules or log payloads.
 */
function output(defaultIndex:'syslog'|'threat'|'session'|'winlogevent'){
  const project=sampleProject();
  project.slug='generic_security';
  project.receiver.port=6801;
  project.classification={defaultIndex,rules:[]};
  const pair=compilePair(project);
  const conf=pair.files.find(file=>file.name.endsWith('.conf'))!;
  const fragment=pair.files.find(file=>!file.name.endsWith('.conf'))!;
  return {pair,conf,fragment};
}

test('generated CONF uses the installed four-pair customized source and routing topology',()=>{
  const {conf}=output('syslog');
  const text=conf.content;
  assert.equal((text.match(/<source>/g)||[]).length,2);
  assert.equal((text.match(/<parse>/g)||[]).length,2);
  assert.match(text,/<source>\s+@type udp\b/);
  assert.match(text,/<source>\s+@type tcp\b/);
  assert.equal((text.match(/\bport 6801\b/g)||[]).length,2);
  assert.equal((text.match(/@type customized_generic_security/g)||[]).length,2);
  assert.match(text,/@include \/etc\/td-agent\/transport_settings\.conf/);
  assert.match(text,/<match customized_generic_security\.\*\*>/);
  assert.match(text,/@type rewrite_tag_filter/);
  assert.match(text,/capitalize_regex_backreference yes/);
  assert.match(text,/<rule>\s+key stellar_log_index\s+pattern \S+\s+tag syslog\s+invert true\s+<\/rule>/);
});

test('every customized CONF retains an explicit final syslog fallback even if default class is not syslog',()=>{
  for(const category of ['syslog','threat','session','winlogevent'] as const){
    const {conf}=output(category);
    const rules=[...conf.content.matchAll(/<rule>([\s\S]*?)<\/rule>/g)].map(x=>x[1]!);
    assert.ok(rules.length>=1);
    assert.match(rules.at(-1)!, /\bkey stellar_log_index\b/);
    assert.match(rules.at(-1)!,/\binvert true\b/);
    assert.match(rules.at(-1)!,/\btag syslog\b/);
    for(const route of rules.slice(0,-1))assert.doesNotMatch(route,/\binvert true\b/);
  }
});

test('explicit Threat/Session rules precede a single non-overlapping inverted syslog fallback',()=>{
  const project=sampleProject();
  project.slug='generic_security';
  project.receiver.port=6801;
  project.classification.defaultIndex='syslog';
  const config=compilePair(project).files.find(x=>x.name.endsWith('.conf'))!.content;
  const blocks=[...config.matchAll(/<rule>([\s\S]*?)<\/rule>/g)].map(x=>x[1]!);
  assert.equal(blocks.length,3);
  assert.match(blocks[0]!,/pattern \/\^threat\$\/\s+tag threat/);
  assert.match(blocks[1]!,/pattern \/\^session\$\/\s+tag session/);
  assert.match(blocks[2]!,/pattern \/\^\(\?:threat\|session\)\$\/\s+tag syslog\s+invert true/);
  assert.equal((config.match(/\binvert true\b/g)||[]).length,1);
});

test('downloadable Ruby is a marker-delimited inner-parser snippet, not a falsely self-registered plugin',()=>{
  const {pair,fragment}=output('syslog');
  assert.equal(pair.manifest.status,'DRAFT');
  assert.equal(pair.manifest.targetImportVerified,false);
  assert.equal(fragment.name,'customized_generic_security');
  const code=fragment.content;
  const markers=['STELLAR_INIT_BEGIN','STELLAR_INIT_END','STELLAR_PARSE_BEGIN','STELLAR_PARSE_END'];
  const positions=markers.map(marker=>{
    assert.equal(code.split(marker).length-1,1,marker+' must appear once');
    return code.indexOf(marker);
  });
  assert.deepEqual([...positions].sort((a,b)=>a-b),positions);
  assert.match(code,/\bdef initialize\(\)/);
  assert.match(code,/\bdef parse\(text\)/);
  assert.match(code,/\byield event_time, normalized/);
  for(const required of ['stellar_log_index','msg_origin','parser_err_msg'])
    assert.ok(code.includes(required),required);
  assert.doesNotMatch(code,/\bregister_parser\b/);
  assert.doesNotMatch(code,/\bclass\s+StellarInnerParseClass\b/);
});
