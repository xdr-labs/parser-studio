// Run-time Parsing Success Contract of the generated Ruby (W7): a key=value body is never emitted as a
// parsed event when a pair of the original text is missing from the parsed fields, on every route that
// reads a key=value body, in both templates. The faults are injected into the loaded Ruby itself.
import assert from 'node:assert/strict';
import {rubyE} from './ruby-argv.js';
import {readFileSync} from 'node:fs';
import {spawnSync} from 'node:child_process';
import {resolvedTemplate} from './template-fixture.js';
import test from 'node:test';

const templates=['ruby-fragment.rb.tpl'];
const rubyAvailable=spawnSync('ruby',['-v'],{encoding:'utf8'}).status===0;
const KV='srcip=10.1.1.1 dstip=10.2.2.2 msg="a=b c" path=C:\\\\dir note=\'it is\' action=deny';
const ROUTES:Array<[string,Record<string,unknown>,string]>=[
  ['kv',{format:'kv'},KV],
  ['mixed kv',{format:'mixed',mixedFormats:['kv','rfc3164_kv','rfc5424_kv']},KV],
  ['mixed rfc3164_kv',{format:'mixed',mixedFormats:['kv','rfc3164_kv','rfc5424_kv']},'<134>Nov 14 09:30:00 fw01 app: '+KV],
  ['rfc3164 tagless',{format:'syslog_rfc3164',syslogBodyFormat:'kv'},'<134>Nov 14 09:30:00 fw01 '+KV],
  ['rfc3164 hostless',{format:'syslog_rfc3164',syslogBodyFormat:'kv'},'<134>Nov 14 09:30:00 '+KV],
  ['rfc5424',{format:'syslog_rfc5424',syslogBodyFormat:'kv'},'<165>1 2026-11-14T09:30:00Z host=a app - ID47 - '+KV],
];
const FAULTS:Record<string,string>={
  none:'',
  // The faults replace the generated key=value reader (psg_strict_key_values), as a defect of the grammar would.
  // One pair is dropped after a successful parse.
  'pair dropped':"alias psg_strict_key_values_real psg_strict_key_values\ndef psg_strict_key_values(input); out=psg_strict_key_values_real(input); out['fields'].delete('dstip'); out; end",
  // A value is cut short.
  'value truncated':"alias psg_strict_key_values_real psg_strict_key_values\ndef psg_strict_key_values(input); out=psg_strict_key_values_real(input); out['fields']['srcip']=out['fields']['srcip'][0,4] if out['fields']['srcip']; out; end",
  // The first pair of the body never reaches the key=value reader.
  'first pair skipped':"alias psg_strict_key_values_real psg_strict_key_values\ndef psg_strict_key_values(input); psg_strict_key_values_real(input.sub(/\\A[^ ]+ +/, '')); end",
};

function run(template:string,extraction:Record<string,unknown>,fault:string,raw:string):string{
  const ruby=resolvedTemplate(template);
  const script=[
    "require 'json'","require 'base64'","require 'ipaddr'","require 'csv'","require 'time'","require 'date'","require 'zlib'",
    ruby,fault,
    "@parser_rule_set={'receiver'=>{'messageLengthLimit'=>65536},'extraction'=>JSON.parse("+JSON.stringify(JSON.stringify(extraction))+")}",
    "begin; record=parserstudio_extract("+JSON.stringify(raw)+"); STDOUT.write('OK '+JSON.generate(record)); rescue ArgumentError => e; STDOUT.write('REJECTED '+e.message); end",
  ].join('\n');
  const result=spawnSync('ruby',rubyE(script),{encoding:'utf8',timeout:8000,maxBuffer:1024*1024});
  assert.equal(result.status,0,result.stderr||String(result.error));
  return result.stdout;
}

test('the template hands over an event only when the shared reading is FULL',()=>{
  for(const template of templates){
    const body=resolvedTemplate(template);
    assert.match(body,/^  reading = psg_read_event\(psg_text\(text\), settings\)$/m);
    // Besides FULL, only a Generic Structural PARTIAL reading and a PARTIAL one whose Syslog message only claims
    // CEF/LEEF and is kept whole as text (owner decision D-2, textKept) are handed over.
    assert.match(body,/^  unless reading\['status'\] == 'FULL' \|\| \(reading\['status'\] == 'PARTIAL' &&\n    \(settings\['format'\] == 'generic_structural' \|\| reading\['textKept'\] == true\)\)$/m);
    assert.match(body,/def psg_classify_structured_parse\(raw, outcome, bodyFormat\)/);
  }
});

test('a complete key=value body is parsed on every route; an injected pair loss becomes a rejection, never a parsed event',
  {skip:!rubyAvailable},()=>{
    for(const template of templates)for(const [route,extraction,raw] of ROUTES){
      const clean=run(template,extraction,FAULTS.none!,raw);
      assert.match(clean,/^OK /,template+' '+route+' '+clean);
      assert.match(clean,/"dstip":"10\.2\.2\.2"/,template+' '+route);
      for(const fault of ['pair dropped','value truncated','first pair skipped']){
        const out=run(template,extraction,FAULTS[fault]!,raw);
        assert.match(out,/^REJECTED raw pair /,template+' / '+route+' / '+fault+' -> '+out.slice(0,160));
      }
    }
  });

test('a field written twice and present once is a lost occurrence',{skip:!rubyAvailable},()=>{
  const fault="def psg_strict_key_values(input); psg_set_tag({'fields'=>{'action'=>'deny','srcip'=>'192.0.2.10'},'errors'=>[]}, 'bodyKind', 'kv'); end";
  for(const template of templates)
    assert.match(run(template,{format:'kv'},fault,'action=deny srcip=192.0.2.10 action=deny'),/^REJECTED raw pair /);
});

test('a TAG or a pair read as the RFC 3164 host name is rejected; an RFC 5424 HOSTNAME is positional and exempt',{skip:!rubyAvailable},()=>{
  const check=(host:string,raw:string)=>{
    const ruby=resolvedTemplate('ruby-fragment.rb.tpl');
    const script=["require 'json'","require 'base64'","require 'ipaddr'","require 'csv'","require 'time'","require 'date'","require 'zlib'",ruby,
      // The outcome carries the tag the RFC 3164 grammar puts on its result; RFC 5424 results never do.
      "outcome={'fields'=>{'syslog_hostname'=>"+JSON.stringify(host)+",'message'=>'x'},'errors'=>[]}",
      "psg_set_tag(outcome,'rfc3164Header',true) unless "+JSON.stringify(raw)+".match?(/\\A<[0-9]{1,3}>[0-9]{1,3} /)",
      "verdict=psg_classify_structured_parse("+JSON.stringify(raw)+",outcome,'other')",
      "STDOUT.write(verdict['status']=='FULL' ? 'OK' : 'REJECTED '+verdict['reasons'][0])"].join('\n');
    const result=spawnSync('ruby',rubyE(script),{encoding:'utf8',timeout:8000});
    assert.equal(result.status,0,result.stderr||String(result.error));
    return result.stdout;
  };
  assert.match(check('kernel:','<134>Nov 14 09:30:00 kernel: started'),/^REJECTED a TAG or a key=value pair was taken as the host name/);
  assert.match(check('srcip=10.1.1.1','<134>Nov 14 09:30:00 srcip=10.1.1.1 action=deny'),/^REJECTED a TAG or a key=value pair was taken as the host name/);
  assert.equal(check('fw01','<134>Nov 14 09:30:00 fw01 started'),'OK');
  assert.equal(check('2001:db8::1','<134>Nov 14 09:30:00 2001:db8::1 started'),'OK');
  assert.equal(check('host=a','<165>1 2026-11-14T09:30:00Z host=a app - ID47 - started'),'OK');
});

// PR #311 review (P2): the header check inferred "RFC 3164" from a field name the customer controls.
test('a field named syslog_hostname in a JSON or key=value event is data, not a Syslog header',{skip:!rubyAvailable},()=>{
  for(const template of templates){
    for(const raw of ['{"syslog_hostname":"host=a","message":"ok"}','{"syslog_hostname":"kernel:","message":"ok"}']){
      const out=run(template,{format:'json'},'',raw);
      assert.match(out,/^OK /,template+' '+out.slice(0,160));
      assert.match(out,/"syslog_hostname":"(host=a|kernel:)"/);
    }
    const kv=run(template,{format:'kv'},'','syslog_hostname="host=a" action=deny');
    assert.match(kv,/^OK /,template+' '+kv.slice(0,160));
    // The check still applies to what the RFC 3164 grammar itself read as the host name.
    const misread=run(template,{format:'syslog_rfc3164',syslogBodyFormat:'kv'},
      "alias psg_parse_rfc3164_strict_real psg_parse_rfc3164_strict\ndef psg_parse_rfc3164_strict(input, choice, pattern = nil); out=psg_parse_rfc3164_strict_real(input, choice, pattern); out['fields']['syslog_hostname']='kernel:'; out; end",
      '<134>Nov 14 09:30:00 fw01 '+KV);
    assert.match(misread,/^REJECTED a TAG or a key=value pair was taken as the host name/,template+' '+misread.slice(0,160));
  }
});

// PR #311 review (P2): STRUCTURED-DATA is not key=value text. An SD-PARAM (stored under its own, encoded name)
// must not be demanded as a key=value field; pair accounting is for the MSG.
const SD_EVENTS=[
  '<165>1 2026-11-14T09:30:00Z host app - ID47 [meta a.b="x"] srcip=10.1.1.1 action=deny',
  '<165>1 2026-11-14T09:30:00Z host app - ID47 [origin ip="192.0.2.1"][meta note="k=v \\] z" seq="1"] srcip=10.1.1.1 dstip=10.2.2.2 action=deny',
];
test('RFC 5424 structured data does not count as key=value pairs; a pair lost from the MSG is still a rejection',{skip:!rubyAvailable},()=>{
  for(const template of templates)for(const raw of SD_EVENTS){
    const clean=run(template,{format:'syslog_rfc5424',syslogBodyFormat:'kv'},FAULTS.none!,raw);
    assert.match(clean,/^OK /,template+' '+clean.slice(0,200));
    assert.match(clean,/"srcip":"10\.1\.1\.1"/);
    for(const fault of ['value truncated','first pair skipped']){
      const out=run(template,{format:'syslog_rfc5424',syslogBodyFormat:'kv'},FAULTS[fault]!,raw);
      assert.match(out,/^REJECTED raw pair /,template+' / '+fault+' -> '+out.slice(0,160));
    }
  }
});

// Re-audit of 2026-11-15 (M-1): the pairs of the MSG are looked up in the key=value body, not in the whole
// record. An SD-PARAM with the same name and value as a pair that the body parser lost must not stand in for it.
test('an SD-PARAM with the name and value of a lost MSG pair does not hide the loss',{skip:!rubyAvailable},()=>{
  const raw='<165>1 2026-11-14T09:30:00Z host app - ID47 [a srcip="10.1.1.1"] srcip=10.1.1.1 action=deny';
  const dropped="alias psg_strict_key_values_real psg_strict_key_values\ndef psg_strict_key_values(input); out=psg_strict_key_values_real(input); out['fields'].delete('srcip'); out; end";
  for(const template of templates){
    const clean=run(template,{format:'syslog_rfc5424',syslogBodyFormat:'kv'},FAULTS.none!,raw);
    assert.match(clean,/^OK /,template+' '+clean.slice(0,200));
    const out=run(template,{format:'syslog_rfc5424',syslogBodyFormat:'kv'},dropped,raw);
    assert.match(out,/^REJECTED raw pair /,template+' -> '+out.slice(0,200));
  }
});

// Format-level browser/Ruby fuzz of 2026-11-15. Contract KV_TRAILING: ASCII white space may follow the last
// pair. The check must not take that white space as part of the last value and reject a complete event.
test('white space after the last pair is not part of its value',{skip:!rubyAvailable},()=>{
  for(const template of templates)for(const tail of ['\f','\v',' \f','\t']){
    const out=run(template,{format:'kv'},FAULTS.none!,'srcip=10.1.1.1 action=deny'+tail);
    assert.match(out,/^OK \{"srcip":"10\.1\.1\.1","action":"deny"\}$/,template+' '+JSON.stringify(tail)+' -> '+out.slice(0,120));
    const lost=run(template,{format:'kv'},FAULTS['value truncated']!,'srcip=10.1.1.1 action=deny'+tail);
    assert.match(lost,/^REJECTED raw pair /,template+' -> '+lost.slice(0,120));
  }
});

// An event from which no field was extracted is not a parsed event (the browser reports UNKNOWN).
test('an empty JSON object is rejected, not emitted as an event without fields',{skip:!rubyAvailable},()=>{
  for(const template of templates){
    assert.match(run(template,{format:'json'},FAULTS.none!,'{}'),/^REJECTED no field was extracted$/);
    assert.match(run(template,{format:'json'},FAULTS.none!,'{"a":1}'),/^OK \{"a":1\}$/);
  }
});
