import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {spawnSync} from 'node:child_process';
import test from 'node:test';

const templates=['ruby-fragment.rb.tpl','ruby-forwarder-family.rb.tpl'];
const rubyAvailable=spawnSync('ruby',['-v'],{encoding:'utf8'}).status===0;

test('both DRAFT native templates use the same strict JSON duplicate-key guard',()=>{
  for(const filename of templates){
    const body=readFileSync(new URL('../templates/'+filename,import.meta.url),'utf8');
    assert.match(body,/def parserstudio_json_duplicate_keys\?\(raw\)/);
    assert.match(body,/raise ArgumentError, 'Duplicate JSON object key' if parserstudio_json_duplicate_keys\?\(text\)/);
  }
});

test('native Ruby DRAFT parser refuses duplicate root/nested/escaped keys and preserves separate objects',
  {skip:!rubyAvailable},()=>{
    const invalid=[
      '{"src_ip":"192.0.2.11","src_ip":"203.0.113.7"}',
      '{"outer":{"event":"one","event":"two"}}',
      '{"\\u0061":1,"a":2}',
    ];
    const accepted=[
      '{"left":{"event":"one"},"right":{"event":"two"}}',
      '{"arr":[{"event":"one"},{"event":"two"}]}',
    ];
    for(const filename of templates){
      const ruby=readFileSync(new URL('../templates/'+filename,import.meta.url),'utf8');
      for(const [source,shouldReject] of [
        ...invalid.map(raw=>[raw,true] as const),
        ...accepted.map(raw=>[raw,false] as const),
      ]){
        const script=[
          "require 'json'","require 'base64'","require 'ipaddr'","require 'csv'","require 'time'",
          ruby,
          "@parser_rule_set={'extraction'=>{'maxDepth'=>8}}",
          "begin; parserstudio_json_object("+JSON.stringify(source)+"); STDOUT.write('OK'); rescue ArgumentError => e; STDOUT.write('REJECTED'); end",
        ].join('\n');
        const result=spawnSync('ruby',['-e',script],{encoding:'utf8',timeout:6000,maxBuffer:512*1024});
        assert.equal(result.status,0,result.stderr||String(result.error));
        assert.equal(result.stdout,shouldReject?'REJECTED':'OK',filename+' '+(shouldReject?'invalid':'valid'));
      }
    }
  });
