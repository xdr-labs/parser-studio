/**
 * Transport only reviewed synthetic generated Ruby fragments into an isolated
 * native runtime CI test. Private stdout includes generated code and must not
 * be uploaded as an artifact or logged.
 */
import {deflateSync} from 'node:zlib';
import {compilePair} from '../../backend/src/compiler';
import {sampleProject} from '../../backend/test/fixture';

const fixtures=[
  {id:'regex',extraction:{format:'regex' as const,pattern:'^(?<action>ALLOW)$'}},
  {id:'syslog-regex-body',extraction:{
    format:'syslog_rfc5424' as const,syslogBodyFormat:'regex' as const,
    pattern:'^(?<action>ALLOW)$',
  }},
  // The generic structural path carries the RFC3164 positional PAN-OS CSV
  // parser. Ruby 3.x syntax is insufficient: require executable Ruby 2.4.9
  // class_eval and real source grammar from the same generated fragment.
  {id:'generic-positional-csv',extraction:{format:'generic_structural' as const}},
  {id:'csv',extraction:{format:'csv' as const,csvColumns:['alpha','bravo','charlie'],csvDelimiter:','}},
];
const records=fixtures.map(({id,extraction})=>{
  const project=sampleProject();
  project.extraction=extraction;
  project.classification.rules=[];
  const pair=compilePair(project);
  const ruby=pair.files.find(f=>!f.name.endsWith('.conf'));
  const hasExpectedCompatibility=id==='csv'
    ? Boolean(ruby?.content.includes('def parserstudio_csv_parse_line(text, separator, strip_edges)'))
    : id==='generic-positional-csv'
    ? Boolean(ruby?.content.includes('def parserstudio_generic_rfc3164_positional_csv(text)')&&
      ruby?.content.includes('def parserstudio_generic_valid_ipv4?(value)'))
    : Boolean(ruby?.content.includes('Native Regex unsupported')&&
      pair.manifest.warnings.some(w=>w.includes('Ruby 2.4.9')));
  if(!ruby||!hasExpectedCompatibility)
    throw new Error('RUBY24_NATIVE_TARGET_GRAMMAR_GUARD_NOT_EMITTED '+id);
  return {
    id,sha256:ruby.sha256,
    compressedRuby:deflateSync(Buffer.from(ruby.content,'utf8')).toString('base64'),
  };
});
if(process.argv[2]==='--private-payload'){
  // Outer compression keeps the private transport small: all artifacts share
  // most of their fixed template, so transmitting separately is unnecessary.
  const input=JSON.stringify({contract:'parser-studio.synthetic-ruby24-regex.v1',records});
  process.stdout.write(deflateSync(Buffer.from(input,'utf8')).toString('base64')+'\n');
}else if(process.argv.length===2){
  console.log(JSON.stringify({
    contract:'parser-studio.synthetic-ruby24-regex-receipt.v1',
    cases:records.map(({id,sha256})=>({id,sha256})),
    expectedTargetBehavior:'FAIL_CLOSED',
    targetIndexedEventVerified:false,
  }));
}else throw new Error('PRIVATE_MODE_REQUIRED');
