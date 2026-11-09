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
];
const records=fixtures.map(({id,extraction})=>{
  const project=sampleProject();
  project.extraction=extraction;
  project.classification.rules=[];
  const pair=compilePair(project);
  const ruby=pair.files.find(f=>!f.name.endsWith('.conf'));
  if(!ruby||!ruby.content.includes('Native Regex unsupported')||
     !pair.manifest.warnings.some(w=>w.includes('Ruby 2.4.9')))
    throw new Error('RUBY24_NATIVE_FAIL_CLOSED_GUARD_NOT_EMITTED '+id);
  return {
    id,sha256:ruby.sha256,
    compressedRuby:deflateSync(Buffer.from(ruby.content,'utf8')).toString('base64'),
  };
});
if(process.argv[2]==='--private-payload'){
  // Outer compression keeps the private transport small: both artifacts share
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
