/**
 * Transport only reviewed synthetic generated Ruby fragments into an isolated
 * native runtime CI test. Private stdout includes generated code and must not
 * be uploaded as an artifact or logged.
 */
import {deflateSync} from 'node:zlib';
import {compilePair} from '../../backend/src/compiler';
import {sampleProject} from '../../backend/test/fixture';

// Independently authored operator-style pattern (statically bounded: anchored,
// one scan loop). The raw FTD lines and expected values live in the offline
// runner and are written by hand from the log text, not read back from Ruby.
const FTD_PATTERN=String.raw`^.*%FTD-\d-(?<event_id>\d+): Built inbound (?<protocol>TCP|UDP) connection \d+ for \w+:(?<srcip>[\d.]+)/(?<srcport>\d+) \([\d.]+/\d+\) to \w+:(?<dstip>[\d.]+)/(?<dstport>\d+) \([\d.]+/\d+\)$`;
// Unanchored repeat: the implicit scan makes it quadratic, so it has no static
// cost proof and MUST fail closed on a runtime without a Regexp timeout.
const UNBOUNDED_PATTERN=String.raw`(?<action>\d+)`;
const fixtures=[
  {id:'regex',pattern:FTD_PATTERN,extraction:{format:'regex' as const,pattern:FTD_PATTERN}},
  {id:'syslog-regex-body',pattern:'^(?<action>ALLOW)$',extraction:{
    format:'syslog_rfc5424' as const,syslogBodyFormat:'regex' as const,
    pattern:'^(?<action>ALLOW)$',
  }},
  {id:'regex-unbounded',pattern:UNBOUNDED_PATTERN,extraction:{format:'regex' as const,pattern:UNBOUNDED_PATTERN}},
  // The generic structural path carries the RFC3164 positional PAN-OS CSV
  // parser. Ruby 3.x syntax is insufficient: require executable Ruby 2.4.9
  // class_eval and real source grammar from the same generated fragment.
  {id:'generic-positional-csv',pattern:undefined,extraction:{format:'generic_structural' as const}},
  {id:'csv',pattern:undefined,extraction:{format:'csv' as const,csvColumns:['alpha','bravo','charlie'],csvDelimiter:','}},
];
const records=fixtures.map(({id,pattern,extraction})=>{
  const project=sampleProject();
  project.extraction=extraction;
  project.classification.rules=[];
  if(id==='regex'){
    project.normalization.topFields={
      srcip:{normalized_name:'srcip',data_type:'ip'},
      dstip:{normalized_name:'dstip',data_type:'ip'},
      protocol:{normalized_name:'protocol',data_type:'string'},
    };
    project.normalization.nsFields={
      srcport:{normalized_name:'srcport',data_type:'port'},
      dstport:{normalized_name:'dstport',data_type:'port'},
      event_id:{normalized_name:'log.event_id',data_type:'integer'},
    };
    project.normalization.vendorFields={};
  }
  const pair=compilePair(project);
  const ruby=pair.files.find(f=>!f.name.endsWith('.conf'));
  const bounded=/def parserstudio_regex_cost_proven\?\n  true\nend/.test(ruby?.content??'');
  const unbounded=/def parserstudio_regex_cost_proven\?\n  false\nend/.test(ruby?.content??'');
  const hasExpectedCompatibility=id==='csv'
    ? Boolean(ruby?.content.includes('def parserstudio_csv_parse_line(text, separator, strip_edges)'))
    : id==='generic-positional-csv'
    ? Boolean(ruby?.content.includes('def parserstudio_generic_rfc3164_positional_csv(text)')&&
      ruby?.content.includes('def parserstudio_generic_valid_ipv4?(value)'))
    : id==='regex-unbounded'
    ? Boolean(ruby?.content.includes('Native Regex unsupported')&&unbounded&&
      pair.manifest.warnings.some(w=>w.includes('Ruby 2.4.9 it fails closed')))
    : Boolean(ruby?.content.includes('Native Regex unsupported')&&bounded&&
      pair.manifest.warnings.some(w=>w.includes('static backtracking-cost classification')));
  if(!ruby||!hasExpectedCompatibility)
    throw new Error('RUBY24_NATIVE_TARGET_GRAMMAR_GUARD_NOT_EMITTED '+id);
  return {
    id,sha256:ruby.sha256,...(pattern===undefined?{}:{pattern}),
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
    expectedTargetBehavior:'BOUNDED_REGEX_EXECUTES_UNBOUNDED_FAILS_CLOSED',
    targetIndexedEventVerified:false,
  }));
}else throw new Error('PRIVATE_MODE_REQUIRED');
