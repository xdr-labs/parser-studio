/** Public-synthetic Cisco/FTD-shaped proof for reviewed Syslog + bounded Regex body. */
import {createHash} from 'node:crypto';
import {resolve} from 'node:path';
import {sampleProject} from '../test/fixture.js';
import {recipeFromLegacyProject} from '../src/parser-recipe-v02.js';
import {nativeRecordSha256,prepareNativeProjectVerification}
  from '../src/native-project-verification.js';
import {createLocalNativeProjectVerifier}
  from '../src/local-native-project-verifier.js';

const sha=(value:string)=>createHash('sha256').update(value,'utf8').digest('hex');
const ruby=process.env['PARSER_NATIVE_RUBY'];
if(!ruby)throw new Error('NATIVE_SYSLOG_REGEX_RUNTIME_PATH');

const project=sampleProject();
project.projectId='draft-native_syslog_regex';
project.slug='native_syslog_regex';
project.receiver.port=7124;
project.extraction={
  format:'syslog_rfc3164',syslogBodyFormat:'regex',
  pattern:'^%FTD-\\d-\\d+: Built \\w+ \\w+ connection (?<connection_id>\\d+) for [^:]+:(?<src_ip>\\d+\\.\\d+\\.\\d+\\.\\d+)/(?<src_port>\\d+) to [^:]+:(?<dst_ip>\\d+\\.\\d+\\.\\d+\\.\\d+)/(?<dst_port>\\d+)$',
};
project.normalization.topFields={
  'body.connection_id':{normalized_name:'connection_id',data_type:'integer'},
  'body.src_ip':{normalized_name:'srcip',data_type:'ip'},
  'body.src_port':{normalized_name:'srcport',data_type:'port'},
  'body.dst_ip':{normalized_name:'dstip',data_type:'ip'},
  'body.dst_port':{normalized_name:'dstport',data_type:'port'},
};
project.normalization.nsFields={};project.normalization.vendorFields={};
project.normalization.msgOriginSource='native_syslog_regex';
project.normalization.msgClass='native_syslog_regex';
project.classification.rules=[];

const source=[
 '<134>May 5 17:51:17 dev01 %FTD-6-302013: Built inbound TCP connection 111 for net:10.10.10.10/53500 to fw:192.168.2.2/443',
 '<134>May 5 17:51:18 dev01 %FTD-6-302013: Built outbound TCP connection 112 for net:10.10.10.11/53501 to fw:192.168.2.3/8443',
].join('\n');
const origin={source:'native_syslog_regex',category:'network',class:'native_syslog_regex'};
const expected=[
 {connection_id:111,srcip:'10.10.10.10',srcport:53500,dstip:'192.168.2.2',dstport:443,
  stellar_log_index:'syslog',msg_origin:origin},
 {connection_id:112,srcip:'10.10.10.11',srcport:53501,dstip:'192.168.2.3',dstport:8443,
  stellar_log_index:'syslog',msg_origin:origin},
];
const prepared=prepareNativeProjectVerification({
 contract:'parser-studio.native-project-request.v0.1',confirmed:true,
 recipe:recipeFromLegacyProject(project,sha(source),2),legacyProject:project,source,
 expected:expected.map((record,index)=>({
  eventId:'event-'+(index+1),recordSha256:nativeRecordSha256(record),eventTimeMs:null,
 })),
});
const environment:Record<string,string>={BUNDLE_GEMFILE:resolve('Gemfile')};
for(const key of ['BUNDLE_PATH','BUNDLE_FROZEN','GEM_HOME','GEM_PATH','RUBYLIB',
 'LD_LIBRARY_PATH','LANG','LC_ALL','HOME'] as const){
 const value=process.env[key];if(value)environment[key]=value;
}
const verifier=createLocalNativeProjectVerifier({rubyExecutable:ruby,environment});
const report=await verifier.verify(prepared);
if(!report.nativeUserParserVerified||report.targetImportVerified||report.sensorTrafficSent||
 report.rawValuesReturned||report.eventsPassed!==2||report.recordHashMatches!==2||
 report.eventTimeMatches!==2)
 throw new Error('NATIVE_SYSLOG_REGEX_PROOF_FAILED');
process.stdout.write(JSON.stringify(report)+'\n');
