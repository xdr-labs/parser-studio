/**
 * Private payload for the real Fluentd UDP reception gate. Generates the pair for
 * a Cisco ASA Regex parser listening on UDP 6801 (UDP only, so the generated
 * .conf is used verbatim: no include files are needed) and lists the datagrams
 * to send with the values expected from the Cisco-published corpus.
 *
 * Output contains generated code: stdout only, never an artifact or a log.
 */
import {deflateSync} from 'node:zlib';
import {compilePair} from '../../backend/src/compiler';
import {sampleProject} from '../../backend/test/fixture';
import {ASA_CORPUS,ASA_PATTERN,applyAsaNormalization} from './cisco-asa-fixture';

const PORT=6801;
const project=sampleProject();
project.slug='cisco_asa_udp_probe';
project.receiver={protocols:['udp'],port:PORT,bindAddress:'0.0.0.0',messageLengthLimit:16384,tcpFraming:'line'};
project.extraction={format:'regex',pattern:ASA_PATTERN};
project.classification.rules=[];
applyAsaNormalization(project);
const pair=compilePair(project);
const conf=pair.files.find(f=>f.name.endsWith('.conf'));
const ruby=pair.files.find(f=>!f.name.endsWith('.conf'));
if(!conf||!ruby)throw new Error('PAIR_FILES_MISSING');
if(!conf.content.includes('@type udp')||!conf.content.includes('port '+PORT)||
  !conf.content.includes('bind 0.0.0.0')||conf.content.includes('@type tcp')||
  conf.content.includes('@include'))
  throw new Error('UDP_ONLY_CONF_SHAPE_UNEXPECTED');
const payload={
  contract:'parser-studio.ruby24-fluentd-udp.v1',
  name:ruby.name,
  port:PORT,
  conf:conf.content,
  ruby:ruby.content,
  datagrams:ASA_CORPUS.map(({id,rawSample,expectedMatch,expectedStellarFields})=>
    ({id,raw:rawSample,expectedMatch,expectedStellarFields})),
};
if(process.argv[2]!=='--private-payload')throw new Error('PRIVATE_MODE_REQUIRED');
process.stdout.write(deflateSync(Buffer.from(JSON.stringify(payload),'utf8')).toString('base64')+'\n');
