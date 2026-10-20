import {describe,expect,it} from 'vitest';
import {originalContainerCompilerGate} from './sourceContainerCompilerGate';
const docker=JSON.stringify({log:'user=김민수\n',stream:'stdout',
  time:'2026-10-19T08:20:00Z'})+'\n';
const securityJson='{"event_type":"threat","username":"김민수","source_ip":"192.0.2.1"}';

describe('source transport/compiler-readiness gate',()=>{
  it('recognizes original Docker JSON-file independently of a browser JSON match',()=>{
    expect(originalContainerCompilerGate(docker)).toMatchObject({
      kind:'DOCKER_JSON_FILE',proof:'BOUNDED_LOCAL_SIGNATURE'});
  });
  it('a verified source framing issue blocks even when the textual syntax is JSON',()=>{
    const witness={raw:securityJson,events:[
      {preview:{issues:['FRAMING_ORIGINAL_CONTAINER_NOT_IN_DRAFT_COMPILER']}},
    ]};
    expect(originalContainerCompilerGate(securityJson,witness)).toMatchObject({
      kind:'SOURCE_REVIEW_ONLY',proof:'QUALIFIED_SOURCE_PREVIEW'});
    expect(originalContainerCompilerGate(securityJson,
      {...witness,raw:'other source'})).toBeNull();
  });
  it('gates core original stream families but not unrelated normal structured inputs',()=>{
    const rejected=[
      '2026-10-19T08:20:00Z stdout F denied\n',
      'type=SYSCALL msg=audit(1760870000.123:12): syscall=59\n',
      '#Fields: date time c-ip\n2026-10-19 08:20:00 192.0.2.1\n',
      '#separator \\x09\n#fields\tts\tuid\n',
      '45 <134>1 2026-10-19T08:20:00Z fw process 1 - x\n',
      '28 {"event_type":"alert"}',
      '2 []',
      '\x1e{"event_type":"threat"}\n',
      'MESSAGE=hello\nPRIORITY=5\n\n',
      '{"version":"1.1","host":"h","short_message":"deny"}\0',
    ];
    for(const raw of rejected)expect(originalContainerCompilerGate(raw)).not.toBeNull();
    for(const raw of [
      securityJson,
      'CEF:0|Example|FW|1|42|Blocked|8|src=192.0.2.1',
      'LEEF:1.0|Example|FW|1|foo|src=192.0.2.1',
      'src_ip=192.0.2.1 action=deny',
      '<134>1 2026-10-19T08:20:00Z fw process 1 - action=deny',
      '{"event_type":"user","log":"audit log","time":"2026-10-19T08:20:00Z"}',
    ])expect(originalContainerCompilerGate(raw),raw).toBeNull();
  });
});
