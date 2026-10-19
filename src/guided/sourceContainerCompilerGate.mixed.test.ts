import {describe,it,expect} from 'vitest';
import {originalContainerCompilerGate} from './sourceContainerCompilerGate';

// These are authored source events, not claims about real device firmware.
const ordinary='{"event_type":"threat","src_ip":"192.0.2.1","action":"deny"}';
const user='{"event_type":"user","username":"김민수","action":"login"}';
const docker=JSON.stringify({
  log:'user=김민수\n',stream:'stdout',time:'2026-10-19T08:20:00Z',
});
const cases=[
  ['Docker JSON-file following ordinary security JSON',docker,'DOCKER_JSON_FILE'],
  ['CRI source following ordinary security JSON',
    '2026-10-19T08:20:00Z stdout F access=denied','KUBERNETES_CRI'],
  ['Linux audit serial following ordinary security JSON',
    'type=SYSCALL msg=audit(1760870000.123:12): syscall=59','LINUX_AUDIT'],
  ['RFC6587 octet-counted source following ordinary security JSON',
    '28 {"event_type":"alert"}','RFC6587_OCTETS'],
  ['W3C original declared header following ordinary security JSON',
    '#Fields: date time c-ip','W3C_DECLARED'],
  ['Zeek declared header following ordinary security JSON',
    '#separator \\x09','ZEEK_DECLARED'],
  ['RFC7464 record following ordinary security JSON',
    '\x1e{"event_type":"threat"}','JSON_TEXT_SEQUENCE'],
] as const;
describe('mixed user-input original transport source compiler gate',()=>{
  for(const [title,second,kind] of cases){
    it(title+' cannot be silently promoted by an eligible first record',()=>{
      const raw=ordinary+'\n'+second+'\n';
      expect(originalContainerCompilerGate(raw)).toMatchObject({
        kind,proof:'BOUNDED_LOCAL_SIGNATURE',
      });
    });
  }
  it('does not flag unrelated multi-event JSON, standard CEF or ordinary KV',()=>{
    for(const raw of [
      ordinary+'\n'+user+'\n',
      ordinary+'\r\n'+user+'\r\n',
      ordinary+'\n'+'{"log":"audit record","time":"2026-10-19T08:20:00Z","event_type":"login"}',
      'CEF:0|Synthetic|Firewall|1|99|Denied|5|src=192.0.2.1\n'+
        'action=deny src_ip=198.51.100.2',
    ])expect(originalContainerCompilerGate(raw),raw).toBeNull();
  });
  it('finds a strong second-line Docker signature after original CRLF and trailing blank lines',()=>{
    expect(originalContainerCompilerGate(ordinary+'\r\n'+docker+'\r\n')).toMatchObject({
      kind:'DOCKER_JSON_FILE',
    });
  });
});
