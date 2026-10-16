import {describe,expect,it} from 'vitest';
import {breakSecurityInput} from './securityEventBreaker';
import {parseSecurityInput} from './securityInputPipeline';

describe('container runtime framing to structural parser pipeline PoC',()=>{
  it('reassembles CRI partial records and reuses reviewed single-event parsers',()=>{
    const raw=[
      '2026-10-16T15:44:21.100000001Z stdout P {"event":"alert","src":"192.',
      '2026-10-16T15:44:21.200000001Z stdout F 0.2.1","dst":"198.51.100.1"}',
      '2026-10-16T15:44:22Z stderr F CEF:1|Vendor|EDR|1|42|Threat|8|src=192.0.2.2 dst=198.51.100.2',
      '2026-10-16T15:44:23Z stdout F plain health message',
    ].join('\n')+'\n';
    const broken=breakSecurityInput(raw);
    expect(broken.ok).toBe(true);
    if(broken.ok){expect(broken.kind).toBe('cri_log');expect(broken.count).toBe(3);}

    const parsed=parseSecurityInput(raw);
    expect(parsed.ok).toBe(true);
    if(!parsed.ok)return;
    expect(parsed.kind).toBe('cri_log');
    expect(parsed.events).toHaveLength(3);
    expect(parsed.events[0].fields).toMatchObject({
      cri:{stream:'stdout',fragments:2},
      message_structured:{event:'alert',src:'192.0.2.1',dst:'198.51.100.1'},
    });
    expect(parsed.events[1].fields).toMatchObject({
      cri:{stream:'stderr',fragments:1},
      message_structured:{cef_version:'1',src:'192.0.2.2',dst:'198.51.100.2'},
    });
    expect(parsed.events[2].fields).toMatchObject({
      cri:{stream:'stdout',fragments:1},message:'plain health message',
    });
    expect(parsed.events[2].fields).not.toHaveProperty('message_structured');
  });

  it('parses Docker json-file framing before generic NDJSON and reuses body parsers',()=>{
    const rows=[
      {log:'{"event":"login","src":"192.0.2.3"}\n',stream:'stdout',time:'2026-10-16T15:45:21.123456789Z'},
      {log:'LEEF:2.0|Vendor|NDR|1|dns|x5E|src=192.0.2.4^dst=198.51.100.4^act=deny\n',stream:'stderr',time:'2026-10-16T15:45:22Z',attrs:{pod:'sensor'}},
      {log:'plain startup message\n',stream:'stdout',time:'2026-10-16T15:45:23+09:00'},
    ];
    const raw=rows.map(row=>JSON.stringify(row)).join('\n')+'\n';
    const broken=breakSecurityInput(raw);
    expect(broken.ok).toBe(true);
    if(broken.ok){expect(broken.kind).toBe('docker_json_log');expect(broken.count).toBe(3);}

    const parsed=parseSecurityInput(raw);
    expect(parsed.ok).toBe(true);
    if(!parsed.ok)return;
    expect(parsed.kind).toBe('docker_json_log');
    expect(parsed.events[0].fields).toMatchObject({
      docker:{stream:'stdout',time:'2026-10-16T15:45:21.123456789Z'},
      message_structured:{event:'login',src:'192.0.2.3'},
    });
    expect(parsed.events[1].fields).toMatchObject({
      docker:{stream:'stderr',extra:{attrs:{pod:'sensor'}}},
      message_structured:{leef_version:'2.0',src:'192.0.2.4',dst:'198.51.100.4',act:'deny'},
    });
    expect(parsed.events[2].fields).toMatchObject({message:'plain startup message'});
  });

  it('treats malformed strong CRI/Docker signatures as terminal container failures',()=>{
    const invalid=[
      '2026-10-16T15:44:21Z stdout P incomplete\n',
      '2026-02-30T15:44:21Z stdout F bad-date\n',
      JSON.stringify({log:'ok\n',stream:'stdout',time:'2026-02-30T15:44:21Z'})+'\n',
      JSON.stringify({log:'ok\n',stream:'console',time:'2026-10-16T15:44:21Z'})+'\n',
    ];
    const rows=invalid.map(raw=>({breaker:breakSecurityInput(raw),pipeline:parseSecurityInput(raw)}));
    expect(rows.every(row=>!row.breaker.ok&&!row.pipeline.ok)).toBe(true);
    console.log('CONTAINER_LOG_PIPELINE_INVALID '+JSON.stringify({total:rows.length,rejected:rows.filter(row=>!row.pipeline.ok).length}));
  });
});
