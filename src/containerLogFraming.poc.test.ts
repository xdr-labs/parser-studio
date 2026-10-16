import {describe,expect,it} from 'vitest';
import {looksLikeDockerJsonLogStream,parseCriLogStream,parseDockerJsonLogStream} from './containerLogFraming';

describe('container runtime log framing PoC',()=>{
  it('parses CRI full records and reassembles same-stream partial fragments',()=>{
    const raw=[
      '2026-10-16T15:44:21.123456789Z stdout P {"event":"alert","src":"192.',
      '2026-10-16T15:44:21.223456789Z stderr F CEF:1|Vendor|EDR|1|42|Threat|8|src=192.0.2.9',
      '2026-10-16T15:44:21.323456789Z stdout F 0.2.1","dst":"198.51.100.1"}',
      '2026-10-16T15:44:22+09:00 stdout F LEEF:2.0|Vendor|NDR|1|dns|x5E|src=192.0.2.2^dst=198.51.100.2',
    ].join('\n')+'\n';
    const parsed=parseCriLogStream(raw);
    expect(parsed.ok).toBe(true);
    if(!parsed.ok)return;
    expect(parsed.events).toHaveLength(3);
    expect(parsed.events[0]).toMatchObject({stream:'stderr',fragments:1,content:'CEF:1|Vendor|EDR|1|42|Threat|8|src=192.0.2.9'});
    expect(parsed.events[1]).toMatchObject({
      stream:'stdout',fragments:2,first_timestamp:'2026-10-16T15:44:21.123456789Z',
      last_timestamp:'2026-10-16T15:44:21.323456789Z',
      content:'{"event":"alert","src":"192.0.2.1","dst":"198.51.100.1"}',
    });
    expect(parsed.events[2].content).toContain('LEEF:2.0');
  });

  it('keeps independent stdout/stderr partial state bounded',()=>{
    const raw=[
      '2026-10-16T15:44:21Z stdout P alpha-',
      '2026-10-16T15:44:21Z stderr P error-',
      '2026-10-16T15:44:22Z stdout F omega',
      '2026-10-16T15:44:22Z stderr F done',
    ].join('\n')+'\n';
    const parsed=parseCriLogStream(raw);
    expect(parsed.ok).toBe(true);
    if(parsed.ok){
      expect(parsed.events.map(event=>event.content)).toEqual(['alpha-omega','error-done']);
      expect(parsed.events.map(event=>event.fragments)).toEqual([2,2]);
    }
  });

  it('rejects malformed CRI timestamps, streams, tags, empty records and dangling partials',()=>{
    const invalid=[
      '2026-02-30T15:44:21Z stdout F bad\n',
      '2026-10-16T25:44:21Z stdout F bad\n',
      '2026-10-16T15:44:21Z console F bad\n',
      '2026-10-16T15:44:21Z stdout X bad\n',
      '2026-10-16T15:44:21Z stdout P incomplete\n',
      '2026-10-16T15:44:21Z stdout F ok\n\n',
      '2026-10-16T15:44:21Z stdout F ok\r\n',
    ];
    const accepted=invalid.filter(raw=>parseCriLogStream(raw).ok);
    console.log('CRI_LOG_INVALID '+JSON.stringify({total:invalid.length,accepted:accepted.length}));
    expect(accepted).toEqual([]);
  });

  it('parses Docker json-file records and preserves original plus normalized content',()=>{
    const one={log:'{"event":"alert","src":"192.0.2.1"}\n',stream:'stdout',time:'2026-10-16T15:44:21.123456789Z'};
    const two={log:'CEF:1|Vendor|EDR|1|42|Threat|8|src=192.0.2.2\n',stream:'stderr',time:'2026-10-16T15:44:22+09:00',attrs:{pod:'sensor'}};
    const raw=JSON.stringify(one)+'\n'+JSON.stringify(two)+'\n';
    expect(looksLikeDockerJsonLogStream(raw)).toBe(true);
    const parsed=parseDockerJsonLogStream(raw);
    expect(parsed.ok).toBe(true);
    if(!parsed.ok)return;
    expect(parsed.events).toHaveLength(2);
    expect(parsed.events[0]).toMatchObject({stream:'stdout',log:one.log,content:'{"event":"alert","src":"192.0.2.1"}'});
    expect(parsed.events[1].extra).toEqual({attrs:{pod:'sensor'}});
  });

  it('rejects malformed Docker json-file required fields and unsafe objects',()=>{
    const valid={log:'ok\n',stream:'stdout',time:'2026-10-16T15:44:21Z'};
    const invalid=[
      JSON.stringify(valid),
      JSON.stringify({...valid,time:'2026-02-30T15:44:21Z'})+'\n',
      JSON.stringify({...valid,stream:'console'})+'\n',
      JSON.stringify({stream:'stdout',time:'2026-10-16T15:44:21Z'})+'\n',
      '{"log":"ok","stream":"stdout","time":}\n',
      '{"log":"ok","stream":"stdout","time":"2026-10-16T15:44:21Z","constructor":"bad"}\n',
      JSON.stringify(valid)+'\n\n',
    ];
    const accepted=invalid.filter(raw=>parseDockerJsonLogStream(raw).ok);
    console.log('DOCKER_JSON_LOG_INVALID '+JSON.stringify({total:invalid.length,accepted:accepted.length}));
    expect(accepted).toEqual([]);
  });
});
