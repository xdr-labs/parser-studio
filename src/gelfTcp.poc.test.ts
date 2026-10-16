import {describe,expect,it} from 'vitest';
import {parseGelfTcpStream} from './gelfTcp';

const messages=[
  {version:'1.1',host:'endpoint-01',short_message:'Malware blocked',timestamp:1792152261.123,level:4,_src_ip:'192.0.2.10',_dst_ip:'198.51.100.20'},
  {version:'1.1',host:'fw01',short_message:'Connection denied',full_message:'Policy blocked outbound connection',level:5,_action:'deny',_src_port:51514},
] as const;

describe('GELF TCP NUL-framing PoC',()=>{
  it('splits and validates multiple GELF 1.1 JSON messages on one TCP stream',()=>{
    const raw=messages.map(message=>JSON.stringify(message)).join('\0')+'\0';
    const parsed=parseGelfTcpStream(raw);
    expect(parsed.ok).toBe(true);
    if(!parsed.ok)return;
    expect(parsed.messages).toHaveLength(2);
    expect(parsed.messages[0].fields).toMatchObject({version:'1.1',host:'endpoint-01',short_message:'Malware blocked',_src_ip:'192.0.2.10'});
    expect(parsed.messages[1].fields).toMatchObject({host:'fw01',level:5,_action:'deny'});
    expect(parsed.messages[0].raw).toBe(JSON.stringify(messages[0]));
    console.log('GELF_TCP '+JSON.stringify({messages:parsed.messages.length}));
  });

  it('preserves nested/array additional values without treating them as framing',()=>{
    const value={version:'1.1',host:'ndr01',short_message:'DNS anomaly',_answers:['192.0.2.53','2001:db8::53'],_meta:{sensor:'east'}};
    const parsed=parseGelfTcpStream(JSON.stringify(value)+'\0');
    expect(parsed.ok).toBe(true);
    if(parsed.ok)expect(parsed.messages[0].fields).toEqual(value);
  });

  it('rejects missing terminators, empty frames, wrong versions, missing required fields, unsafe keys, and invalid level/timestamp',()=>{
    const valid=JSON.stringify(messages[0]);
    const invalid=[
      valid,
      valid+'\0\0',
      JSON.stringify({...messages[0],version:'1.0'})+'\0',
      JSON.stringify({version:'1.1',host:'x'})+'\0',
      JSON.stringify({...messages[0],host:''})+'\0',
      JSON.stringify({...messages[0],level:9})+'\0',
      JSON.stringify({...messages[0],timestamp:-1})+'\0',
      '{"version":"1.1","host":"x","short_message":"broken"\0',
      '{"version":"1.1","host":"x","short_message":"ok","constructor":"bad"}\0',
    ];
    const accepted=invalid.filter(raw=>parseGelfTcpStream(raw).ok);
    console.log('GELF_TCP_INVALID '+JSON.stringify({total:invalid.length,accepted:accepted.length}));
    expect(accepted).toEqual([]);
  });
});
