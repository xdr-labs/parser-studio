import {describe,expect,it} from 'vitest';
import {parseNdjsonObjectStream} from './ndjsonStream';

const objects=[
  {timestamp:'2026-10-16T15:44:21Z',event_type:'alert',src_ip:'192.0.2.10',dest_ip:'198.51.100.20',alert:{signature:'ET TEST'}},
  {eventVersion:'1.10',eventSource:'signin.amazonaws.com',eventName:'ConsoleLogin',sourceIPAddress:'192.0.2.11',responseElements:{ConsoleLogin:'Success'}},
  {vendor:'ExampleEDR',host:'endpoint-01',severity:8,process:{name:'powershell.exe',command_line:'Write-Output \\n literal'}},
] as const;

function encode(lineEnding:'\n'|'\r\n'):string{
  return objects.map(value=>JSON.stringify(value)).join(lineEnding)+lineEnding;
}

describe('NDJSON security-event stream PoC',()=>{
  it('parses bounded LF and CRLF object streams while preserving raw records',()=>{
    for(const [ending,kind] of [['\n','lf'],['\r\n','crlf']] as const){
      const raw=encode(ending);
      const parsed=parseNdjsonObjectStream(raw);
      expect(parsed.ok,kind).toBe(true);
      if(!parsed.ok)continue;
      expect(parsed.stream.lineEnding).toBe(kind);
      expect(parsed.stream.records).toEqual(objects);
      expect(parsed.stream.rawRecords).toEqual(objects.map(value=>JSON.stringify(value)));
    }
  });

  it('preserves nested arrays and escaped newlines inside JSON strings',()=>{
    const raw=JSON.stringify({event:'dns',answers:['192.0.2.1','2001:db8::1'],message:'line1\nline2'})+'\n';
    const parsed=parseNdjsonObjectStream(raw);
    expect(parsed.ok).toBe(true);
    if(parsed.ok)expect(parsed.stream.records[0]).toMatchObject({answers:['192.0.2.1','2001:db8::1'],message:'line1\nline2'});
  });

  it('rejects malformed framing, non-object records, and unsafe object keys',()=>{
    const valid=encode('\n');
    const invalid=[
      valid.slice(0,-1),
      JSON.stringify(objects[0])+'\n\n'+JSON.stringify(objects[1])+'\n',
      JSON.stringify(objects[0])+'\r\n'+JSON.stringify(objects[1])+'\n',
      '[1,2,3]\n',
      '42\n',
      'null\n',
      '{"event":"alert"\n',
      '{"constructor":"bad","event":"alert"}\n',
      '{"__proto__":{"polluted":true},"event":"alert"}\n',
      '{"prototype":"bad","event":"alert"}\n',
    ];
    const accepted=invalid.filter(raw=>parseNdjsonObjectStream(raw).ok);
    console.log('NDJSON_INVALID '+JSON.stringify({total:invalid.length,accepted:accepted.length}));
    expect(accepted).toEqual([]);
  });
});
