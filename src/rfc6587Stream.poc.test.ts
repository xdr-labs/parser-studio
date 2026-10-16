import {describe,expect,it} from 'vitest';
import {extractGenericStructural} from './genericStructural';
import {splitSyslogStream} from './syslogFraming';

const messages=[
  '<134>Oct 16 15:44:21 EDR01 agent: CEF:0|Vendor|EDR|1.0|42|Malware|9|src=10.0.0.8 dst=198.51.100.8',
  '<134>2026-10-16T15:44:21Z IDS01 sensor: {"event_type":"alert","src_ip":"10.0.0.2","dest_ip":"198.51.100.2"}',
  '<134>2026-10-16T15:44:21Z ZEEK01 zeek: 1764958704.891921\tCod6Wj3YeJFHgkaO8j\t192.0.2.10\t51514\t198.51.100.20\t443\ttcp\tssl',
  '<134>2026-10-16T15:44:21Z WIN01 winlog: <Event><System><EventID>4625</EventID><Computer>WIN01</Computer><Channel>Security</Channel></System><EventData><Data Name="TargetUserName">alice</Data><Data Name="IpAddress">192.0.2.10</Data><Data Name="IpPort">51514</Data></EventData></Event>',
] as const;

function octetFrame(message:string):string{
  return new TextEncoder().encode(message).byteLength+' '+message;
}

describe('RFC6587 multi-record stream PoC',()=>{
  it('splits concatenated octet-counted records by UTF-8 byte length',()=>{
    const unicode=messages[0].replace('Malware','Mälware');
    const expected=[unicode,...messages.slice(1)];
    const stream=expected.map(octetFrame).join('');
    const split=splitSyslogStream(stream);
    expect(split).toMatchObject({ok:true,mode:'rfc6587_octet_counting_stream'});
    if(!split.ok)return;
    expect(split.records).toEqual(expected);
    const parsed=split.records.map(record=>extractGenericStructural(record));
    expect(parsed.every(result=>result.errors.length===0)).toBe(true);
    console.log('RFC6587_STREAM_OCTET '+JSON.stringify({records:split.records.length,parsed:parsed.filter(result=>!result.errors.length).length}));
  });

  it('splits bounded LF, CRLF, and NUL non-transparent streams',()=>{
    for(const delimiter of ['\n','\r\n','\0']){
      const stream=messages.join(delimiter)+delimiter;
      const split=splitSyslogStream(stream);
      expect(split.ok,JSON.stringify(delimiter)).toBe(true);
      if(!split.ok)continue;
      expect(split.records).toEqual(messages);
      expect(split.records.every(record=>extractGenericStructural(record).errors.length===0)).toBe(true);
    }
  });

  it('rejects truncation, malformed counts, mixed delimiters, invalid UTF-8 boundaries, and empty frames',()=>{
    const first=messages[0];
    const bytes=new TextEncoder().encode(first).byteLength;
    const emoji=first+'😀';
    const emojiBytes=new TextEncoder().encode(emoji).byteLength;
    const invalid=[
      String(bytes+1)+' '+first,
      '00 '+first,
      'x '+first,
      octetFrame(first)+'3 <1',
      messages[0]+'\n'+messages[1]+'\0',
      messages[0]+'\n\n',
      messages[0]+'\0'+messages[1],
      String(emojiBytes-1)+' '+emoji,
    ];
    const accepted=invalid.filter(stream=>splitSyslogStream(stream).ok);
    console.log('RFC6587_STREAM_INVALID '+JSON.stringify({total:invalid.length,accepted}));
    expect(accepted).toEqual([]);
  });
});
