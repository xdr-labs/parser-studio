import {describe,expect,it} from 'vitest';
import {parseRfc4180HeaderCsv} from './rfc4180Csv';

describe('RFC4180 header CSV security-export PoC',()=>{
  it('maps explicit headers and preserves quoted commas, quotes, empty fields, and multiline values',()=>{
    const raw=[
      'timestamp,src_ip,dst_ip,action,message,user',
      '2026-10-16T15:44:21Z,192.0.2.10,198.51.100.20,block,"SQL injection, union select","alice"',
      '2026-10-16T15:44:22Z,2001:db8::10,2001:db8::20,allow,"User said ""hello""",',
      '2026-10-16T15:44:23Z,192.0.2.11,198.51.100.21,alert,"line1\r\nline2",bob',
    ].join('\r\n');
    const parsed=parseRfc4180HeaderCsv(raw);
    expect(parsed.ok).toBe(true);
    if(!parsed.ok)return;
    expect(parsed.table.lineEnding).toBe('crlf');
    expect(parsed.table.header).toEqual(['timestamp','src_ip','dst_ip','action','message','user']);
    expect(parsed.table.rows).toHaveLength(3);
    expect(parsed.table.rows[0]).toMatchObject({action:'block',message:'SQL injection, union select',user:'alice'});
    expect(parsed.table.rows[1]).toMatchObject({src_ip:'2001:db8::10',message:'User said "hello"',user:''});
    expect(parsed.table.rows[2]).toMatchObject({action:'alert',message:'line1\r\nline2',user:'bob'});
  });

  it('accepts uniform LF files and a final record without a line terminator',()=>{
    const raw='time,host,event\n2026-10-16T15:44:21Z,edge01,login\n2026-10-16T15:44:22Z,edge02,logout';
    const parsed=parseRfc4180HeaderCsv(raw);
    expect(parsed.ok).toBe(true);
    if(parsed.ok){
      expect(parsed.table.lineEnding).toBe('lf');
      expect(parsed.table.rows).toHaveLength(2);
      expect(parsed.table.rows[1]).toMatchObject({host:'edge02',event:'logout'});
    }
  });

  it('rejects unsafe headers, duplicate columns, width drift, bad quoting, mixed line endings, and header-only input',()=>{
    const invalid=[
      'timestamp,constructor,event\n1,bad,x\n',
      'timestamp,event,event\n1,x,y\n',
      'timestamp,event\n1,x,extra\n',
      'timestamp,event\n1\n',
      'timestamp,event\n1,"unterminated\n',
      'timestamp,event\n1,bad"quote\n',
      'timestamp,event\r\n1,x\n',
      'timestamp,event\n',
      'timestamp\n1\n',
      ' bad,event\n1,x\n',
    ];
    const accepted=invalid.filter(raw=>parseRfc4180HeaderCsv(raw).ok);
    console.log('RFC4180_INVALID '+JSON.stringify({total:invalid.length,accepted:accepted.length}));
    expect(accepted).toEqual([]);
  });
});
