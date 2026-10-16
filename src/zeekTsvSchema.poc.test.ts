import {describe,expect,it} from 'vitest';
import {parseZeekTsvBlock} from './zeekTabular';

const block=[
  '#separator \\x09',
  '#set_separator\t,',
  '#empty_field\t(empty)',
  '#unset_field\t-',
  '#path\tconn',
  '#open\t2026-10-16-15-44-21',
  '#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice',
  '#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tstring',
  '1764958704.891921\tCod6Wj3YeJFHgkaO8j\t192.0.2.10\t51514\t198.51.100.20\t443\ttcp\tssl',
  '1764958705.001122\tCZx0a13abcDEF45678\t2001:db8::10\t53\t2001:db8::53\t53\tudp\tdns',
  '#close\t2026-10-16-15-45-00',
].join('\n')+'\n';

describe('Zeek schema-aware TSV block PoC',()=>{
  it('maps positional TSV rows to authoritative #fields names without semantic guessing',()=>{
    const parsed=parseZeekTsvBlock(block);
    expect(parsed.ok).toBe(true);
    if(!parsed.ok)return;
    expect(parsed.block.path).toBe('conn');
    expect(parsed.block.fields).toEqual(['ts','uid','id.orig_h','id.orig_p','id.resp_h','id.resp_p','proto','service']);
    expect(parsed.block.types).toEqual(['time','string','addr','port','addr','port','enum','string']);
    expect(parsed.block.rows).toHaveLength(2);
    expect(parsed.block.rows[0]).toMatchObject({
      ts:'1764958704.891921',uid:'Cod6Wj3YeJFHgkaO8j','id.orig_h':'192.0.2.10','id.orig_p':'51514',
      'id.resp_h':'198.51.100.20','id.resp_p':'443',proto:'tcp',service:'ssl',
    });
    expect(parsed.block.rows[1]).toMatchObject({'id.orig_h':'2001:db8::10','id.resp_h':'2001:db8::53',proto:'udp',service:'dns'});
    console.log('ZEEK_SCHEMA_BLOCK '+JSON.stringify({rows:parsed.block.rows.length,fields:parsed.block.fields.length,path:parsed.block.path}));
  });

  it('rejects duplicate/unsafe schemas and row-width drift',()=>{
    const invalid=[
      block.replace('#fields\tts\tuid\tid.orig_h', '#fields\tts\tuid\tuid'),
      block.replace('#fields\tts\tuid\tid.orig_h', '#fields\tts\tconstructor\tid.orig_h'),
      block.replace('#types\ttime\tstring\taddr', '#types\ttime\tstring'),
      block.replace('\tssl\n', '\n'),
      block.replace('#separator \\x09','#separator \\x2c'),
      block.replace('#fields\tts\tuid', '#fields\tts\tuid\n#fields\tts\tuid'),
    ];
    const accepted=invalid.filter(raw=>parseZeekTsvBlock(raw).ok);
    console.log('ZEEK_SCHEMA_INVALID '+JSON.stringify({total:invalid.length,accepted:accepted.length}));
    expect(accepted).toEqual([]);
  });
});
