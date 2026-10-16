import {describe,expect,it} from 'vitest';
import {mapZeekTsvRow,parseZeekFieldsHeader} from './zeekTabular';

const header='#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\torig_bytes\tresp_bytes';
const row='1764958704.891921\tCod6Wj3YeJFHgkaO8j\t192.0.2.10\t51514\t198.51.100.20\t443\ttcp\tssl\t1.245\t1200\t3400';

describe('Zeek #fields schema-aware TSV PoC',()=>{
  it('maps a data row using the explicit Zeek field header',()=>{
    const schema=parseZeekFieldsHeader(header);
    expect(schema).not.toBeNull();
    if(!schema)return;
    const mapped=mapZeekTsvRow(row,schema);
    expect(mapped).toMatchObject({
      ts:'1764958704.891921',
      uid:'Cod6Wj3YeJFHgkaO8j',
      'id.orig_h':'192.0.2.10',
      'id.orig_p':'51514',
      'id.resp_h':'198.51.100.20',
      'id.resp_p':'443',
      proto:'tcp',
      service:'ssl',
    });
  });

  it('preserves Zeek unset and empty markers exactly',()=>{
    const schema=parseZeekFieldsHeader('#fields\tts\tuid\ta\tb\tc\td');
    expect(schema).not.toBeNull();
    if(!schema)return;
    expect(mapZeekTsvRow('1.0\tABCDEF12\t-\t(empty)\t0\t',schema)).toMatchObject({a:'-',b:'(empty)',c:'0',d:''});
  });

  it('rejects unsafe, duplicate, malformed, and cardinality-mismatched schemas',()=>{
    const invalidHeaders=[
      '#fields\tts\tuid\tip',
      '#fields\tts\tuid\ta\tb\tc\tconstructor',
      '#fields\tts\tuid\ta\tb\tc\ta',
      '#fields ts uid a b c d',
      '#fields\tts\tuid\ta\tb\tc\tbad field',
    ];
    expect(invalidHeaders.filter(value=>parseZeekFieldsHeader(value)!==null)).toEqual([]);
    const schema=parseZeekFieldsHeader(header)!;
    expect(mapZeekTsvRow(row+'\textra',schema)).toBeNull();
    expect(mapZeekTsvRow(row.split('\t').slice(0,-1).join('\t'),schema)).toBeNull();
  });
});
