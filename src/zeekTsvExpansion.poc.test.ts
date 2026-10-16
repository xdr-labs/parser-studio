import {describe,expect,it} from 'vitest';
import {extractGenericStructural} from './genericStructural';

const conn='1764958704.891921\tCod6Wj3YeJFHgkaO8j\t192.0.2.10\t51514\t198.51.100.20\t443\ttcp\tssl\t1.245\t1200\t3400\tSF\t-\t-\t0\tShADadFf\t10\t1720\t12\t4040\t-\t6';

const samples=[
  conn,
  '<134>Oct 16 15:44:21 ZEEK01 zeek: '+conn,
  '<134>Oct 16 2026 15:44:21 ZEEK01 zeek: '+conn,
  '<134>2026-10-16T15:44:21Z ZEEK01 zeek: '+conn,
  '<134>1 2026-10-16T15:44:21Z ZEEK01 zeek 991 CONN - '+conn,
] as const;

describe('Zeek conn TSV structural PoC',()=>{
  it('preserves standalone and Syslog-wrapped Zeek conn values as positional TSV',()=>{
    const parsed=samples.map(raw=>extractGenericStructural(raw));
    const failures=parsed.map((result,index)=>({index,result})).filter(row=>row.result.errors.length);
    console.log('ZEEK_TSV_BODY '+JSON.stringify({total:parsed.length,parsed:parsed.length-failures.length,failures:failures.map(row=>row.index)}));
    expect(failures).toEqual([]);
    for(const result of parsed){
      const generic=result.fields.generic as {mode?:string;profile?:string;columns?:Record<string,string>}|undefined;
      expect(generic?.profile).toBe('zeek_conn_candidate');
      expect(generic?.columns).toMatchObject({
        column_0:'1764958704.891921',
        column_1:'Cod6Wj3YeJFHgkaO8j',
        column_2:'192.0.2.10',
        column_3:'51514',
        column_4:'198.51.100.20',
        column_5:'443',
        column_6:'tcp',
      });
    }
  });

  it('supports IPv6 Zeek endpoints without weakening tuple validation',()=>{
    const ipv6=conn.replace('192.0.2.10','2001:db8::10').replace('198.51.100.20','2001:db8::20');
    const parsed=extractGenericStructural('<134>2026-10-16T15:44:21Z ZEEK01 zeek: '+ipv6);
    expect(parsed.errors).toEqual([]);
    expect((parsed.fields.generic as {columns:Record<string,string>}).columns.column_2).toBe('2001:db8::10');
  });

  it('does not promote malformed or metadata-only TSV rows',()=>{
    const invalid=[
      '#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto',
      'bad-ts\tCod6Wj3YeJFHgkaO8j\t192.0.2.10\t51514\t198.51.100.20\t443\ttcp',
      '1764958704.891921\tbad!uid\t192.0.2.10\t51514\t198.51.100.20\t443\ttcp',
      '1764958704.891921\tCod6Wj3YeJFHgkaO8j\t999.0.0.1\t51514\t198.51.100.20\t443\ttcp',
      '1764958704.891921\tCod6Wj3YeJFHgkaO8j\t192.0.2.10\t70000\t198.51.100.20\t443\ttcp',
      '1764958704.891921\tCod6Wj3YeJFHgkaO8j\t192.0.2.10\t51514\t198.51.100.20\t443\thttp',
    ];
    const accepted=invalid.filter(raw=>extractGenericStructural(raw).errors.length===0);
    console.log('ZEEK_TSV_INVALID '+JSON.stringify({total:invalid.length,accepted}));
    expect(accepted).toEqual([]);
  });
});
