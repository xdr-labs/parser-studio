import {describe,expect,it} from 'vitest';
import {extractGenericStructural} from './genericStructural';

const bodies=[
  {id:'cee',text:'@cee: {"event":"block","src":"192.0.2.1","dst":"198.51.100.1"}'},
  {id:'embedded',text:'security payload {"event":"alert","src":"192.0.2.2","dst":"198.51.100.2"}'},
] as const;

const wrappers=[
  (body:string)=>'<134>Oct 16 15:44:21 EDGE01 app: '+body,
  (body:string)=>'<134>Oct 16 2026 15:44:21 EDGE01 app: '+body,
  (body:string)=>'<134>2026-10-16T15:44:21Z EDGE01 app: '+body,
  (body:string)=>'<134>1 2026-10-16T15:44:21Z EDGE01 app 123 EVENT - '+body,
] as const;

describe('bounded embedded JSON expansion PoC',()=>{
  it('measures CEE and embedded JSON across wrappers',()=>{
    const rows=[] as Array<{id:string;wrapper:number;structured:boolean;mode?:string}>;
    for(const body of bodies){
      wrappers.forEach((wrap,index)=>{
        const parsed=extractGenericStructural(wrap(body.text));
        const generic=parsed.fields.generic as {mode?:string}|undefined;
        rows.push({
          id:body.id,wrapper:index,
          structured:parsed.errors.length===0&&!!parsed.fields.body,
          mode:generic?.mode,
        });
      });
    }
    const summary={
      total:rows.length,
      structured:rows.filter(row=>row.structured).length,
      byBody:Object.fromEntries(bodies.map(body=>[
        body.id,rows.filter(row=>row.id===body.id&&row.structured).length,
      ])),
      failures:rows.filter(row=>!row.structured).map(row=>row.id+'#'+row.wrapper),
    };
    console.log('EMBEDDED_JSON_EXPANSION '+JSON.stringify(summary));
    expect(summary.total).toBe(8);
    expect(summary.structured).toBe(8);
    expect(summary.failures).toEqual([]);
  });

  it('rejects truncated, array, and trailing-content candidates',()=>{
    const invalid=[
      'prefix {"event":"alert"',
      'prefix [1,2,3]',
      'prefix {"event":"alert"} trailing',
      '@cee: {"event":"alert"} trailing',
      '@cee: [1,2,3]',
      'CEF:2|Vendor|EDR|1.0|42|Bad|9|payload={"event":"alert"}',
      'LEEF:9.0|Vendor|NDR|1.0|dns|payload={"event":"alert"}',
      'prefix {not-json}',
    ];
    const structured=invalid.filter(body=>{
      const raw='<134>1 2026-10-16T15:44:21Z EDGE01 app 123 EVENT - '+body;
      const parsed=extractGenericStructural(raw);
      return parsed.errors.length===0&&!!parsed.fields.body;
    });
    console.log('EMBEDDED_JSON_INVALID '+JSON.stringify({total:invalid.length,structured}));
    expect(structured).toEqual([]);
  });
});
