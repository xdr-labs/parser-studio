import {describe,expect,it} from 'vitest';
import {extractGenericStructural} from './genericStructural';
import {parseSyslogEnvelope} from './syslogEnvelope';

const bodies=[
  {id:'checkpoint-pipe',text:'action=Accept|src=192.0.2.10|dst=198.51.100.20|service=443|product=VPN-1 & FireWall-1'},
  {id:'logrhythm-pipe',text:'action=Drop|src=192.0.2.11|dst=198.51.100.21|proto=tcp|rule=Internet_Block'},
  {id:'zscaler-tab-4',text:'action=Allowed\tuser=alice@example.test\turl=https://example.test/a\tsrc=192.0.2.12'},
  {id:'zscaler-tab-quoted',text:'action=Blocked\tuser="Alice Example"\turl=https://bad.example.test/\treason="Policy Block"'},
  {id:'semicolon-equals',text:'action=block; src=192.0.2.13; dst=198.51.100.23; rule=deny_web; reason="bad category"'},
  {id:'pipe-escaped-value',text:'action=block|src=192.0.2.14|dst=198.51.100.24|note="left\\|right"|rule=web'},
] as const;

const wrappers=[
  (body:string)=>'<134>Oct 16 15:44:21 EDGE01 app: '+body,
  (body:string)=>'<134>Oct 16 2026 15:44:21 EDGE01 app: '+body,
  (body:string)=>'<134>2026-10-16T15:44:21Z EDGE01 app: '+body,
  (body:string)=>'<134>2026-10-16 15:44:21.123 +0900 EDGE01 app: '+body,
] as const;

describe('delimiter-aware KV body expansion PoC',()=>{
  it('measures current cross-wrapper coverage',()=>{
    const rows=[] as Array<{body:string;wrapper:number;ok:boolean}>;
    for(const body of bodies){
      wrappers.forEach((wrap,index)=>{
        const raw=wrap(body.text);
        expect(parseSyslogEnvelope(raw),raw).not.toBeNull();
        const parsed=extractGenericStructural(raw);
        const generic=parsed.fields.generic as {mode?:string;kv?:Record<string,unknown>}|undefined;
        rows.push({
          body:body.id,
          wrapper:index,
          ok:parsed.errors.length===0&&
            generic?.mode==='syslog_envelope_delimited_kv'&&
            typeof generic.kv?.action==='string',
        });
      });
    }
    const summary={
      total:rows.length,
      parsed:rows.filter(row=>row.ok).length,
      byBody:Object.fromEntries(bodies.map(body=>[
        body.id,
        rows.filter(row=>row.body===body.id&&row.ok).length,
      ])),
      failures:rows.filter(row=>!row.ok).map(row=>bodyKey(row.body,row.wrapper)),
    };
    console.log('DELIMITED_KV_EXPANSION '+JSON.stringify(summary));
    expect(summary.total).toBe(24);
    expect(summary.parsed).toBe(24);
    expect(summary.failures).toEqual([]);
  });

  it('rejects malformed delimiter KV shapes',()=>{
    const malformed=[
      'action=block|src=192.0.2.1|broken|dst=198.51.100.1',
      'action=block|constructor=bad|dst=198.51.100.1',
      'action=block; src="unterminated; dst=198.51.100.1; rule=x',
      'action=block||src=192.0.2.1||dst=198.51.100.1',
      'one=1|two=2',
    ];
    const accepted=malformed.filter(body=>
      extractGenericStructural('<134>2026-10-16T15:44:21Z EDGE01 app: '+body).errors.length===0
    );
    console.log('DELIMITED_KV_MALFORMED '+JSON.stringify({total:malformed.length,accepted}));
    expect(accepted).toEqual([]);
  });
});

function bodyKey(body:string,wrapper:number):string{
  return body+'#'+wrapper;
}
