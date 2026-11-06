import {describe,expect,it} from 'vitest';
import {createDraft} from './model';
import {preview,extractFields} from './parser';
import {toBackendProject} from './guided/backendAdapter';

const raw='<134>date=2023-02-23 time=22:49:29 devname=FMG-VM log_id=0001010018 type=event user=alice status=success';
function draft(vendor:string){
  return {...createDraft(),name:'Audit fixture',vendor,format:'generic_structural' as const,
    guided:{...createDraft().guided!,groups:{},classification:{defaultIndex:'Syslog' as const,rules:[]}},
    mappings:[{id:'m1',source:'generic.kv.user',target:'injected_user',type:'string' as const}]};
}
function kv(count:number):string{
  return Array.from({length:count},(_,i)=>'field'+String(i).padStart(3,'0')+'=v').join(' ');
}
describe('Audit 2026-11-06 source integrity and KV native contract',()=>{
  it('rejects a vendor name aliasing the source or a runtime namespace',()=>{
    for(const name of ['parserstudio_source','parserstudio_transport','parserstudio_event_family',
      'parser_err_msg','parser_err_field','parser_err_stage','stellar_log_index','msg_origin']){
      const original=preview(raw,draft(name)).events[0]!;
      expect(original.status,name).toBe('fail');
      expect(original.diagnostics.some(d=>d.code==='TARGET_COLLISION'),name).toBe(true);
      expect((original.fields as any).injected_user,name).toBeUndefined();
      expect((original.normalized.parserstudio_source as any).injected_user,name).toBeUndefined();
      expect(toBackendProject(draft(name)).ok,name).toBe(false);
    }
  });
  it('keeps the original extraction object unchanged for a legitimate vendor',()=>{
    const event=preview(raw,draft('Acme')).events[0]!;
    expect(event.diagnostics.some(d=>d.code==='TARGET_COLLISION')).toBe(false);
    expect((event.fields as any).injected_user).toBeUndefined();
    expect((event.normalized.parserstudio_source as any).injected_user).toBeUndefined();
    expect((event.normalized.Acme as any).injected_user).toBe('alice');
    expect(toBackendProject(draft('Acme')).ok).toBe(true);
  });
  it.each([99,100,101,150])('enforces the exact 100 KV field limit for %s keys',count=>{
    const source=kv(count);
    for(const format of ['kv','syslog_rfc3164','syslog_rfc5424'] as const){
      const d=createDraft();
      d.format=format;
      d.syslogBodyFormat='kv';
      const line=format==='kv'?source:format==='syslog_rfc3164'?
        '<134>Nov  6 10:00:00 fw app: '+source:
        '<14>1 2026-11-06T11:11:11Z fw app - id - '+source;
      const extracted=extractFields(line,format,d);
      if(count<=100)expect(extracted.errors,format).toEqual([]);
      else expect(extracted.errors,format).toEqual(expect.arrayContaining([
        expect.stringContaining('KV field limit'),
      ]));
    }
  });
});
