import {describe,expect,it} from 'vitest';
import {createDraft} from '../model';
import {preview} from '../parser';
import {toBackendProject} from './backendAdapter';
import {selectDraftFormat} from './draftFormatTransition';
import {reconstructExactBackendDraft} from './pairProjectImport';

const LOG='<134>date=2023-02-23 time=22:49:29 devname=FMG-VM log_id=0001010018 type=event user=alice status=success';
const generic=()=>({...createDraft(),format:'generic_structural' as const,
  vendor:'Acme',name:'Gate',
  guided:{...createDraft().guided!,classification:{rules:[],defaultIndex:'syslog' as const}},
  mappings:[{id:'m-user',source:'generic.kv.user',target:'custom.username',type:'string' as const}]});

function sourceOf(draft:ReturnType<typeof generic>):Record<string,unknown>{
  const event=preview(LOG,draft).events[0]!;
  return event.normalized.parserstudio_source as Record<string,unknown>;
}
function hasKey(value:unknown,key:string):boolean{
  if(!value||typeof value!=='object')return false;
  if(Array.isArray(value))return value.some(v=>hasKey(v,key));
  return Object.entries(value as Record<string,unknown>).some(([k,v])=>k===key||hasKey(v,key));
}

describe('Generic Structural: copying the full raw line is switchable',()=>{
  it('keeps source_raw by default',()=>{
    expect(hasKey(sourceOf(generic()),'source_raw')).toBe(true);
  });
  it('leaves source_raw out of parserstudio_source when switched off, but keeps the parsed fields',()=>{
    const source=sourceOf({...generic(),omitSourceRaw:true});
    expect(hasKey(source,'source_raw')).toBe(false);
    expect(JSON.stringify(source)).toContain('alice');
  });
  it('reaches the backend project only when switched off, and only for Generic Structural',()=>{
    const on=toBackendProject({...generic(),omitSourceRaw:true});
    expect(on.ok&&on.project.extraction).toMatchObject({format:'generic_structural',omitSourceRaw:true});
    const off=toBackendProject(generic());
    expect(off.ok&&'omitSourceRaw' in off.project.extraction).toBe(false);
    const wrong=toBackendProject({...createDraft(),format:'json',omitSourceRaw:true});
    expect(wrong.ok).toBe(false);
  });
  it('is retired when another format is chosen',()=>{
    const next=selectDraftFormat({...generic(),omitSourceRaw:true},'json');
    expect('omitSourceRaw' in next).toBe(false);
  });
  it('round-trips through a backend project import',()=>{
    const draft={...createDraft(),format:'generic_structural' as const,vendor:'Acme',name:'Gate',
      omitSourceRaw:true as const,genericStructuralProfile:'syslog_prefix_kv' as const};
    const project=toBackendProject(draft);
    expect(project.ok).toBe(true);
    if(!project.ok)return;
    const imported=reconstructExactBackendDraft(project.project,'customized_'+project.project.slug);
    expect(imported?.omitSourceRaw).toBe(true);
  });
});
