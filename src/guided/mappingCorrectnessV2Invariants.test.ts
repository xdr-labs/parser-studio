import {describe,expect,it} from 'vitest';
import {createDraft} from '../model';
import {preview} from '../parser';
import {planVendorFieldNames} from './vendorFieldNames';
import {suggestUnmappedFieldPlan} from './fieldMappingSuggestions';
import {reconcileGeneratedMappings} from './generatedMappingReconciliation';

const overlap=(a:string,b:string)=>a===b||a.startsWith(b+'.')||b.startsWith(a+'.');
const choices=(s:string)=>[s,s.split('.').at(-1)!];
// Independent bounded oracle: exhaustive subset assignment, NOT the 2-SAT
// algorithm's own output, determines whether a lossless assignment exists.
function oracleExists(sources:string[],occupied:string[]):boolean{
  const n=sources.length;
  for(let bits=0;bits<2**n;bits++){
    const selected=sources.map((s,i)=>choices(s)[(bits>>i)&1]!);
    if(selected.some(s=>occupied.some(t=>overlap(s,t))))continue;
    if(selected.some((s,i)=>selected.some((t,j)=>i!==j&&overlap(s,t))))continue;
    return true;
  }
  return false;
}
function random(seed:number){
  let value=seed>>>0;
  return ()=>{value^=value<<13;value^=value>>>17;value^=value<<5;return value>>>0;};
}

describe('Mapping Correctness v2 invariant-first executable contract',()=>{
  it('preserves source identity and destination uniqueness for 512 independently seeded allocation cases',()=>{
    const parts=['a','b','c','d','ip','src','dst','meta','http'];
    for(let seed=1;seed<=512;seed++){
      const next=random(seed),n=2+(next()%7),seen=new Set<string>();
      while(seen.size<n){
        const parent=parts[next()%parts.length]!;
        const leaf=parts[next()%parts.length]!;
        seen.add(next()%3===0?leaf:parent+'.'+leaf);
      }
      const sources=[...seen];
      const occupied=seed%3===0?[choices(sources[next()%sources.length]!)[next()%2]!] : [];
      const truth=oracleExists(sources,occupied);
      const plan=planVendorFieldNames(sources,occupied);
      const reversed=planVendorFieldNames([...sources].reverse(),occupied);
      expect(Object.fromEntries(plan.names),'seed '+seed+' deterministic').toEqual(Object.fromEntries(reversed.names));
      expect(plan.unresolved,'seed '+seed+' consistency').toEqual(reversed.unresolved);
      if(!truth){
        expect(plan.names.size,'seed '+seed+' must fail closed').toBe(0);
        expect([...plan.unresolved].sort(),'seed '+seed+' unresolved census')
          .toEqual([...sources].sort());
        continue;
      }
      expect(plan.unresolved,'seed '+seed+' no silent loss').toEqual([]);
      expect(plan.names.size,'seed '+seed+' all source paths').toBe(sources.length);
      const destinations=[...plan.names.values()];
      for(const [source,target] of plan.names){
        expect(choices(source),'seed '+seed+' source identity').toContain(target);
        expect(occupied.some(x=>overlap(x,target)),'seed '+seed+' occupied collision').toBe(false);
      }
      for(let i=0;i<destinations.length;i++)for(let j=i+1;j<destinations.length;j++)
        expect(overlap(destinations[i]!,destinations[j]!),'seed '+seed+' dest collision').toBe(false);
    }
  });

  it('reports impossible occupied destinations, not a successful but lossy suggestion',()=>{
    const draft=createDraft();
    draft.mappings=[{id:'existing-1',source:'old_a',target:'status',type:'string'},
      {id:'existing-2',source:'old_b',target:'http.status',type:'string'}];
    const result=suggestUnmappedFieldPlan([{http:{status:'403'}}],draft);
    expect(result.suggestions).toEqual([]);
    expect(result.unresolved).toEqual(['http.status']);
  });

  it('accounts for all paths above the 100-field proposal budget without silently discarding them',()=>{
    const draft=createDraft();draft.mappings=[];
    const source=Object.fromEntries(Array.from({length:150},(_,i)=>[
      'source_field_'+String(i).padStart(3,'0'),String(i)]));
    const result=suggestUnmappedFieldPlan([source],draft);
    expect(result.suggestions).toHaveLength(100);
    expect(result.unresolved.length+result.suggestions.length+
      result.unaddressableValues).toBeGreaterThanOrEqual(150);
  });

  it('holds legacy unknown provenance unchanged after save/restore and reanalysis',()=>{
    const original=createDraft();
    original.format='json';
    original.mappings=[{id:'auto-1',source:'http.status',target:'http.status',type:'string',
      authoring:{version:1,origin:'USER_EDITED'}}];
    original.guided={...original.guided!,groups:{'auto-1':'vendor_fields'}};
    const saved=JSON.parse(JSON.stringify(original)) as typeof original;
    for(let i=0;i<3;i++){
      const after=reconcileGeneratedMappings(saved,preview('{"http":{"status":200}}',saved));
      expect(after.mappings[0]).toEqual(original.mappings[0]);
      expect(after.guided?.groups).toEqual(original.guided?.groups);
    }
    const old={...saved,mappings:[{...saved.mappings[0]!,authoring:undefined}]};
    expect(reconcileGeneratedMappings(old,preview('{"http":{"status":200}}',old)).mappings)
      .toEqual(old.mappings);
  });
});
