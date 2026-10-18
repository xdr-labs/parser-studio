import type {EventResult,SuiteResult} from '../model';
import {listSafeLeafPaths,lookupFieldValue} from '../fieldPaths';

export interface UnionField {
  source:string;
  populated:number;
  blank:number;
  missing:number;
  optional:boolean;
  semanticStatus:'SOURCE_FIELD_NAME'|'POSITIONAL_UNVERIFIED';
}
export interface UnionGroup{
  id:string;format:string;eventType:string|null;
  sampleNumbers:number[];fields:UnionField[];
}
export interface SampleUnionSchema{
  totalEvents:number;reviewed:number;maxExamples:10;
  groups:UnionGroup[];unscorable:number;moreSamplesNotUsed:number;
  meaning:'STRUCTURAL_SAMPLE_COVERAGE_ONLY';
}
const safe=(value:string):boolean=>value.length<=128&&
  /^[A-Za-z_][A-Za-z0-9_.-]*(?:\.[A-Za-z_][A-Za-z0-9_.-]*)*$/.test(value)&&
  !value.split('.').some(part=>['__proto__','constructor','prototype'].includes(part));
const pathSet=(event:EventResult)=>new Set(
  listSafeLeafPaths(event.fields).filter(safe));
const usableType=(event:EventResult,source:string)=>{
  const found=lookupFieldValue(event.fields,source);
  return found.found&&typeof found.value==='string'&&
    found.value.length>0&&found.value.length<=128&&
    !/[\x00-\x1f\x7f]/.test(found.value)?found.value:null;
};
const blank=(value:unknown)=>value===undefined||value===null||
  typeof value==='string'&&value.trim()==='';
function familyKey(event:EventResult,type:string|null):string{
  // Family labels and positional widths are orthogonal. Do not merge
  // different positional columns merely because the type name is identical.
  const csv=event.effectiveFormat==='csv'||event.detected.format==='csv';
  const width=csv?pathSet(event).size:0;
  return JSON.stringify([event.effectiveFormat,type,csv?width:null]);
}
export function buildSampleUnionSchema(
  suite:SuiteResult|undefined,discriminator='event_type',
):SampleUnionSchema{
  const events=suite?.events??[];
  const eligible=events.flatMap((event,index)=>
    event.extracted&&event.fields&&Object.keys(event.fields).length?
      [{event,index,type:safe(discriminator)?usableType(event,discriminator):null}]:[]);
  // Greedy structural coverage: favor first events from new formats/types,
  // then samples that add previously unseen populated fields to a group.
  // Deterministic ties preserve original input order.
  const chosen:typeof eligible=[];
  const remaining=[...eligible];
  const chosenGroups=new Map<string,Set<string>>();
  while(chosen.length<10&&remaining.length){
    let pick=0,high=-Infinity;
    for(let i=0;i<remaining.length;i++){
      const item=remaining[i]!;
      const key=familyKey(item.event,item.type);
      const prior=chosenGroups.get(key);
      const paths=pathSet(item.event);
      const novel=[...paths].filter(name=>{
        const selected=lookupFieldValue(item.event.fields,name);
        return selected.found&&!blank(selected.value)&&!prior?.has(name);
      }).length;
      const score=(prior?0:1000)+novel;
      if(score>high){high=score;pick=i;}
    }
    const [next]=remaining.splice(pick,1);
    if(!next)break;
    chosen.push(next);
    const key=familyKey(next.event,next.type);
    const seen=chosenGroups.get(key)??new Set<string>();
    for(const path of pathSet(next.event)){
      const found=lookupFieldValue(next.event.fields,path);
      if(found.found&&!blank(found.value))seen.add(path);
    }
    chosenGroups.set(key,seen);
  }
  const groups=new Map<string,{format:string;eventType:string|null;selected:typeof eligible}>();
  for(const item of chosen){
    const key=familyKey(item.event,item.type);
    const existing=groups.get(key);
    if(existing)existing.selected.push(item);
    else groups.set(key,{format:item.event.effectiveFormat,eventType:item.type,selected:[item]});
  }
  const output=[...groups.entries()].map(([key,group]):UnionGroup=>{
    const names=new Set<string>();
    for(const {event} of group.selected)for(const path of pathSet(event))names.add(path);
    const fields=[...names].sort().map((source):UnionField=>{
      let populated=0,missing=0,empty=0;
      for(const {event} of group.selected){
        const result=lookupFieldValue(event.fields,source);
        if(!result.found)missing++;
        else if(blank(result.value))empty++;
        else populated++;
      }
      return {source,populated,blank:empty,missing,
        optional:missing>0||empty>0,
        semanticStatus:/^(?:field_\d+|column_\d+|col_\d+)$/i.test(source)?
          'POSITIONAL_UNVERIFIED':'SOURCE_FIELD_NAME'};
    });
    return {id:key,format:group.format,eventType:group.eventType,
      sampleNumbers:group.selected.map(({index})=>index+1).sort((a,b)=>a-b),fields};
  });
  return {totalEvents:events.length,reviewed:chosen.length,maxExamples:10,
    groups:output,unscorable:events.length-eligible.length,
    moreSamplesNotUsed:Math.max(0,eligible.length-chosen.length),
    meaning:'STRUCTURAL_SAMPLE_COVERAGE_ONLY'};
}
