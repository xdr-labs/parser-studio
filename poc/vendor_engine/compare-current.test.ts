/** Same six gold roles, same pinned corpus, ACTUAL unmodified src/parser.ts preview.
 * Raw/expected fixtures remain ignored local source files; output is aggregate only.
 * Direct extracted role ≠ extracted unassigned value ≠ normalized semantic role.
 */
import {existsSync,readFileSync,writeFileSync} from 'node:fs';
import {join,dirname} from 'node:path';
import {fileURLToPath} from 'node:url';
import {describe,it,expect} from 'vitest';
import {preview,detectFormat} from '../../src/parser';
import {createDraft} from '../../src/model';
import {lookupFieldValue} from '../../src/fieldPaths';

const here=dirname(fileURLToPath(import.meta.url));
const cache=join(here,'.cache');
const cases=[
  'fortinet_traffic','fortinet_event','fortinet_utm',
  'palo_traffic','palo_threat','trellix_edr','trellix_epo','trend_vision',
] as const;
const roles=[
  'source.ip','destination.ip','source.port',
  'destination.port','event.action','user.name',
] as const;
type Role=typeof roles[number];
type Counts={TP:number;FP:number;FN:number;gold_present:number};
const empty=():Counts=>({TP:0,FP:0,FN:0,gold_present:0});
const available=cases.every(id=>
  existsSync(join(cache,id+'.raw'))&&existsSync(join(cache,id+'.gold.json')));
function goldValue(record:Record<string,unknown>,path:string):unknown {
  const direct=lookupFieldValue(record,path);
  if(direct.found)return direct.value;
  if(path==='user.name') {
    const alternate=lookupFieldValue(record,'source.user.name');
    if(alternate.found)return alternate.value;
  }
  return null;
}
function normalizedCompare(value:unknown):string {
  if(Array.isArray(value))return JSON.stringify(value.map(String).sort());
  if(value&&typeof value==='object') {
    const sort=(node:unknown):unknown=>Array.isArray(node)?node.map(sort):
      node&&typeof node==='object'
        ?Object.fromEntries(Object.entries(node).sort(([a],[b])=>a.localeCompare(b)).map(([k,v])=>[k,sort(v)]))
        :node;
    return JSON.stringify(sort(value));
  }
  return JSON.stringify([String(value)]);
}
function score(counts:Counts, gold:unknown, observed:unknown) {
  const g=gold!==null&&gold!==undefined;
  const o=observed!==null&&observed!==undefined;
  if(g)counts.gold_present++;
  if(!g&&o)counts.FP++;
  else if(g&&!o)counts.FN++;
  else if(g&&o) {
    if(normalizedCompare(gold)===normalizedCompare(observed))counts.TP++;
    else {counts.FP++;counts.FN++;}
  }
}
function get(obj:Record<string,unknown>,role:Role):unknown {
  const v=lookupFieldValue(obj,role);
  return v.found?v.value:null;
}
function containsUnassignedValue(value:unknown,gold:unknown):boolean {
  if(gold===null||gold===undefined)return false;
  const pending:Array<{v:unknown;depth:number}>=[{v:value,depth:0}];
  let count=0;
  while(pending.length&&++count<10000) {
    const {v,depth}=pending.pop()!;
    if(depth>12)continue;
    if(Array.isArray(v)){for(const item of v)pending.push({v:item,depth:depth+1});continue;}
    if(v&&typeof v==='object'){
      for(const item of Object.values(v))pending.push({v:item,depth:depth+1});
      continue;
    }
    if(v!==null&&v!==undefined&&normalizedCompare(v)===normalizedCompare(gold))return true;
  }
  return false;
}
const add=(destination:Counts,source:Counts)=>{
  for(const k of ['TP','FP','FN','gold_present'] as const)destination[k]+=source[k];
};
const metrics=(counts:Counts)=>{
  const {TP,FP,FN,gold_present}=counts;
  return {...counts,
    precision:TP+FP?Number((TP/(TP+FP)).toFixed(4)):null,
    recall:TP+FN?Number((TP/(TP+FN)).toFixed(4)):null,
    f1:2*TP+FP+FN?Number((2*TP/(2*TP+FP+FN)).toFixed(4)):null,
    gold_present};
};
const emptyRoles=()=>Object.fromEntries(roles.map(role=>[role,empty()])) as Record<Role,Counts>;
const count=(dest:Record<string,number>,key:string)=>{dest[key]=(dest[key]??0)+1;};

describe('Actual current Auto Parser / six-role gold field baseline',()=>{
  it.skipIf(!available)('scores direct extraction, unassigned values, and mapped normalization separately',()=>{
    const matrix:Record<string,unknown>[]=[];
    const totalExtracted=emptyRoles(),totalNormalized=emptyRoles();
    const valuePresent=Object.fromEntries(roles.map(role=>[role,0])) as Record<Role,number>;
    let expectedTotal=0,parsedTotal=0,fullyNormalized=0,allGoldRoles=0;
    for(const label of cases){
      const raw=readFileSync(join(cache,label+'.raw'),'utf8');
      const lines=raw.split(/\r?\n/).filter(x=>x.trim().length>0);
      const source=JSON.parse(readFileSync(join(cache,label+'.gold.json'),'utf8')) as unknown;
      const records=Array.isArray(source)?source:(source as {expected:unknown[]}).expected;
      expect(records).toHaveLength(lines.length);
      const suite=preview(lines.join('\n'),createDraft());
      expect(suite.counts.total).toBe(lines.length);
      expect(suite.engine).toBe('browser-preview');
      expect(suite.nativeFluentdVerified).toBe(false);
      expect(suite.stellarExportVerified).toBe(false);
      const detected:Record<string,number>={},statuses:Record<string,number>={};
      const extracted=emptyRoles(),normalized=emptyRoles();
      const availableOnly=Object.fromEntries(roles.map(role=>[role,0])) as Record<Role,number>;
      let fixtureGold=0,metadata=0;
      suite.events.forEach((event,i)=>{
        count(detected,detectFormat(event.raw).format);
        count(statuses,event.status);
        const gold=(records[i]??{}) as Record<string,unknown>;
        if(!Object.keys(gold).length)metadata++;
        for(const role of roles){
          const expected=goldValue(gold,role);
          if(expected!==null&&expected!==undefined)fixtureGold++;
          score(extracted[role],expected,get(event.fields,role));
          score(normalized[role],expected,get(event.normalized,role));
          if(containsUnassignedValue(event.fields,expected))availableOnly[role]++;
        }
      });
      for(const role of roles){
        add(totalExtracted[role],extracted[role]);
        add(totalNormalized[role],normalized[role]);
        valuePresent[role]+=availableOnly[role];
      }
      matrix.push({
        fixture:label,physical_rows:lines.length,gold_event_records:lines.length-metadata,
        metadata_or_goldless_records:metadata,six_role_gold_present:fixtureGold,
        parser_count:suite.counts,detected,status:statuses,
        directly_extracted_role_metrics:Object.fromEntries(roles.map(role=>[role,metrics(extracted[role])])),
        normalized_role_metrics:Object.fromEntries(roles.map(role=>[role,metrics(normalized[role])])),
        raw_extracted_value_presence_without_semantic_assertion:availableOnly,
      });
      expectedTotal+=lines.length;
      parsedTotal+=suite.counts.extracted;
      fullyNormalized+=suite.counts.normalized;
      allGoldRoles+=fixtureGold;
    }
    const directSummary=empty(),normSummary=empty();
    for(const role of roles){add(directSummary,totalExtracted[role]);add(normSummary,totalNormalized[role]);}
    expect(expectedTotal).toBe(256);
    expect(parsedTotal).toBe(80);
    expect(fullyNormalized).toBe(59);
    expect(allGoldRoles).toBe(1168);
    expect(directSummary.gold_present).toBe(allGoldRoles);
    expect(normSummary.gold_present).toBe(allGoldRoles);
    const result={
      contract:'parser-studio.poc.existing-browser-field-baseline.v0.2',
      note:'Same six gold ECS-style roles and records as Python PoC. Defaults only; raw value presence has no role identity and is NOT a field true-positive. No vendor profile configured.',
      roles:[...roles],records:expectedTotal,six_role_gold_present:allGoldRoles,
      browser_extracted:parsedTotal,browser_normalized:fullyNormalized,
      direct_extracted_role_metrics:metrics(directSummary),
      normalized_role_metrics:metrics(normSummary),
      direct_per_role:Object.fromEntries(roles.map(role=>[role,metrics(totalExtracted[role])])),
      normalized_per_role:Object.fromEntries(roles.map(role=>[role,metrics(totalNormalized[role])])),
      raw_extracted_value_presence_without_semantic_assertion:valuePresent,
      native_verified:false,target_verified:false,fixtures:matrix,
    };
    writeFileSync(join(cache,'current_baseline.json'),JSON.stringify(result,null,2)+'\n');
    expect(matrix).toHaveLength(8);
  });
});