import {describe,it,expect,vi,beforeEach,afterEach} from 'vitest';
import {createDraft} from '../model';
import {preview} from '../parser';
import {compareCandidate} from './autoParserRegression';
import {readApprovedPatterns,saveApprovedMapping,validApprovedPattern,
 prepareApprovedPatternDraft,forgetApprovedPattern} from './approvedPatterns';

function storage():Storage{
 const data=new Map<string,string>();
 return {get length(){return data.size;},clear(){data.clear();},
  getItem(k){return data.get(k)??null;},key(i){return [...data.keys()][i]??null;},
  removeItem(k){data.delete(k);},setItem(k,v){data.set(k,v)}} as Storage;
}
const source=[
 '{"action":"allow","src_ip":"198.51.100.10","dst_port":443,"detail":"PRIVATE_OWNER"}',
 '{"action":"deny","src_ip":"203.0.113.5","dst_port":22,"detail":"SECRET_STAFF"}',
].join('\n');
const holdout=[
 '{"action":"allow","src_ip":"192.0.2.5","dst_port":443,"detail":"PRIVATE_HOLDOUT"}',
 '{"action":"deny","src_ip":"192.0.2.8","dst_port":22,"detail":"SECOND_HOLDOUT"}',
].join('\n');
function ready(){
 const draft=createDraft();draft.format='json';
 const mapping={id:'approved-mapping',source:'detail',target:'custom.detail',type:'string' as const};
 const candidate={...draft,mappings:[...draft.mappings,mapping],
  guided:{...draft.guided!,groups:{...draft.guided!.groups,[mapping.id]:'vendor_fields' as const}}};
 const comparison=compareCandidate({source,baseline:preview(source,draft),
  candidate:preview(source,candidate),holdout:{source:holdout,
   baseline:preview(holdout,draft),candidate:preview(holdout,candidate)}});
 return {draft,candidate,mapping,comparison};
}
describe('P1-AP7 explicit safe reusable patterns',()=>{
 beforeEach(()=>vi.stubGlobal('crypto',{randomUUID:()=> 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee'}));
 afterEach(()=>vi.unstubAllGlobals());
 it('only saves user-approved mapping metadata after successful independent holdout and keeps all raw values out',()=>{
  const s=storage(),{candidate,mapping,comparison}=ready();
  expect(comparison.acceptedWithoutRegression).toBe(true);
  const saved=saveApprovedMapping({draft:candidate,mapping,comparison},s);
  expect(saved).toMatchObject({family:'json',origin:'explicit-browser-user-approval',
   rawLogsIncluded:false,nativeVerified:false,targetVerified:false});
  expect(readApprovedPatterns(s)).toHaveLength(1);
  for(const secret of ['PRIVATE_OWNER','SECRET_STAFF','198.51.100.10','PRIVATE_HOLDOUT'])
   expect(JSON.stringify(readApprovedPatterns(s))).not.toContain(secret);
 });
 it('refuses absent holdout, native evidence forgery and mismatched mapping identity',()=>{
  const s=storage(),{candidate,mapping,comparison}=ready();
  const incomplete={...comparison,holdout:null,holdoutStatus:'NOT_SUPPLIED' as const};
  expect(()=>saveApprovedMapping({draft:candidate,mapping,comparison:incomplete},s)).toThrow();
  const wrong={...mapping,source:'constructor.private'};
  expect(()=>saveApprovedMapping({draft:candidate,mapping:wrong,comparison},s)).toThrow();
  expect(readApprovedPatterns(s)).toEqual([]);
 });
 it('requires a second explicit approval path to propose stored metadata and preserves current rules',()=>{
  const s=storage(),{draft,candidate,mapping,comparison}=ready();
  const saved=saveApprovedMapping({draft:candidate,mapping,comparison},s);
  const proposed=prepareApprovedPatternDraft(draft,saved);
  expect(proposed.ok).toBe(true);
  if(!proposed.ok)return;
  expect(draft.mappings).toHaveLength(3);
  expect(proposed.draft.mappings).toHaveLength(4);
  expect(prepareApprovedPatternDraft(candidate,saved))
   .toMatchObject({ok:false,reason:'DUPLICATE_OR_CONFLICT'});
  expect(prepareApprovedPatternDraft({...draft,format:'kv'},saved))
   .toMatchObject({ok:false,reason:'MISMATCHED_FORMAT'});
 });
 it('forgets only an explicitly selected browser-local pattern, not the live draft',()=>{
  const s=storage(),{draft,candidate,mapping,comparison}=ready();
  const saved=saveApprovedMapping({draft:candidate,mapping,comparison},s);
  expect(forgetApprovedPattern('review-not-a-valid-id',s)).toBe(false);
  expect(readApprovedPatterns(s)).toHaveLength(1);
  expect(forgetApprovedPattern(saved.id,s)).toBe(true);
  expect(readApprovedPatterns(s)).toEqual([]);
  expect(draft.mappings).toHaveLength(3);
  expect(forgetApprovedPattern(saved.id,s)).toBe(false);
 });
 it('filters tampered entries, unsafe keys, oversized or invalid list',()=>{
  const s=storage(),{candidate,mapping,comparison}=ready();
  const saved=saveApprovedMapping({draft:candidate,mapping,comparison},s);
  expect(validApprovedPattern({...saved,nativeVerified:true})).toBe(false);
  expect(validApprovedPattern({...saved,mapping:{...saved.mapping,source:'__proto__.private'}})).toBe(false);
  s.clear();s.setItem('parser-studio:approved-patterns:v0.1',JSON.stringify([
   {...saved,nativeVerified:true},saved]));
  expect(readApprovedPatterns(s)).toEqual([saved]);
  s.setItem('parser-studio:approved-patterns:v0.1','not-json');
  expect(readApprovedPatterns(s)).toEqual([]);
 });
});
