import {describe,it,expect} from 'vitest';
import {createDraft} from '../model';
import {preview} from '../parser';
import {prepareBoundedPathCandidate} from './boundedPathReview';
const source=[
 '{"event":{"user":"PRIVATE_USER_A","action":"allow"},"src_ip":"198.51.100.10","dst_port":443}',
 '{"event":{"user":"PRIVATE_USER_B","action":"deny"},"src_ip":"203.0.113.10","dst_port":22}',
].join('\n');
const draft={...createDraft(),format:'json' as const};
describe('P1-AP6 bounded JSONata-style path-only review, without expression evaluation',()=>{
 it('allows exact nested path lookup as a non-applied candidate under current backend subset',()=>{
  const result=prepareBoundedPathCandidate('$.event.user',source,draft,preview(source,draft));
  expect(result).toMatchObject({ok:true,source:'event.user',target:'custom.event_user',
   approvalRequired:true,nativeVerified:false});
  if(!result.ok)return;
  expect(result.candidate.mappings).toHaveLength(4);
  expect(draft.mappings).toHaveLength(3);
  for(const value of ['PRIVATE_USER_A','PRIVATE_USER_B','198.51.100.10'])
   expect(JSON.stringify({source:result.source,target:result.target})).not.toContain(value);
 });
 it('fails closed on JSONata functions, wildcard, expressions, indexed access and dangerous paths',()=>{
  const rejected=['$sum($.event)', '$.event.*', '$.event.user[0]', '$.event[0]',
   '$.constructor.anything','event.__proto__.x','$.a..b', '$.event | eval',
   '$.event.user = 1','$','', 'user?','event["user"]'];
  for(const expression of rejected)
   expect(prepareBoundedPathCandidate(expression,source,draft,preview(source,draft)))
    .toMatchObject({ok:false,reason:'UNSUPPORTED_EXPRESSION'});
 });
 it('rejects stale suites, absent fields and existing mapping collisions',()=>{
  expect(prepareBoundedPathCandidate('event.user',source+'\nthird',draft,preview(source,draft)))
   .toMatchObject({ok:false,reason:'UNTRUSTED_SOURCE'});
  expect(prepareBoundedPathCandidate('event.unknown',source,draft,preview(source,draft)))
   .toMatchObject({ok:false,reason:'NOT_PRESENT_IN_ALL_EVENTS'});
  expect(prepareBoundedPathCandidate('src_ip',source,draft,preview(source,draft)))
   .toMatchObject({ok:false,reason:'MAPPING_CONFLICT'});
 });
});
