import {describe,expect,it} from 'vitest';
import {createDraft,type MappingRule,type ParserDraft} from '../model';
import {preview,convertValue} from '../parser';
import {validIsoCalendarDate} from '../isoCalendar';
import {validatePreviewRegexPattern} from '../regexSafety';
import {validateNormalizationMappings,isBlockingNormalizationFinding} from './normalizationValidation';
import {JSONATA_MAPPING_CONTRACT,createJsonataMappingPrompt,reviewJsonataMapping,applyReviewedJsonataMapping} from './jsonataMappingAssist';
import {toBackendProject} from './backendAdapter';

function draft(mappings:MappingRule[]=[]):ParserDraft{
 const base=createDraft();
 return {...base,vendor:'Demo',format:'json',mappings,guided:{...base.guided!,
  groups:Object.fromEntries(mappings.map(m=>[m.id,m.target.startsWith('custom.')?'vendor_fields':'top_fields'])),
  classification:{defaultIndex:'Syslog',rules:[]}}};
}
const packet=(hash:string,records:number,entries:{expression:string;target:string}[])=>
 JSON.stringify({contract:JSONATA_MAPPING_CONTRACT,sample:{sha256:hash,events:records},mappings:entries});

describe('2026-11-04 targeted re-audit correctness regressions',()=>{
 it('rejects exponentially ambiguous nested alternations without blocking simple captures',()=>{
  for(const pattern of [
   '^(?<field>((a|aa))+)$',
   '^(?<field>((a|aa)){2,40})$',
   '^(?<field>(?:a|aa)+)$',
  ])expect(validatePreviewRegexPattern(pattern),pattern).not.toBeNull();
  expect(validatePreviewRegexPattern('^(?<field>https?)-(?:tcp|udp)$')).toBeNull();
 });
 it('rejects impossible ISO calendar dates instead of normalizing into the next month',()=>{
  for(const timestamp of ['2026-02-30T12:00:00Z','2026-04-31T12:00:00+09:00',
   '2025-02-29T00:00:00Z','0000-01-01T00:00:00Z']){
   expect(validIsoCalendarDate(timestamp),timestamp).toBe(false);
   expect(convertValue(timestamp,'timestamp').error).toBeTruthy();
  }
  for(const timestamp of ['2024-02-29T23:59:59Z','2026-11-04T12:00:00+09:00']){
   expect(validIsoCalendarDate(timestamp),timestamp).toBe(true);
   expect(convertValue(timestamp,'timestamp').error).toBeUndefined();
  }
  const settings=draft([{id:'date',source:'event_time',target:'timestamp',type:'timestamp'}]);
  const result=preview('{"event_time":"2026-02-30T12:00:00Z"}',settings);
  expect(result.events[0]?.diagnostics).toEqual(expect.arrayContaining([
   expect.objectContaining({code:'TYPE_ERROR',severity:'error'}),
  ]));
  expect(result.events[0]?.normalized).not.toHaveProperty('timestamp');
 });
 it('preserves a literal dotted JSONata key selector across future nested-only logs',async()=>{
  const settings=draft();
  const raw='{"source.ip":"203.0.113.47"}';
  const suite=preview(raw,settings);
  const prepared=await createJsonataMappingPrompt(suite,settings);
  const reviewed=await reviewJsonataMapping(packet(prepared.sha256,1,[
   {expression:'`source.ip`',target:'srcip'}]),suite,settings,prepared.sha256);
  expect(reviewed.ok).toBe(true);
  if(!reviewed.ok)return;
  expect(reviewed.rows[0]?.status).not.toBe('BLOCKED');
  const applied=applyReviewedJsonataMapping(settings,suite,reviewed.rows);
  expect(applied.ok).toBe(true);
  if(!applied.ok)return;
  const mapping=applied.draft.mappings.find(m=>m.source==='source.ip');
  expect(mapping?.sourcePathKind).toBe('literal_root');
  const ir=toBackendProject(applied.draft);
  expect(ir.ok).toBe(true);
  if(ir.ok)expect(ir.project.normalization.topFields['source.ip']?.source_path_kind).toBe('literal_root');
  expect(preview(raw,applied.draft).events[0]?.normalized).toMatchObject({srcip:'203.0.113.47'});
  expect(preview('{"source":{"ip":"192.0.2.19"}}',applied.draft).events[0]?.normalized)
   .not.toHaveProperty('srcip');
 });
 it('preserves a nested JSONata selector instead of matching later literal root keys',async()=>{
  const settings=draft(),raw='{"source":{"ip":"192.0.2.19"}}';
  const suite=preview(raw,settings);
  const prepared=await createJsonataMappingPrompt(suite,settings);
  const reviewed=await reviewJsonataMapping(packet(prepared.sha256,1,[
    {expression:'source.ip',target:'srcip'}]),suite,settings,prepared.sha256);
  expect(reviewed.ok).toBe(true);
  if(!reviewed.ok)return;
  const applied=applyReviewedJsonataMapping(settings,suite,reviewed.rows);
  expect(applied.ok).toBe(true);
  if(!applied.ok)return;
  expect(applied.draft.mappings[0]?.sourcePathKind).toBe('nested');
  expect(preview(raw,applied.draft).events[0]?.normalized).toMatchObject({srcip:'192.0.2.19'});
  expect(preview('{"source.ip":"203.0.113.47"}',applied.draft).events[0]?.normalized)
   .not.toHaveProperty('srcip');
  const original=preview('{"source.ip":"203.0.113.47","source":{"ip":"192.0.2.19"}}',applied.draft);
  expect(original.events[0]?.diagnostics).toEqual(expect.arrayContaining([
   expect.objectContaining({code:'AMBIGUOUS_SOURCE_PATH'}),
  ]));
 });
 it('blocks mutually inconsistent official proto/proto_name values in preview and mapping review',async()=>{
  const settings=draft([
   {id:'p',source:'proto',target:'proto',type:'integer'},
   {id:'n',source:'proto_name',target:'proto_name',type:'string'},
  ]);
  const raw='{"proto":6,"proto_name":"UDP"}';
  const result=preview(raw,settings);
  expect(result.events[0]?.normalizedOk).toBe(false);
  expect(result.events[0]?.diagnostics).toEqual(expect.arrayContaining([
   expect.objectContaining({code:'PROTOCOL_CONFLICT',severity:'error'}),
  ]));
  const findings=validateNormalizationMappings(result,settings.mappings,settings.guided!.groups);
  expect(findings.some(f=>f.code==='PROTOCOL_CONFLICT'&&isBlockingNormalizationFinding(f.code))).toBe(true);
  const valid=preview('{"proto":6,"proto_name":"TCP"}',settings);
  expect(valid.events[0]?.diagnostics.some(d=>d.code==='PROTOCOL_CONFLICT')).toBe(false);
  const fresh=draft(),suite=preview(raw,fresh);
  const prepared=await createJsonataMappingPrompt(suite,fresh);
  const reviewed=await reviewJsonataMapping(packet(prepared.sha256,1,[
   {expression:'proto',target:'proto'},
   {expression:'proto_name',target:'proto_name'},
  ]),suite,fresh,prepared.sha256);
  expect(reviewed.ok).toBe(true);
  if(reviewed.ok){
   const applied=applyReviewedJsonataMapping(fresh,suite,reviewed.rows);
   expect(applied.ok).toBe(false);
  }
 });
 it('represents a structured JSON value as a stable JSON string in browser',()=>{
  const settings=draft([{id:'d',source:'details',target:'custom.payload',type:'string'}]);
  const raw='{"details":{"a":"b","n":1}}';
  const output=preview(raw,settings).events[0];
  expect(output?.normalized.Demo).toMatchObject({custom:{payload:'{"a":"b","n":1}'}});
 });
});
