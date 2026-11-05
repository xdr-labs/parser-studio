import {describe,expect,it} from 'vitest';
import {createDraft,type MappingRule,type ParserDraft} from '../model';
import {preview,splitEvents,convertValue} from '../parser';
import {jsonSourceValueValid} from '../jsonSourceSafety';
import {validIsoTimestamp} from '../isoCalendar';
import {listSafeLeafPaths,lookupFieldValue,countUnaddressableSourceValues} from '../fieldPaths';
import {analyzeLogEnvelopes,assessEnvelopeCompilation} from './autoParserEnvelope';
import type {BackendCapabilities} from './backendCapabilities';
import {toBackendProject} from './backendAdapter';
import {parseJsonataSelector,pathToJsonataSelector,createJsonataMappingPrompt,reviewJsonataMapping,applyReviewedJsonataMapping,JSONATA_MAPPING_CONTRACT} from './jsonataMappingAssist';

function project(mappings:MappingRule[],enrichment:NonNullable<ParserDraft['guided']>['enrichment']=[]):ParserDraft{
 const original=createDraft();
 return {...original,vendor:'Demo',format:'json',mappings,guided:{...original.guided!,
  enrichment,groups:Object.fromEntries(mappings.map(m=>[m.id,m.target.startsWith('custom.')?'vendor_fields':'top_fields'])),
  classification:{defaultIndex:'Syslog',rules:[]}}};
}

describe('Issue #210 browser/native parity and security regressions',()=>{
 it('F-01 blocks enriched protocol, IP, and impossible timestamps without rejecting valid enrichments',()=>{
  const mapping:MappingRule={id:'proto',source:'p',target:'proto',type:'integer'};
  const badPair=project([mapping],[{id:'bad-proto',operator:'set_const',source:'',target:'proto_name',value:'UDP'}]);
  const actual=preview('{"p":6}',badPair).events[0]!;
  expect(actual.normalizedOk).toBe(false);
  expect(actual.diagnostics).toEqual(expect.arrayContaining([
   expect.objectContaining({code:'PROTOCOL_CONFLICT',severity:'error'}),
  ]));
  for(const [target,value] of [['srcip','not-a-valid-IP'],
   ['timestamp','2026-02-30T00:00:00Z']] as const){
   const candidate=project([{id:'action',source:'a',target:'action',type:'string'}],
    [{id:'bad-enrichment',operator:'set_const',source:'',target,value}]);
   const output=preview('{"a":"deny"}',candidate).events[0]!;
   expect(output.normalizedOk).toBe(false);
   expect(output.diagnostics.some(d=>d.code==='ENRICHMENT_TYPE')).toBe(true);
  }
  const timestampPipeline=project(
    [{id:'action',source:'a',target:'action',type:'string'}],
    [
      {id:'iso-time',operator:'set_const',source:'',target:'timestamp',
        value:'2026-11-04T12:00:00Z'},
      {id:'upper-time',operator:'uppercase',source:'timestamp',target:'message',value:''},
      {id:'copy-time',operator:'copy',source:'timestamp',
        target:'custom.reviewed_timestamp',value:''},
    ],
  );
  const timestampPreview=preview('{"a":"deny"}',timestampPipeline).events[0]!;
  expect(timestampPreview.normalizedOk).toBe(true);
  expect(timestampPreview.normalized).toMatchObject({
    timestamp:'2026-11-04T12:00:00Z',
    message:'2026-11-04T12:00:00Z',
    custom:{reviewed_timestamp:'2026-11-04T12:00:00Z'},
  });
  const good=project([{id:'src',source:'src',target:'srcip',type:'ip'}],
    [{id:'valid-copy',operator:'copy',source:'srcip',target:'dstip',value:''}]);
  expect(preview('{"src":"192.0.2.10"}',good).events[0]?.normalized).toMatchObject({
   srcip:'192.0.2.10',dstip:'192.0.2.10'});
  expect(preview('{"src":"192.0.2.10"}',good).events[0]?.normalizedOk).toBe(true);
 });
 it('F-02 rejects native-invalid JSON nesting at 8+ and permits 7-level input',()=>{
  const sample=project([{id:'action',source:'action',target:'action',type:'string'}]);
  const fixture=(depth:number)=>{
   let nested:unknown='inner';
   for(let i=0;i<depth;i++)nested={level:nested};
   return JSON.stringify({action:'deny',payload:nested});
  };
  const accepted=preview(fixture(6),sample).events[0]!;
  expect(accepted.normalizedOk).toBe(true);
  for(const depth of [8,9,12]){
   const output=preview(fixture(depth),sample).events[0]!;
   expect(output.normalizedOk).toBe(false);
   expect(output.diagnostics.some(d=>d.code==='EXTRACTION_FAILED')).toBe(true);
  }
  expect(jsonSourceValueValid({action:'deny'})).toBe(true);
 });
 it('F-03 rejects unpaired escaped UTF-16 surrogate values and keys but accepts pairs and Korean',()=>{
  const sample=project([{id:'action',source:'action',target:'action',type:'string'}]);
  const invalid=[String.raw`{"action":"deny","value":"\ud800"}`,
   String.raw`{"action":"deny","bad\udc00":1}`];
  for(const raw of invalid)expect(preview(raw,sample).events[0]?.normalizedOk).toBe(false);
  expect(preview(String.raw`{"action":"deny","v":"\ud83d\ude02"}`,sample).events[0]?.normalizedOk).toBe(true);
  expect(preview('{"action":"deny","v":"한글"}',sample).events[0]?.normalizedOk).toBe(true);
 });
 it('F-06 respects configured receiver message bytes, including UTF-8 multibyte source',()=>{
  const sample=project([{id:'action',source:'action',target:'action',type:'string'}]);
  for(const [payload,pass] of [['a'.repeat(7900),true],['a'.repeat(8200),false],
   ['한'.repeat(2600),true],['한'.repeat(2900),false],['😀'.repeat(2300),false]] as const){
   const raw=JSON.stringify({action:'deny',payload});
   const result=preview(raw,sample).events[0]!;
   expect(result.normalizedOk).toBe(pass);
   if(!pass)expect(result.diagnostics.some(d=>d.code==='MESSAGE_LIMIT')).toBe(true);
   const ledger=analyzeLogEnvelopes(raw,'single-line',undefined,8192);
   expect(ledger.unsupported===0).toBe(pass);
  }
 });
 it('F-07 never turns bare CR into fabricated physical records',()=>{
  const source='action=deny\raction=allow';
  expect(splitEvents(source,'single-line')).toHaveLength(1);
  const report=analyzeLogEnvelopes(source,'single-line');
  expect(report.unsupported).toBe(1);
  const sample=project([{id:'action',source:'action',target:'action',type:'string'}]);
  const kv={...sample,format:'kv' as const};
  expect(preview(source,kv).counts.normalized).toBe(0);
  expect(splitEvents('action=deny\r\naction=allow','single-line')).toHaveLength(2);
  expect(splitEvents('action=deny\naction=allow','single-line')).toHaveLength(2);
 });
 it('F-09 preserves JS integer/port/boolean numeric token interpretation while rejecting fractional values',()=>{
  for(const raw of ['6','6.0','6e0'])expect(convertValue(JSON.parse(raw),'integer').value).toBe(6);
  expect(convertValue(JSON.parse('443.0'),'port').value).toBe(443);
  expect(convertValue(JSON.parse('1e0'),'boolean').value).toBe(true);
  expect(convertValue(JSON.parse('6.5'),'integer').error).toBeTruthy();
 });
 it('F-10 refuses CIDR and zone-suffixed IP values in browser',()=>{
  for(const ip of ['192.0.2.1/24','2001:db8::1/64','fe80::1%eth0'])
   expect(convertValue(ip,'ip').error).toBeTruthy();
  for(const ip of ['192.0.2.1','2001:db8::1','::ffff:192.0.2.1'])
   expect(convertValue(ip,'ip').error).toBeUndefined();
 });
 it('F-11 refuses invalid offset minutes and second 60 without regressing leap day',()=>{
  for(const ts of ['2026-11-04T00:00:00+00:60','2026-11-04T00:00:00+12:60',
   '2026-11-04T23:59:60Z','2026-02-30T12:00:00Z']){
   expect(validIsoTimestamp(ts)).toBe(false);
   expect(convertValue(ts,'timestamp').error).toBeTruthy();
  }
  expect(validIsoTimestamp('2024-02-29T23:59:59Z')).toBe(true);
 });
 it('F-05 supports only the escaped ECS root selector, without arbitrary special field names',async()=>{
  const draft=project([]);
  const source='{"@timestamp":"2026-11-04T12:00:00Z","action":"deny"}';
  const suite=preview(source,draft);
  expect(listSafeLeafPaths(suite.events[0]!.fields)).toContain('@timestamp');
  expect(countUnaddressableSourceValues(suite.events[0]!.fields)).toBe(0);
  expect(pathToJsonataSelector('@timestamp')).toBe('`@timestamp`');
  expect(parseJsonataSelector('`@timestamp`')).toBe('@timestamp');
  expect(parseJsonataSelector('@timestamp')).toBeNull();
  expect(parseJsonataSelector('`@forbidden`')).toBeNull();
  const prompt=await createJsonataMappingPrompt(suite,draft);
  const response=JSON.stringify({contract:JSONATA_MAPPING_CONTRACT,
    sample:{sha256:prompt.sha256,events:1},
    mappings:[{expression:'`@timestamp`',target:'timestamp'}]});
  const reviewed=await reviewJsonataMapping(response,suite,draft,prompt.sha256);
  expect(reviewed.ok).toBe(true);
  if(!reviewed.ok)return;
  expect(reviewed.rows[0]?.status).not.toBe('BLOCKED');
  const applied=applyReviewedJsonataMapping(draft,suite,reviewed.rows);
  expect(applied.ok).toBe(true);
  if(!applied.ok)return;
  expect(applied.draft.mappings[0]?.sourcePathKind).toBe('literal_root');
  expect(preview(source,applied.draft).events[0]?.normalized.timestamp)
   .toBe('2026-11-04T12:00:00.000Z');
  const ir=toBackendProject(applied.draft);
  expect(ir.ok).toBe(true);
  if(ir.ok)expect(ir.project.normalization.topFields['@timestamp']?.source_path_kind)
   .toBe('literal_root');
  expect(lookupFieldValue(suite.events[0]!.fields,'@timestamp','literal_root').found).toBe(true);
 });
 it('F-08 allows explicitly confirmed TCP LF LF JSON and rejects inferred UDP multiline',()=>{
  const source=[{action:'deny',srcip:'192.0.2.1'},
   {action:'allow',srcip:'192.0.2.2'}]
    .map(item=>JSON.stringify(item,null,2)).join('\n\n');
  const unapproved=analyzeLogEnvelopes(source,'blank-line');
  expect(unapproved.unsupported).toBe(2);
  const reviewed=analyzeLogEnvelopes(source,'blank-line',undefined,8192,'blank_line_json');
  expect(reviewed.unsupported).toBe(0);
  expect(reviewed.events.map(event=>event.body)).toEqual(['json','json']);
  const capabilities={authoring:{
    extractionFormats:['json'],
    jsonBlankLineTcpFraming:true,jsonBlankLineOtherTransports:false,
    jsonBlankLineDelimiter:'LF_LF'},
    verification:{engineVerified:false,targetImportVerified:false}
  } as unknown as BackendCapabilities;
  expect(assessEnvelopeCompilation(reviewed,capabilities,'blank_line_json').status)
   .toBe('DRAFT_COMPILABLE');
  expect(assessEnvelopeCompilation(reviewed,capabilities,'newline').status)
   .toBe('BOUNDARY_REVIEW');
 });
 it('F-04 browser canonical JSON object-to-string expectation includes array indexes and decimals',()=>{
  const input={details:JSON.parse('{"2":"b","1":"a","small":0.000001,"float":1.0}')};
  const value=convertValue(input.details,'string');
  expect(value.value).toBe('{"1":"a","2":"b","small":0.000001,"float":1}');
 });
});
