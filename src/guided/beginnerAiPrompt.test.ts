import {expect,it} from 'vitest';
import {buildBeginnerRepairPrompt} from './beginnerAiPrompt';
import type {MultiPassSourcePreview} from './multipassPreviewClient';

it('tells recovery AI to map residual source text into final parser output',async()=>{
 const source='prefix id=123 suffix';
 const preview:MultiPassSourcePreview={
  contract:'parser-studio.multipass-source-preview.v0.1',
  status:'PARTIAL',syntax:'UNKNOWN+GENERIC_SINGLE_KV',
  sourceSha256:'a'.repeat(64),sourceBytes:new TextEncoder().encode(source).byteLength,
  fields:{generic_single_kv:{id:['123']}},
  spans:[{path:'generic_single_kv.id[0]',startByte:10,endByte:13}],
  residuals:[{startByte:0,endByte:10},{startByte:13,endByte:new TextEncoder().encode(source).byteLength}],
  issues:['NO_SUPPORTED_GRAMMAR'],nativeVerified:false,targetVerified:false,
 };
 const prompt=await buildBeginnerRepairPrompt({
  fullSource:source,eventSource:source,preview,
  recommendation:{label:'Create a rule for this text format',text:'Keep extracted values and repair only the unresolved text.'},
 });
 expect(prompt).toContain('preserve every unparsed source region listed above in the final parser output too');
 expect(prompt).toContain('Capturing a region as raw_event is not enough unless that capture is mapped into final output');
});

it('keeps metadata-only source anomalies explanation-only even when UI wording changes',async()=>{
 const source='<85>1 2023-01-13T10:10:16--5:00 gw CP-GW - Log [Fields@1 src="192.0.2.1" src="192.0.2.2" ]';
 const preview:MultiPassSourcePreview={
  contract:'parser-studio.multipass-source-preview.v0.1',
  status:'PARTIAL',syntax:'SYSLOG_SOURCE_ANOMALIES_PRESERVED',
  sourceSha256:'b'.repeat(64),sourceBytes:new TextEncoder().encode(source).byteLength,
  fields:{syslog:{hostname:'gw'}},spans:[],residuals:[],
  issues:['RFC5424_TIMESTAMP_INVALID','RFC5424_DUPLICATE_SD_KEY'],
  nativeVerified:false,targetVerified:false,
 };
 const prompt=await buildBeginnerRepairPrompt({
  fullSource:source,eventSource:source,preview,
  recommendation:{label:'Review the log header or time',text:'Explain the source issue without inventing parser rules.'},
 });
 expect(prompt).toContain('parser-studio.source-metadata-review.v0.1');
 expect(prompt).toContain('Do not propose a Regex merely to hide malformed source metadata.');
 expect(prompt).not.toContain('Return only one ParserRecipe v0.2 JSON object');
});
