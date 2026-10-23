import {describe,it,expect} from 'vitest';
import {buildPromptSourceEvidence} from './chatGptSourceEvidence';

describe('Conservative locally observed ChatGPT grammar evidence',()=>{
 const zeek=[
  '#separator \\x09',
  '#fields\tts\tuid\tid.orig_h\tid.resp_h\tproto',
  '1760832000.000\tCw01\t192.0.2.10\t198.51.100.3\ttcp',
  '1760832001.000\tCw02\t192.0.2.11\t198.51.100.4\tudp',
 ].join('\n');
 const w3c=[
  '#Version: 1.0',
  '#Fields: date time c-ip cs-method cs-uri-stem sc-status',
  '2026-10-23 12:11:13 192.0.2.10 GET /login 403',
 ].join('\n');
 it('separates physical source identity from Zeek semantic data events',()=>{
   const evidence=buildPromptSourceEvidence(zeek);
   expect(evidence.originalPhysicalRecordCount).toBe(4);
   expect(evidence.schema).toBe('ZEEK_DECLARED');
   expect(evidence.headerLines).toBe(2);
   expect(evidence.logicalDataRows).toBe(2);
   expect(evidence.text).toMatch(/REVIEW_REQUIRED/);
   expect(evidence.text).toContain('not the logical data-event count');
   expect(evidence.text).not.toContain('192.0.2.10');
 });
 it('counts W3C header lines without inventing a native compiler claim',()=>{
   const evidence=buildPromptSourceEvidence(w3c);
   expect(evidence.originalPhysicalRecordCount).toBe(3);
   expect(evidence.schema).toBe('W3C_DECLARED');
   expect(evidence.headerLines).toBe(2);
   expect(evidence.logicalDataRows).toBe(1);
   expect(evidence.text).toContain('REVIEW_REQUIRED');
   expect(evidence.text).toContain('no deployable recipe');
 });
 it('uses fixed local grammar labels for normal JSON, not hypothetical fields',()=>{
   const evidence=buildPromptSourceEvidence('{"src_ip":"192.0.2.10","action":"deny"}');
   expect(evidence.schema).toBe(null);
   expect(evidence.originalPhysicalRecordCount).toBe(1);
   expect(evidence.text).toContain('"body":"json"');
   expect(evidence.text).not.toContain('192.0.2.10');
 });
 it('does not promote unknown free text to a supported log grammar',()=>{
   const evidence=buildPromptSourceEvidence('10/23-12:10:11 [**] [1:1000:0] Threat [**] {TCP} 192.0.2.10:5123 -> 198.51.100.5:443');
   expect(evidence.schema).toBe(null);
   expect(evidence.text).toContain('"unrecognizedSourceRecords":1');
   expect(evidence.text).not.toContain('192.0.2.10');
 });
 it('rejects interleaved W3C metadata after data events as unaudited',()=>{
   const evidence=buildPromptSourceEvidence('#Fields: date time c-ip\n2026-10-23 12:00:00 192.0.2.1\n#Version: 1.0');
   expect(evidence.schema).toBe(null);
   expect(evidence.logicalDataRows).toBe(null);
 });
 it('abstains from logical counts for incomplete W3C declarations',()=>{
   const evidence=buildPromptSourceEvidence('#Fields: date time c-ip\n2026-10-23 invalid');
   expect(evidence.schema).toBe(null);
   expect(evidence.logicalDataRows).toBe(null);
 });
});
