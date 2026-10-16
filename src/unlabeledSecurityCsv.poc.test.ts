import {describe,expect,it} from 'vitest';
import {parseSecurityInput} from './securityInputPipeline';
import {extractGenericStructural} from './genericStructural';

const panBare='1,2026/10/16 15:44:21,,TRAFFIC,end,2561,2026/10/16 15:44:20,192.0.2.10,198.51.100.20,,,allow-web,,,ssl,vsys1,trust,untrust,ethernet1/1,ethernet1/2,forward-all,2026/10/16 15:44:21,123456,1,51234,443,45001,443';
const panSystem='1,2026/10/16 15:44:21,,SYSTEM,general,2561,2026/10/16 15:44:20,,general,,0,0,general,informational,"Connection established, path preserved"';
const panHostless='Oct 16 15:44:21 '+panBare;
const panTagged='<14>Oct 16 15:44:21 edge-fw01 '+panBare;
const quote=(value:string)=>'"'+value.replaceAll('"','""')+'"';
const csvColumns=['2026-10-16 15:44:21','analyst','192.0.2.1','198.51.100.2','ALLOW','https://example.test/search?a=1,b=2','Browser "QA"','', 'normal policy','443','tcp'];
const fullQuoted=csvColumns.map(quote).join(',');

function extractedColumns(raw:string):{values:string[];mode:string;fields:Record<string,unknown>}|null{
 const result=parseSecurityInput(raw);
 if(!result.ok)return null;
 const fields=result.events[0]?.fields??{};
 const generic=fields.generic as Record<string,unknown>|undefined;
 const values=generic?.columns&&typeof generic.columns==='object'
   ?Object.values(generic.columns as Record<string,string>):null;
 return values?{values,mode:String(generic?.mode??''),fields}:null;
}

describe('unlabeled security CSV and PAN body boundary PoC',()=>{
 it('keeps every PAN positional source value without a Syslog envelope',()=>{
   for(const raw of [panBare,panSystem]){
     const result=extractedColumns(raw);
     expect(result,raw.slice(0,24)).not.toBeNull();
     expect(result?.values.length).toBeGreaterThan(12);
     expect(result?.values[1]).toBe('2026/10/16 15:44:21');
     expect(result?.mode).toContain('positional_csv');
   }
 });
 it('separates hostname-free BSD time prefixes from real hostname fields',()=>{
   const hostless=extractedColumns(panHostless);
   expect(hostless?.values).toEqual(extractedColumns(panBare)?.values);
   expect(hostless?.fields.syslog).toMatchObject({hostname_missing:true,month:'Oct',day:'16',time:'15:44:21'});
   expect((hostless?.fields.syslog as Record<string,unknown>).hostname).toBeUndefined();
   expect(extractedColumns(panTagged)?.values).toEqual(hostless?.values);
 });
 it('preserves all fully quoted unlabeled CSV fields without guessing names',()=>{
   const result=extractedColumns(fullQuoted);
   expect(result?.mode).toBe('quoted_csv_unlabeled');
   expect(result?.values).toEqual(csvColumns);
   expect(Object.keys(result?.fields??{})).toEqual(['generic']);
   expect((result?.fields.generic as Record<string,unknown>).source_raw).toBe(fullQuoted);
 });
 it('preserves the PAN payload after an explicitly separated Syslog dash marker',()=>{
   const raw='Nov 26 12:53:54 edge-dns - '+panBare;
   const parsed=extractedColumns(raw);
   expect(parsed?.values).toEqual(extractedColumns(panBare)?.values);
   expect((parsed?.fields.generic as Record<string,unknown>).source_prefix).toBe('-');
 });
 it('does not mistake interior vendor quotes for CSV quote boundaries',()=>{
   const raw=panBare+',Some-Header:"example-one, example-two";';
   const parsed=extractedColumns(raw);
   expect(parsed?.values.slice(-2)).toEqual(['Some-Header:"example-one',' example-two";']);
 });
 it('allows optional whitespace after CSV delimiters without dropping quoted content',()=>{
   const raw=csvColumns.map((value,index)=>(index===0?'': ' ')+quote(value)).join(',');
   expect(extractedColumns(raw)?.values).toEqual(csvColumns);
 });
 it('keeps unlabeled unquoted date/endpoint CSV without source-specific field naming',()=>{
   const values=['2026-10-16 15:44:21','[100200]','Passive Monitor','Tunnel Node','OUTBOUND',
     '1','84','192.0.2.10','','198.51.100.20','','us-east','12','ALLOW'];
   const parsed=extractedColumns(values.join(','));
   expect(parsed?.values).toEqual(values);
   expect(parsed?.mode).toBe('csv_unlabeled_row');
 });
 it('uses the second date column only when a fully quoted numeric record ID precedes it',()=>{
   const values=['1234567890','2026-10-16 15:44:21','test-user','name','record','update','192.0.2.1','old','new'];
   const raw=values.map(quote).join(', ');
   expect(extractedColumns(raw)?.values).toEqual(values);
 });
 it('preserves PAN audit eight-position records under both standalone and Syslog envelopes',()=>{
   const audit='003001000000,2026/10/16 15:44:21,audit,2561,gui-op,reviewer,"<show><status/></show>",success';
   const bare=extractedColumns(audit);
   expect(bare?.values).toEqual(['003001000000','2026/10/16 15:44:21','audit','2561','gui-op',
     'reviewer','<show><status/></show>','success']);
   expect((bare?.fields.generic as Record<string,unknown>).profile).toBe('panos_audit');
   const wrapped=extractedColumns('Oct 16 15:44:21 edge-fw '+audit);
   expect(wrapped?.values).toEqual(bare?.values);
   expect(wrapped?.fields.syslog).toMatchObject({hostname:'edge-fw',month:'Oct'});
 });
 it('rejects malformed known audit records without generic downgrade',()=>{
   const audit='003001000000,2026/10/16 15:44:21,audit,2561,gui-op,reviewer,"<show><status/></show>",success';
   const invalid=[
     audit.replace('2026/10/16','2026/02/30'),
     audit.replace('003001000000','not-serial'),
     audit.replace('audit,2561','audit,broken'),
     audit.replace(',success',',unknown-outcome'),
     audit.replace('"<show><status/></show>"','"<show><status/>'),
   ];
   expect(invalid.map(raw=>parseSecurityInput(raw).ok)).toEqual([false,false,false,false,false]);
 });
 it('never downgrades a known PAN body with invalid receive time behind a misleading Syslog header',()=>{
   const invalid=panBare.replace('2026/10/16 15:44:21','2026/02/30 15:44:21');
   const samples=[
     'Oct 16 15:44:21 '+invalid,
     'Oct 16 15:44:21 edge-fw '+invalid,
     '<14>Oct 16 15:44:21 edge-fw '+invalid,
     'Oct 16 15:44:21 edge-fw - '+invalid,
   ];
   expect(samples.map(raw=>parseSecurityInput(raw).ok)).toEqual([false,false,false,false]);
 });
 it('rejects malformed PAN signatures rather than falling into loose extraction',()=>{
   const invalid=[
     panBare.replace('2026/10/16','2026/02/30'),
     panBare.replace(',TRAFFIC,',',UNKNOWN,'),
     panBare.replace(',TRAFFIC,',',TRAFFIC_EXTRA,'),
     '1,2026/10/16 15:44:21,,TRAFFIC',
     panBare.replace(',TRAFFIC,',',TRAFFIC,').replace('allow-web','"unterminated'),
   ];
   expect(invalid.map(raw=>parseSecurityInput(raw).ok)).toEqual([false,false,false,false,false]);
 });
 it('fails closed on malformed unlabeled quoted rows and invalid dates',()=>{
   const invalid=[
     fullQuoted.replace('2026-10-16','2026-02-30'),
     fullQuoted.replace('"Browser ""QA"""','"Browser "QA""'),
     fullQuoted.replace('"ALLOW"','ALLOW'),
     fullQuoted.slice(0,-1),
     csvColumns.slice(0,3).map(quote).join(','),
     fullQuoted+'\nregular unstructured prose',
   ];
   expect(invalid.map(raw=>parseSecurityInput(raw).ok)).toEqual([false,false,false,false,false,false]);
 });
 it('does not loosen unrelated generic free text',()=>{
   const invalid=['just some text,with commas,not really events','2026-10-16 15:44:21 random,words,not a valid CSV export','"2026-10-16 15:44:21",foo,"third","fourth"'];
   expect(invalid.map(raw=>extractGenericStructural(raw).errors.length===0)).toEqual([false,false,false]);
 });
});
