import {describe,it,expect} from 'vitest';
import {materializeStructuralGroupSource,mineLocalStructuralHints} from './localPatternMining';

describe('P1-AP5 isolated bounded privacy-safe structural hints',()=>{
 it('clusters only unknown records without retaining arbitrary words or identifiers',()=>{
   const data=[
    'ERROR customerAlice connected to 198.51.100.10',
    'ERROR customerBob connected to 203.0.113.11',
    '{"action":"allow"}',
    'WARN secretAccount disconnected',
   ].join('\n');
   const result=mineLocalStructuralHints(data);
   expect(result).toMatchObject({status:'CANDIDATES',sourceCount:4,
    unknownCount:3,groupedCount:3,nativeVerified:false,customerValuesIncluded:false});
   expect(result.groups.some(x=>x.count===2)).toBe(true);
   expect(JSON.stringify(result)).not.toMatch(/customerAlice|customerBob|secretAccount|198\.51\.100\.10|203\.0\.113\.11/);
   expect(result.groups.reduce((sum,x)=>sum+x.count,0)).toBe(3);
 });
 it('clusters BSD structural prefixes without retaining host, process, tag or message values',()=>{
   const data=[
    'Jan 29 06:09:59 procA.exe[100]: EVENT_ALPHA_LONG: private message one',
    'Feb 12 13:12:33 EVENT_BETA_LONG message repeated [700]: private message two',
    'Mar 26 10:20:16 host-a EVENT_GAMMA_LONG: private message three',
    'Apr 24 00:25:25 host-b: procB.exe[200]: EVENT_DELTA_LONG: private message four',
    'May 08 07:27:59 host-c: label-x: private message five',
    'Jun 09 08:28:59 label-y: private message six',
   ].join('\n');
   const result=mineLocalStructuralHints(data);
   expect(result).toMatchObject({status:'CANDIDATES',sourceCount:6,unknownCount:6,
    groupedCount:6,customerValuesIncluded:false});
   expect(result.groups.map(group=>group.fingerprint).sort()).toEqual([
    'BSD <HOST> <LABEL> <MESSAGE>',
    'BSD <HOST> <PROCESS> <TAG> <MESSAGE>',
    'BSD <HOST> <TAG> <MESSAGE>',
    'BSD <LABEL> <MESSAGE>',
    'BSD <PROCESS> <TAG> <MESSAGE>',
    'BSD <TAG> MESSAGE_REPEATED <MESSAGE>',
   ].sort());
   expect(JSON.stringify(result)).not.toMatch(/procA|procB|host-a|host-b|host-c|EVENT_|private message|label-x|label-y/);
 });

 it('rejects too many rows and oversized inputs without publishing any sample',()=>{
   const many=Array.from({length:501},(_,i)=>`PRIVATE_NAME_${i} started`).join('\n');
   expect(mineLocalStructuralHints(many)).toMatchObject({status:'UNSUPPORTED_OR_LIMIT',groups:[]});
   const large='SECRET '.repeat(15000);
   expect(mineLocalStructuralHints(large).groups).toEqual([]);
 });
 it('does not relabel known JSON or malformed structured records as a successful parser',()=>{
   expect(mineLocalStructuralHints('{"action":"allow"}')).toMatchObject({status:'NO_UNKNOWN'});
   expect(mineLocalStructuralHints('{"action":')).toMatchObject({unknownCount:0});
   const result=mineLocalStructuralHints('PRIVATE_TEXT standalone\nPRIVATE_SECOND standalone');
   expect(result.nativeVerified).toBe(false);
   expect(result.targetVerified).toBe(false);
 });
 it('uses a hard bound on token length and group count and fixed category labels',()=>{
   const values=Array.from({length:30},(_,i)=>Array(i+1).fill('PRIVATE_NAME').join(' ')).join('\n');
   const report=mineLocalStructuralHints(values);
   expect(report.groups.length).toBeLessThanOrEqual(12);
   expect(report.groups.every(x=>!x.fingerprint.includes('PRIVATE_NAME'))).toBe(true);
 });
 it('materializes only an explicitly selected group with enough independent examples',()=>{
   const source=['alpha one','skip me','alpha two','alpha three'].join('\n');
   const eligible={fingerprint:'TEST <WORD>',count:3,tokenCount:2,
     sourceLines:[1,3,4],status:'REVIEW_ONLY' as const};
   expect(materializeStructuralGroupSource(source,eligible)).toEqual({
     ok:true,source:'alpha one\nalpha two\nalpha three',count:3,sourceLines:[1,3,4]});
   expect(materializeStructuralGroupSource(source,{...eligible,count:2,sourceLines:[1,3]}))
     .toEqual({ok:false,reason:'HOLDOUT_REQUIRED'});
   expect(materializeStructuralGroupSource(source,{...eligible,sourceLines:[1,3,5]}))
     .toEqual({ok:false,reason:'SOURCE_MISMATCH'});
 });
});
