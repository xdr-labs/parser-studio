import {describe,it,expect} from 'vitest';
import {mineLocalStructuralHints} from './localPatternMining';

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
});
