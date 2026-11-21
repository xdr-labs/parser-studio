import {readFileSync} from 'node:fs';
import {describe,expect,it} from 'vitest';
import {createDraft} from '../model';
import {extractFields,preview} from '../parser';
import {lookupFieldValue} from '../fieldPaths';
import {sha256Utf8Hex} from '../sha256';
import {accountLosslessSource} from './losslessAccounting';

type Sample={id:string;family:string;provenance:'AUTHORED'|'VENDOR_DERIVED';raw:string;format:'json'|'mixed'|'csv'|'cef'|'leef'|'syslog';knownEvents?:number;expected?:Record<string,unknown>;nonFull?:boolean};
const vendor=(id:string)=>readFileSync(`tests/fixtures/vendor-holdout-20261116/${id}/raw.log`,'utf8').replace(/\n+$/u,'');
const samples:Sample[]=[
 {id:'json-array-null-dotted-utf8',family:'json',provenance:'AUTHORED',format:'json',raw:'{"message":"診断ログ 🔎","items":[{"id":1},{"id":2}],"nullable":null,"literal.dot":"kept"}',knownEvents:1,expected:{message:'診断ログ 🔎'}},
 {id:'json-128-paths',family:'path-bound',provenance:'AUTHORED',format:'json',raw:JSON.stringify(Object.fromEntries(Array.from({length:128},(_,i)=>[`field_${i}`,`value-${i}`]))),knownEvents:1,expected:{field_0:'value-0',field_127:'value-127'}},
 {id:'json-1025-paths',family:'path-bound',provenance:'AUTHORED',format:'json',raw:JSON.stringify(Object.fromEntries(Array.from({length:1025},(_,i)=>[`field_${i}`,`value-${i}`]))),knownEvents:1},
 {id:'empty-object-no-leaf-values',family:'json-empty',provenance:'AUTHORED',format:'json',raw:'{}',knownEvents:1},
 {id:'mixed-json-cef-leef-utf8',family:'mixed',provenance:'AUTHORED',format:'mixed',raw:'{"kind":"json","value":"α"}\nCEF:0|Acme|Sensor|1|100|blocked login|7|src=192.0.2.1\nLEEF:2.0|Acme|Sensor|1|cat=auth\tusrName=δοκιμή\tsrc=192.0.2.5',knownEvents:3},
 {id:'quoted-csv-utf8',family:'csv',provenance:'AUTHORED',format:'csv',raw:'name,message\n"Doe, Jane","said ""hello"""\n"診断","quoted, UTF-8"',knownEvents:3},
 {id:'cef-quoted',family:'cef',provenance:'AUTHORED',format:'cef',raw:'CEF:0|Acme|Sensor|1|100|blocked login|7|src=192.0.2.1 msg="user said \\"no\\""',knownEvents:1,expected:{cef_device_vendor:'Acme',src:'192.0.2.1'}},
 {id:'leef-utf8',family:'leef',provenance:'AUTHORED',format:'leef',raw:'LEEF:1.0|Acme|Sensor|1|100|usrName=δοκιμή\tsrc=192.0.2.5',knownEvents:1,expected:{src:'192.0.2.5'}},
 {id:'rfc5424-vendor-derived',family:'syslog',provenance:'VENDOR_DERIVED',format:'syslog',raw:vendor('h_suricata_rfc5424')},
 {id:'duplicate-source-records',family:'duplicates',provenance:'AUTHORED',format:'json',raw:'{"event":"same","value":7}\n{"event":"same","value":7}',knownEvents:2,expected:{event:'same',value:7}},
 {id:'malformed-json',family:'malformed',provenance:'AUTHORED',format:'json',raw:'{"event":"partial", broken',nonFull:true},
 {id:'dotted-collision',family:'collision',provenance:'AUTHORED',format:'json',raw:'{"a.b":"literal","a":{"b":"nested"}}',knownEvents:1},
];

describe('LF-0 independently scored bounded acceptance matrix',()=>{
 it('checks known source properties, preserves actual status, and reports deterministic family counts',async()=>{
  const receipt:{id:string;family:string;provenance:string;bytes:number;sha256:string;events:number;status:string[];sourceChecks:number}[]=[];
  for(const sample of samples){
   const draft={...createDraft(),format:sample.format};
   const suite=preview(sample.raw,draft);
   const accounting=await accountLosslessSource(sample.raw,suite.events.map(event=>({event})),draft);
   expect(accounting.sourceBytes,sample.id).toBe(new TextEncoder().encode(sample.raw).byteLength);
   expect(accounting.sourceSha256,sample.id).toBe(await sha256Utf8Hex(sample.raw));
   expect(accounting.proof,sample.id).toBe('UNKNOWN');
   expect(accounting.events.every(event=>event.residuals===null),sample.id).toBe(true);
   if(sample.knownEvents!==undefined)expect(suite.events,sample.id).toHaveLength(sample.knownEvents);
   if(sample.nonFull)expect(suite.events.every(event=>event.parseStatus!=='FULL'),sample.id).toBe(true);
   let sourceChecks=0;
   const extracted=extractFields(sample.raw,sample.format,draft).fields;
   const sourceFields=sample.id==='duplicate-source-records'?suite.events.map(event=>event.fields):[extracted];
   for(const [path,value] of Object.entries(sample.expected??{})){
    expect(sourceFields.every(fields=>{
     const actual=lookupFieldValue(fields,path);
     return actual.found&&Object.is(actual.value,value);
    }),`${sample.id}:${path}`)
     .toBe(true);
    sourceChecks++;
   }
   if(sample.id==='duplicate-source-records'){
    expect(suite.events.map(event=>event.raw),sample.id).toEqual([sample.raw.split('\n')[0],sample.raw.split('\n')[1]]);
   }
   if(sample.id==='json-array-null-dotted-utf8'){
    expect(suite.events[0]!.fields.items).toEqual([{id:1},{id:2}]);
    expect(suite.events[0]!.fields.nullable).toBeNull();
    expect(suite.events[0]!.fields['literal.dot']).toBe('kept');
   }
   if(sample.id==='dotted-collision')expect(accounting.events[0]!.notMappablePaths.some(path=>path.includes('ambiguous'))).toBe(true);
   if(sample.id==='json-1025-paths')expect(accounting.events[0]!.pathListTruncated).toBe(true);
   if(sample.id==='empty-object-no-leaf-values')expect(accounting.events[0]!.structuralLeafCount).toBe(0);
   receipt.push({id:sample.id,family:sample.family,provenance:sample.provenance,bytes:accounting.sourceBytes,
    sha256:accounting.sourceSha256,events:suite.events.length,status:suite.events.map(event=>event.parseStatus??'UNKNOWN'),sourceChecks});
  }
  const families=[...new Set(samples.map(sample=>sample.family))].sort();
  const familyReceipt=families.map(family=>({family,samples:receipt.filter(item=>item.family===family).length,
   actualStatuses:receipt.filter(item=>item.family===family).flatMap(item=>item.status)}));
  expect(receipt.map(({id,family,provenance,bytes,sha256,events,status,sourceChecks})=>
   ({id,family,provenance,bytes,sha256,events,status,sourceChecks,residuals:'UNKNOWN'}))).toMatchSnapshot();
  expect(familyReceipt).toMatchSnapshot();
 });
});
