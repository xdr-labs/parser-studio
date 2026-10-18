import {createHash} from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import {describe,expect,it} from 'vitest';

const pathToManifest=path.join(__dirname,
  '../../scripts/poc/standard9PublisherCefExamples.pinned.json');
const frozen=fs.readFileSync(pathToManifest);
const manifestSha='c4384572021d05515f7a92918c4f00618eb0acf3e15637172be0adceaa4b4882';
type Claim={name:string;ordinal:number;category:string;
  startByte:number;endByte:number;rawValueSha256:string;decodedValueSha256:string};
type Case={id:string;privateFile:string;sourceSha256:string;
  sourceBytes:number;cefBodyStartByte:number;claimCount:number;claims:Claim[]};
type Manifest={authorityClass:string;sourceOnly:boolean;
  nativeVerified:boolean;originalUri:string;cases:Case[]};
describe('P0-STD-9 private ArcSight CEF vendor-standard examples, SHA and evidence limits',()=>{
 it('fixes provider-authored sample bytes and expected field positions before candidate scoring',()=>{
   expect(createHash('sha256').update(frozen).digest('hex')).toBe(manifestSha);
   const evidence=JSON.parse(frozen.toString('utf8')) as Manifest;
   expect(evidence.authorityClass).toBe(
     'ARCSIGHT_PUBLISHER_AUTHORED_CEF_STANDARD_ILLUSTRATIONS');
   expect(evidence.sourceOnly).toBe(true);
   expect(evidence.nativeVerified).toBe(false);
   expect(evidence.originalUri).toContain('cef-implementation-standard');
   expect(evidence.cases).toHaveLength(2);
   for(const [row,c] of evidence.cases.entries()){
     expect(c.id).toBe('CEF-PUBLISHER-EXAMPLE-'+row);
     expect(c.sourceBytes).toBe(120);
     expect(c.cefBodyStartByte).toBe(21);
     expect(c.sourceSha256).toMatch(/^[a-f0-9]{64}$/);
     expect(c.claimCount).toBe(10);
     expect(c.claims).toHaveLength(10);
     for(const [index,claim] of c.claims.entries()){
       expect(claim.ordinal).toBe(index);
       expect(claim.startByte).toBeLessThan(claim.endByte);
       expect(claim.rawValueSha256).toMatch(/^[a-f0-9]{64}$/);
       expect(claim.decodedValueSha256).toMatch(/^[a-f0-9]{64}$/);
     }
   }
 });
});
