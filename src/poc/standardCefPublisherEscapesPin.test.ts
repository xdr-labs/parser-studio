import {createHash} from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import {describe,expect,it} from 'vitest';
type Claim={
 name:string;ordinal:number;category:string;startByte:number;endByte:number;
 rawSha256:string;decodedSha256:string;
};
type Example={id:string;privateFile:string;originalSha256:string;
 originalBytes:number;cefMarkerByte:number;claimCount:number;claims:Claim[]};
const raw=fs.readFileSync(path.join(__dirname,
 '../../scripts/poc/standardCefPublisherEscapes.pinned.json'));
const sha='ec43bbf61e211e693cff40ce813a289863743396a64b164194cfc65fe16f7309';
const expectedClaims=39;
describe('P0-STD ArcSight publisher original CEF escape source SHA and provenance',()=>{
 it('pins independent vendor-authored expected input metadata, never fakes private source',()=>{
  expect(createHash('sha256').update(raw).digest('hex')).toBe(sha);
  const data=JSON.parse(raw.toString('utf8')) as {
    sourceOnly:boolean;nativeTarget:string;cases:Example[];
    publisherHtmlSha256:string;
  };
  expect(data.sourceOnly).toBe(true);
  expect(data.nativeTarget).toBe('NOT_VERIFIED');
  expect(data.cases).toHaveLength(4);
  expect(data.publisherHtmlSha256).toMatch(/^[a-f0-9]{64}$/);
  expect(data.cases.reduce((count,x)=>count+x.claimCount,0))
    .toBe(expectedClaims);
  data.cases.forEach((x,index)=>{
    expect(x.id).toBe('CEF-PUBLISHER-ESCAPE-'+index);
    expect(x.originalSha256).toMatch(/^[a-f0-9]{64}$/);
    expect(x.claims).toHaveLength(x.claimCount);
    x.claims.forEach((c,ordinal)=>{
      expect(c.ordinal).toBe(ordinal);
      expect(c.startByte).toBeGreaterThanOrEqual(x.cefMarkerByte);
      expect(c.endByte).toBeGreaterThan(c.startByte);
      expect(c.endByte).toBeLessThanOrEqual(x.originalBytes);
      expect(c.rawSha256).toMatch(/^[a-f0-9]{64}$/);
      expect(c.decodedSha256).toMatch(/^[a-f0-9]{64}$/);
    });
  });
 });
});
