import fs from 'node:fs';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {describe,expect,it} from 'vitest';

type Entry={
  roadmap:string;standard:string;
  pinnedOraclePath:string;pinnedOracleSha256:string;caseCount:number;
  implementationPaths:string[];actualTestPaths:string[];
  status:string;stillUnverified:string;
};
type Ledger={
  baseSourceSha:string;sourceOnly:boolean;productIntegrated:boolean;
  nativeVerified:boolean;releaseAuthorized:boolean;
  evidence:Entry[];publisherExampleSourceSha256:string;
  publisherOriginalPrivate:boolean;
  legacyReplayOnly:{originals:number;invalidMutations:number;
    historicalReviewOnly:number;priorIndependentCases:number};
};
const root=path.resolve(__dirname,'../..');
const ledger=JSON.parse(fs.readFileSync(path.join(root,
 'scripts/poc/standardCrossFamilyEvidenceLedger.v1.json'),'utf8')) as Ledger;
const sha=(file:Buffer)=>createHash('sha256').update(file).digest('hex');

describe('STD-10/11 immutable standards source-to-code-to-test coverage ledger',()=>{
 it('cross-references each frozen oracle to real parser functions and actual tests',()=>{
  expect(ledger.sourceOnly).toBe(true);
  expect(ledger.productIntegrated).toBe(false);
  expect(ledger.nativeVerified).toBe(false);
  expect(ledger.releaseAuthorized).toBe(false);
  expect(ledger.evidence).toHaveLength(11);
  let synthetic=0,publisher=0;
  for(const row of ledger.evidence){
    expect(row.implementationPaths.length).toBeGreaterThan(0);
    expect(row.actualTestPaths.length).toBeGreaterThan(0);
    expect(row.stillUnverified.length).toBeGreaterThan(30);
    expect(row.status).toBe('NARROW_SOURCE_EVIDENCE_ONLY');
    const pinned=fs.readFileSync(path.join(root,row.pinnedOraclePath));
    expect(sha(pinned)).toBe(row.pinnedOracleSha256);
    for(const item of [...row.implementationPaths,...row.actualTestPaths])
      expect(fs.existsSync(path.join(root,item)),item).toBe(true);
    const data=JSON.parse(pinned.toString('utf8')) as {
      cases?:unknown[];rows?:number;
    };
    if(row.roadmap==='STD-9'){
      expect(data.rows).toBe(row.caseCount);
      publisher+=row.caseCount;
    }else{
      expect(data.cases).toHaveLength(row.caseCount);
      synthetic+=row.caseCount;
    }
  }
  expect(synthetic).toBe(143);
  expect(publisher).toBe(4);
  expect(ledger.legacyReplayOnly).toEqual({
    originals:1361,invalidMutations:2892,
    historicalReviewOnly:197,priorIndependentCases:50,
  });
  expect(ledger.publisherOriginalPrivate).toBe(true);
  expect(ledger.publisherExampleSourceSha256).toMatch(/^[a-f0-9]{64}$/);
 });
});
