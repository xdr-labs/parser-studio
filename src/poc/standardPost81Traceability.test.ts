import fs from 'node:fs';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {describe,expect,it} from 'vitest';

type Reference={id:string;section:string};
type Row={
  pr:number;exactHead:string;ciObserved:'SUCCESS';
  roadmapStage:string;sections:Reference[];
  codePaths:string[];testPaths:string[];
  pinnedOracle:string|null;pinnedOracleSha256:string|null;
  frozenCases:number;
  evidenceClass:string;impactRisk:string;
  finding:string;stillUnverified:string;
  sourceDisposition:string;owner:string;
  productIntegrated:false;manufacturerWireCertified:false;
  nativeVerified:false;autoPromotionAuthorized:false;
  functionAnchor:{path:string;symbol:string;line:number};
};
type Reconciled={
  id:string;originalFindingStatus:string;
  risk:string;sourceOnlyFollowupPRs:number[];
  currentQualifiedInterpretation:string;nativeVerified:false;
};
type PostLedger={
  contract:string;sourceBaseExactHead:string;scope:string;
  initialAuditLedgerSha256:string;priorCrossFamilyLedgerSha256:string;
  normativeSourcePinsSha256:string;
  priorRows:number;initialRiskRows:number;
  initialRiskReconciliation:Reconciled[];
  newRows:number;traceableTotalRows:number;
  authoredSyntheticCasesNotDeduplicated:number;
  publisherDocumentationCasesNotDeviceCaptures:number;
  convergenceNewOracleCases:number;
  casesNotDistinctEventsOrGeneralizationAccuracy:true;
  regressionHistoryOnly:{
    originals:1361;invalidMutations:2892;
    unchangedReviewOnly:197;priorIndependentOriginals:50;
  };
  flags:{
    sourceOnly:true;productIntegrated:false;nativeVerified:false;
    manufacturerWireCertified:false;completeEventF1Measured:false;
    allStandardsCompliant:false;releaseAuthorized:false;
  };
  rows:Row[];
};
const root=path.resolve(__dirname,'../..');
const read=(file:string)=>fs.readFileSync(path.join(root,file));
const sha=(data:Uint8Array)=>createHash('sha256').update(data).digest('hex');
const ledgerFile='scripts/poc/standardPost81Traceability.v1.json';
const data=read(ledgerFile);
const frozenLedgerSha='06647515d0c767287522c882c86f5ddb1d74edc97175ffe0d795c1a1e0bf890f';
const ledger=JSON.parse(data.toString('utf8')) as PostLedger;
const old=JSON.parse(read('scripts/poc/standardCrossFamilyEvidenceLedger.v1.json').toString('utf8')) as {
  evidence:unknown[];
};
const initial=JSON.parse(read('scripts/poc/standardCoverageLedger.v1.json').toString('utf8')) as {
  entries:Array<{id:string;status:string;risk:string}>;
};
const standards=JSON.parse(read('scripts/poc/normativeGrammarSources.pinned.json').toString('utf8')) as {
  sources:Array<{id:string;uri:string;sha256:string;sourceRedistributed:boolean}>;
};

describe('P0-STD-11 after PR81 spec-to-function-to-oracle coverage traceability',()=>{
  it('keeps previously pinned v1 ledger and authoritative source manifest immutable',()=>{
    expect(sha(data)).toBe(frozenLedgerSha);
    expect(sha(read('scripts/poc/standardCrossFamilyEvidenceLedger.v1.json')))
      .toBe(ledger.priorCrossFamilyLedgerSha256);
    expect(sha(read('scripts/poc/standardCoverageLedger.v1.json')))
      .toBe(ledger.initialAuditLedgerSha256);
    expect(sha(read('scripts/poc/normativeGrammarSources.pinned.json')))
      .toBe(ledger.normativeSourcePinsSha256);
    expect(ledger.sourceBaseExactHead)
      .toBe('309189334fcfd3328c4dc15be11a30c3645de34c');
    expect(ledger.contract).toBe('parserstudio.p0-std-post81-source-evidence-addendum.v1');
    expect(standards.sources).toHaveLength(11);
    expect(standards.sources.every(s=>s.uri.startsWith('https://')&&
      /^[0-9a-f]{64}$/.test(s.sha256)&&s.sourceRedistributed===false))
      .toBe(true);
  });

  it('exposes no false product/native/manufacturer promotion or reused holdout accuracy',()=>{
    expect(ledger.flags).toEqual({
      sourceOnly:true,productIntegrated:false,nativeVerified:false,
      manufacturerWireCertified:false,completeEventF1Measured:false,
      allStandardsCompliant:false,releaseAuthorized:false,
    });
    expect(ledger.casesNotDistinctEventsOrGeneralizationAccuracy).toBe(true);
    expect(ledger.regressionHistoryOnly).toEqual({
      originals:1361,invalidMutations:2892,unchangedReviewOnly:197,
      priorIndependentOriginals:50,
    });
    expect(ledger.convergenceNewOracleCases).toBe(0);
  });

  it('reconciles every original 19 risk rows without rewriting their historical classification',()=>{
    expect(ledger.initialRiskRows).toBe(initial.entries.length);
    expect(initial.entries).toHaveLength(19);
    expect(ledger.initialRiskReconciliation).toHaveLength(19);
    expect(new Set(ledger.initialRiskReconciliation.map(x=>x.id)).size).toBe(19);
    for(const original of initial.entries){
      const now=ledger.initialRiskReconciliation.find(x=>x.id===original.id)!;
      expect(now.originalFindingStatus).toBe(original.status);
      expect(now.risk).toBe(original.risk);
      expect(now.nativeVerified).toBe(false);
      expect(now.currentQualifiedInterpretation.length).toBeGreaterThan(16);
      for(const id of now.sourceOnlyFollowupPRs)
        expect(id>=69&&id<=81).toBe(true);
    }
    expect(ledger.initialRiskReconciliation.find(x=>
      x.id==='STD-NATIVE-CONTRACT')?.currentQualifiedInterpretation)
      .toBe('NATIVE_TARGET_NOT_VERIFIED');
  });

  it('links 13 actual source PRs and old ledger, with exact section, real symbol line and pin',()=>{
    expect(old.evidence).toHaveLength(11);
    expect(ledger.priorRows).toBe(11);
    expect(ledger.newRows).toBe(13);
    expect(ledger.traceableTotalRows).toBe(24);
    expect(ledger.rows.map(r=>r.pr)).toEqual([
      69,70,71,72,73,74,75,76,77,78,79,80,81,
    ]);
    const validSources=new Set(standards.sources.map(s=>s.id));
    const totals:Record<string,number>={};
    for(const row of ledger.rows){
      expect(row.ciObserved).toBe('SUCCESS');
      expect(row.exactHead).toMatch(/^[a-f0-9]{40}$/);
      expect(row.sections.length).toBeGreaterThan(0);
      expect(row.sections.every(s=>validSources.has(s.id)&&s.section.length>5))
        .toBe(true);
      expect(row.finding.length).toBeGreaterThan(30);
      expect(row.stillUnverified.length).toBeGreaterThan(40);
      expect(['HIGH','MEDIUM']).toContain(row.impactRisk);
      expect(row.owner).toBe('CHATGPT_CHAT_SOURCE_ONLY');
      expect(row.nativeVerified).toBe(false);
      expect(row.manufacturerWireCertified).toBe(false);
      expect(row.productIntegrated).toBe(false);
      expect(row.autoPromotionAuthorized).toBe(false);
      for(const name of [...row.codePaths,...row.testPaths])
        expect(fs.existsSync(path.join(root,name)),name).toBe(true);

      const anchor=row.functionAnchor;
      expect(row.codePaths).toContain(anchor.path);
      const lines=read(anchor.path).toString('utf8').split('\n');
      expect(lines[anchor.line-1]).toContain(anchor.symbol);
      expect(lines[anchor.line-1]).toMatch(/function |const /);
      if(row.pinnedOracle===null){
        expect(row.pr).toBe(75);
        expect(row.pinnedOracleSha256).toBeNull();
        expect(row.frozenCases).toBe(0);
        expect(row.sourceDisposition).toBe('REGRESSION_ONLY');
      }else{
        const pinned=read(row.pinnedOracle);
        expect(sha(pinned),row.pinnedOracle).toBe(row.pinnedOracleSha256);
        const parsed=JSON.parse(pinned.toString('utf8')) as {cases:unknown[]};
        expect(parsed.cases,row.pinnedOracle).toHaveLength(row.frozenCases);
      }
      totals[row.evidenceClass]=(totals[row.evidenceClass]??0)+row.frozenCases;
    }
    expect(totals.INDEPENDENT_STANDARDS_DERIVED_SYNTHETIC)
      .toBe(ledger.authoredSyntheticCasesNotDeduplicated);
    expect(totals.PUBLISHER_DOCUMENTATION_ILLUSTRATION_NOT_DEVICE_CAPTURE)
      .toBe(ledger.publisherDocumentationCasesNotDeviceCaptures);
    expect(ledger.authoredSyntheticCasesNotDeduplicated).toBe(177);
    expect(ledger.publisherDocumentationCasesNotDeviceCaptures).toBe(6);
  });
});
