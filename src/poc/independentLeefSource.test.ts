import {describe,expect,it} from 'vitest';
import {arbitrateIndependentNonJson} from './independentNonJsonStructural';
import {arbitrateIndependentLeef} from './independentLeefSource';

// These synthetic unit examples are deliberately distinct from sealed upstream originals.
const v1='LEEF:1.0|ExampleCo|Beacon|9.4|AuditSeen|src=203.0.113.11\tdst=198.51.100.22\tsev=4\tproto=UDP\tdstPort=445';
const v2='LEEF:2.0|ExampleWorks|Sensor|2.7|PolicyAlert|0x09|src=203.0.113.18\tdst=192.0.2.45\tsev=6';
const caret='LEEF:2.0|ExampleNetworks|Agent|4.1|940|^|src=203.0.113.4^dst=192.0.2.10^user=lab_operator^detail=Sample blocked';
describe('independent LEEF standard source grammar, synthetic unit coverage only',()=>{
  it('retains source-defined LEEF 1.0 header and tab extension exact bytes',()=>{
    const r=arbitrateIndependentLeef(v1);
    expect(r.disposition).toBe('REVIEW_ONLY_STRUCTURED_BODY');
    expect(r.bodyClaims.map(c=>[c.name,c.value])).toEqual([
      ['version','1.0'],['vendor','ExampleCo'],['product','Beacon'],
      ['product_version','9.4'],['event_id','AuditSeen'],
      ['src','203.0.113.11'],['dst','198.51.100.22'],
      ['sev','4'],['proto','UDP'],['dstPort','445'],
    ]);
    const bytes=Buffer.from(v1,'utf8');
    for(const claim of r.bodyClaims)
      expect(bytes.subarray(claim.startByte,claim.endByte).toString('utf8')).toBe(claim.value);
    expect(r.autoPromoted).toBe(false);
    expect(r.independentOracleCertified).toBe(false);
    expect(r.nativeVerified).toBe(false);
    expect(r.branchAttempts).toBeLessThanOrEqual(8);
  });
  it('handles source-declared LEEF 2.0 hex-tab delimiter without vendor profiles',()=>{
    const r=arbitrateIndependentLeef(v2);
    expect(r.selectedBodyGrammar).toBe('leef');
    expect(r.bodyClaims.find(c=>c.name==='delimiter')?.value).toBe('0x09');
    expect(r.bodyClaims.find(c=>c.name==='product')?.value).toBe('Sensor');
    expect(r.bodyClaims.find(c=>c.name==='src')?.value).toBe('203.0.113.18');
  });
  it('uses a source-declared 2.0 custom delimiter for values containing spaces',()=>{
    const r=arbitrateIndependentLeef(caret);
    expect(r.disposition).toBe('REVIEW_ONLY_STRUCTURED_BODY');
    expect(r.bodyClaims.find(c=>c.name==='detail')?.value).toBe('Sample blocked');
    expect(r.bodyClaims.find(c=>c.name==='event_id')?.value).toBe('940');
    const raw=Buffer.from(caret,'utf8');
    for(const c of r.bodyClaims)
      expect(raw.subarray(c.startByte,c.endByte).toString('utf8')).toBe(c.rawSpanValue);
  });
  it('preserves namespace distinctness and repeated source extension key positions',()=>{
    const raw='LEEF:2.0|DemoOrg|Tool|1.0|E7|^|vendor=ext^src=192.0.2.1^vendor=repeated';
    const c=arbitrateIndependentLeef(raw).bodyClaims.filter(x=>x.name==='vendor');
    expect(c.map(x=>x.path)).toEqual([
      '/body/leef/header/vendor#0',
      '/body/leef/extension/vendor#0',
      '/body/leef/extension/vendor#1',
    ]);
  });
  it('retains UTF-8 byte spans without modifying non-ASCII original characters',()=>{
    const raw='LEEF:1.0|\uBCF4\uC548|Router|1|E7|src=192.0.2.1\tmsg=\uD14C\uC2A4\uD2B8';
    const r=arbitrateIndependentLeef(raw);
    const bytes=Buffer.from(raw,'utf8');
    expect(r.bodyClaims.find(c=>c.name==='msg')?.value).toBe('\uD14C\uC2A4\uD2B8');
    for(const f of r.bodyClaims)
      expect(bytes.subarray(f.startByte,f.endByte).toString('utf8')).toBe(f.value);
  });
  it.each([
    'LEEF:1.0|DemoOrg|Tool',
    'LEEF:1.0|DemoOrg|Tool|MissingEventId|',
    'LEEF:3.0|DemoOrg|Tool|1.0|Alert|src=192.0.2.1',
    'LEEF:2.0|DemoOrg|Tool|1.0|E7|0x00|src=192.0.2.1',
    'LEEF:1.0|DemoOrg|Tool|1.0|Alert|src=192.0.2.1\u0000dst=198.51.100.2',
  ])('abstains on unsupported or incomplete source grammar: %s',raw=>{
    const r=arbitrateIndependentLeef(raw);
    expect(r.disposition).toBe('ABSTAIN_UNSAFE');
    expect(r.bodyClaims).toHaveLength(0);
    expect(r.raw).toBe(raw);
  });
  it('does not invent body fields on empty or unknown quoted/escaped extensions',()=>{
    for(const raw of [
      'LEEF:1.0|DemoOrg|Tool|1.0|AuditSeen|',
      'LEEF:1.0|DemoOrg|Tool|1.0|AuditSeen|msg="uncertain value"',
      'LEEF:1.0|DemoOrg|Tool|1.0|AuditSeen|msg=Unknown\\t',
    ]){
      const r=arbitrateIndependentLeef(raw);
      expect(r.disposition).toBe('REVIEW_ONLY_UNFRAMED');
      expect(r.bodyReviewEvidence).toBe('NOT_PROVEN');
      expect(r.autoPromoted).toBe(false);
    }
  });
  it('keeps external independent VETO and rejects positive-only self-certification',()=>{
    for(const v of [
      {sourceIdentity:'MISMATCH',structuralProfile:'ACCEPT',independentSourceTruth:'EXACT'},
      {sourceIdentity:'MATCH',structuralProfile:'VETO',independentSourceTruth:'EXACT'},
      {sourceIdentity:'MATCH',structuralProfile:'ACCEPT',independentSourceTruth:'CONFLICT'},
    ] as const){
      const r=arbitrateIndependentLeef(v1,v);
      expect(r.disposition).toBe('ABSTAIN_UNSAFE');
      expect(r.bodyClaims).toHaveLength(0);
      expect(r.autoPromoted).toBe(false);
    }
    const positive=arbitrateIndependentLeef(v1,{
      sourceIdentity:'MATCH',structuralProfile:'ACCEPT',independentSourceTruth:'EXACT'});
    expect(positive.autoPromoted).toBe(false);
    expect(positive.nativeVerified).toBe(false);
  });
  it('keeps unchanged CEF, JSON, Syslog and unstructured observations identical',()=>{
    for(const raw of [
      'CEF:0|A|B|1|E7|Alert|5|src=203.0.113.1 dst=192.0.2.2',
      '{"user":"alice","count":17}',
      '<34>Oct 11 22:14:15 gateway process[42]: message=allowed',
      'unknown gibberish source',
    ])
      expect(arbitrateIndependentLeef(raw)).toEqual(arbitrateIndependentNonJson(raw));
  });
  it('enforces maximum source byte size and bounded candidate attempts',()=>{
    const raw=v1+'x'.repeat(9000);
    const r=arbitrateIndependentLeef(raw);
    expect(r.disposition).toBe('ABSTAIN_UNSAFE');
    expect(r.branchAttempts).toBeLessThanOrEqual(8);
    expect(r.autoPromoted).toBe(false);
  });
});
