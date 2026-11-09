import {describe,it,expect} from 'vitest';
import {createDraft,type ParserDraft} from '../model';
import {preview} from '../parser';
import {createCanonicalMappingPlan} from './canonicalMappingPlan';
import {defaultGuidedOptions} from './contract';

const unconfigured=():ParserDraft=>{
  const draft=createDraft();
  return {...draft,format:'json',vendor:'LabSecurity',mappings:[],
    guided:{...defaultGuidedOptions(),groups:{}}};
};

describe('canonical source-to-destination decision plan v1',()=>{
  it('accounts for every safe field, preserves exact source path and carries no source values',()=>{
    const draft=unconfigured();
    const source=JSON.stringify({event:{'source-port':594,'destination-port':10400},
      vendor:{family:'ALLOW',reason:'private user value'}});
    const plan=createCanonicalMappingPlan(preview(source,draft),draft);
    expect(plan.contract).toBe('parser-studio.mapping-plan.v1');
    expect(plan.sourceCount).toBe(4);
    expect(plan.entries.map(e=>e.source)).toEqual([
      'event.destination-port','event.source-port','vendor.family','vendor.reason']);
    expect(plan.entries.filter(e=>e.disposition==='SUGGESTED_OFFICIAL').map(e=>e.target).sort())
      .toEqual(['dstport','srcport']);
    expect(plan.mappedCount).toBe(0);
    expect(JSON.stringify(plan)).not.toContain('private user value');
    expect(JSON.stringify(plan)).not.toContain('ALLOW');
  });

  it('reports all unassignable source keys rather than dropping them',()=>{
    const draft=unconfigured();
    draft.mappings=[
      {id:'manual-a',source:'old-a',target:'status',type:'string',
        authoring:{version:1,origin:'USER_EDITED'}},
      {id:'manual-b',source:'old-b',target:'http.status',type:'string',
        authoring:{version:1,origin:'USER_EDITED'}},
    ];
    const plan=createCanonicalMappingPlan(preview('{"http":{"status":403}}',draft),draft);
    expect(plan.entries).toMatchObject([{source:'http.status',disposition:'REVIEW_REQUIRED',
      reviewReasons:['NO_VALID_DESTINATION']}]);
    expect(plan.unresolvedCount).toBe(1);
  });

  it('does not promote translated/NAT ports in ambiguous mixed security logs',()=>{
    const draft=unconfigured();
    const records=[
      {src_ip:'203.0.113.3',post_nat:{'source-port':33100},'source-port':'1544'},
      {src_ip:'203.0.113.4',post_nat:{'source-port':33101},'source-port':'1545'},
    ];
    const plan=createCanonicalMappingPlan(preview(records.map(record=>JSON.stringify(record)).join('\n'),draft),draft);
    expect(plan.entries.find(e=>e.source==='post_nat.source-port')?.target).toBe('post_nat.source-port');
    expect(plan.officialCandidates.some(c=>c.source==='post_nat.source-port')).toBe(false);
    expect(plan.entries.find(e=>e.source==='source-port')?.target).toBe('srcport');
  });

  it('tracks provenance and blocks ambiguous conflicting official destinations',()=>{
    const draft=unconfigured();
    draft.mappings=[{id:'auto-1',source:'src_ip',target:'chosen.ip',type:'ip',
      authoring:{version:1,origin:'USER_EDITED'}}];
    draft.guided!.groups['auto-1']='vendor_fields';
    const plan=createCanonicalMappingPlan(preview('{"src_ip":"192.0.2.4","source_ip":"198.51.100.4"}',draft),draft);
    expect(plan.entries.find(e=>e.source==='src_ip')).toMatchObject({
      target:'chosen.ip',origin:'USER_EDITED',disposition:'MAPPED'});
    expect(plan.officialCandidates.find(c=>c.source==='src_ip')?.safeForBulk).toBe(false);
    const unmapped=plan.entries.find(e=>e.source==='source_ip');
    expect(unmapped?.disposition).not.toBe('SUGGESTED_OFFICIAL');
  });

  it('retains catalog collision diagnostics without offering an occupied official target',()=>{
    const draft=unconfigured();
    draft.mappings=[{id:'manual-1',source:'previous',target:'srcip',type:'ip',
      authoring:{version:1,origin:'USER_EDITED'}}];
    draft.guided!.groups['manual-1']='top_fields';
    const plan=createCanonicalMappingPlan(preview('{"src_ip":"192.0.2.2"}',draft),draft);
    expect(plan.entries).toMatchObject([{source:'src_ip',
      disposition:'SUGGESTED_VENDOR',reviewReasons:['EXISTING_TARGET_CONFLICT']}]);
    expect(plan.officialCandidates).toHaveLength(0);
  });

  it('produces an order-independent source census on mixed event permutations',()=>{
    const draft=unconfigured();
    const a=JSON.stringify({'source-port':594,alpha:{code:'A'}});
    const b=JSON.stringify({'destination-port':10400,beta:{code:'B'}});
    const left=createCanonicalMappingPlan(preview(a+'\n'+b,draft),draft);
    const right=createCanonicalMappingPlan(preview(b+'\n'+a,draft),draft);
    const summarize=(plan:typeof left)=>plan.entries.map(({source,target,disposition,origin,reviewReasons})=>({
      source,target,disposition,origin,reviewReasons}));
    expect(summarize(left)).toEqual(summarize(right));
  });
});
