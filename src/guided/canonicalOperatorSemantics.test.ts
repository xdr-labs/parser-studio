import {describe,expect,it} from 'vitest';
import {CANONICAL_OPERATOR_CONTRACT_V1,evaluateCanonicalClassificationPredicate,
  supportsCanonicalClassificationOperator} from '../../backend/src/canonical-operator-contract';
import {createDraft} from '../model';
import {preview} from '../parser';
import {suggestClassification} from './classify';
import {defaultGuidedOptions} from './contract';
import {toBackendProject} from './backendAdapter';

describe('canonical v1 classification is based on normalized typed values',()=>{
  it('has a stable cross-runtime version and no native/target verification promises',()=>{
    expect(CANONICAL_OPERATOR_CONTRACT_V1.contract).toBe('parser-studio.operator-semantics.v1');
    expect(CANONICAL_OPERATOR_CONTRACT_V1.verification).toMatchObject({
      sourcePreviewIsNativeEvidence:false,nativeRubyIsTargetEvidence:false,
    });
    expect(supportsCanonicalClassificationOperator('exists','integer')).toBe(true);
    expect(supportsCanonicalClassificationOperator('equals','integer')).toBe(false);
    expect(evaluateCanonicalClassificationPredicate('equals',6,'6')).toBe(false);
  });
  it('preserves leading zeros and refuses implicit numeric source equality',()=>{
    const draft=createDraft();draft.format='json';
    draft.mappings=[{id:'status',source:'status',target:'action',type:'string'}];
    const options=defaultGuidedOptions();options.groups={status:'top_fields'};
    options.classification={defaultIndex:'Syslog',rules:[
      {id:'threat',sourceField:'status',equals:'0006',index:'Threat'},
    ]};
    draft.guided=options;
    expect(toBackendProject(draft).ok).toBe(true);
    for(const [source,index] of [
      [{status:'0006'},'Threat'],
      [{status:'6'},'Syslog'],
      [{status:6},'Syslog'],
      [{status:null},'Syslog'],
    ] as const){
      const result=preview(JSON.stringify(source),draft);
      const event=result.events[0]!;
      expect(suggestClassification(event,options,draft).index).toBe(index);
    }
  });
});
