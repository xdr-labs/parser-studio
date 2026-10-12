import { describe,expect,it } from 'vitest';
import { createDraft } from '../model';
import { toBackendProject } from './backendAdapter';
import { reconstructExactBackendDraft } from './pairProjectImport';

function project(){
  const draft=createDraft();
  draft.format='json';
  draft.name='Synthetic Firewall';
  draft.vendor='Documentation Vendor';
  const result=toBackendProject(draft);
  if(!result.ok)throw Error('Reviewed source fixture did not compile');
  return result.project;
}
const clone=(value:unknown)=>JSON.parse(JSON.stringify(value));

describe('backend-exact, byte-verified portable parser project reconstruction',()=>{
  it('reconstructs an equivalent user-reviewable draft without executing Ruby or retaining raw events',()=>{
    const initial=project();
    const reconstructed=reconstructExactBackendDraft(initial,'customized_demo_firewall');
    expect(reconstructed).not.toBeNull();
    expect(reconstructed).toMatchObject({
      name:'Synthetic Firewall',vendor:'Documentation Vendor',
      format:'json',mappings:expect.arrayContaining([
        expect.objectContaining({source:'src_ip',target:'custom.source_ip',type:'ip'}),
      ]),
    });
    expect(reconstructed?.guided?.receiver.port).toBe(7501);
    expect(reconstructed?.guided?.classification.rules).toHaveLength(2);
    const check=toBackendProject(reconstructed!);
    expect(check.ok).toBe(true);
    if(check.ok)expect(check.project).toEqual(initial);
    expect(JSON.stringify(reconstructed)).not.toContain('SECRET_CUSTOMER_EVENT');
  });
  it('accepts native reviewed mapping groups and enrichment only when completely preserved',()=>{
    const original=project();
    const value=clone(original);
    value.normalization.vendorFields.device={normalized_name:'custom.device',data_type:'string'};
    value.enrichment=[{operator:'set_const',target:'custom.environment',value:'lab'}];
    const reconstructed=reconstructExactBackendDraft(value,'customized_demo_firewall');
    expect(reconstructed).not.toBeNull();
    expect(reconstructed?.guided?.enrichment).toEqual([{
      id:'imported-enrichment-1',
      operator:'set_const',source:'',target:'custom.environment',value:'lab',
    }]);
    const check=toBackendProject(reconstructed!);
    expect(check.ok).toBe(true);
    if(check.ok)expect(check.project).toEqual(value);
  });
  it('rejects unknown project IDs, extra properties and ambiguous normalization without a lossy import',()=>{
    const original=project();
    for(const invalid of [
      {...original,projectId:'customer-private-id'},
      {...original,revision:2},
      {...original,extra:'unverified-data'},
      {...original,sourceCategory:'new-unknown-category'},
      {...original,receiver:{...original.receiver,protocols:['http']}},
      {...original,receiver:{...original.receiver,port:0}},
      {...original,normalization:{...original.normalization,unknownField:{}}},
      {...original,extraction:{format:'unknown'}},
      {...original,classification:{...original.classification,
        rules:[{field:'not_mapped',operator:'equals',value:'allow',index:'session'}]}},
    ]){
      expect(reconstructExactBackendDraft(invalid,'customized_demo_firewall')).toBeNull();
    }
    expect(reconstructExactBackendDraft(original,'customized_other')).toBeNull();
  });
  it('rejects potentially sensitive or unsafe embedded fields instead of guessing their meaning',()=>{
    const x=clone(project());
    x.normalization.topFields['__proto__.secret']={
      normalized_name:'custom.internal',data_type:'string',
    };
    expect(reconstructExactBackendDraft(x,'customized_demo_firewall')).toBeNull();
    const y=clone(project());
    y.normalization.vendorFields.username={
      normalized_name:'__proto__.secret',data_type:'string',
    };
    expect(reconstructExactBackendDraft(y,'customized_demo_firewall')).toBeNull();
    const z=clone(project());
    z.undocumentedSource='SECRET_CUSTOMER_EVENT';
    expect(reconstructExactBackendDraft(z,'customized_demo_firewall')).toBeNull();
    expect(reconstructExactBackendDraft({secret:'CUSTOMER_LOG'},'customized_demo_firewall')).toBeNull();
  });
  it('disallows malformed pair names and oversized embedded projects without evaluating content',()=>{
    expect(reconstructExactBackendDraft(project(),'../escape')).toBeNull();
    const x=clone(project());
    x.vendor='x'.repeat(300_000);
    expect(reconstructExactBackendDraft(x,'customized_demo_firewall')).toBeNull();
  });
});
