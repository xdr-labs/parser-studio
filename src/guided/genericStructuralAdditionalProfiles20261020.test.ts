import {describe,it,expect} from 'vitest';
import syslogFixture from '../../tests/fixtures/roadmap-syslog-prefix-kv-20261020.json';
import leefFixture from '../../tests/fixtures/roadmap-leef2-implicit-tab-20261020.json';
import {createDraft} from '../model';
import {extractGenericStructural} from '../genericStructural';
import {buildAutomaticGenericStructuralDraft} from './genericStructuralAutoDraft';
import {toBackendProject} from './backendAdapter';
import {assertBackendProjectSupported,fetchBackendCapabilities,type BackendCapabilities} from './backendCapabilities';
import {lookupFieldValue} from '../fieldPaths';

const profiles=['syslog_prefix_kv','leef2_implicit_tab'] as const;
function capability():BackendCapabilities{
  return {
    contract:'host-customized-pair.v0.1',projectSchemaRevision:'0.1',
    authoring:{receiverProtocols:['udp','tcp'],extractionFormats:['generic_structural'],
      genericStructuralGrammar:'GENERIC_STRUCTURAL_ULTRA_COMPILER_V15',
      genericStructuralProfiles:[...profiles],formatCoverage:'reviewed-bounded-subset',
      httpReceiver:false,multipleDistinctReceiverPorts:false,multiline:false,arbitraryRuby:false},
    import:{exactInternalPairsEditable:true,unknownLegacyRubyEditable:false,structuralInspectionOnly:true},
    verification:{engineVerified:false,targetImportVerified:false,liveListenerVerified:false,proprietaryLoaderVerified:false},
    limits:{maxProjectBodyBytes:256*1024,maxInspectBodyBytes:2*1024*1024},
  };
}

describe('one explicit additional Generic Structural profile per project',()=>{
  for(const sample of leefFixture.positive){
    it('prepares the implicit TAB grammar without changing source: '+sample.name,()=>{
      expect(extractGenericStructural(sample.raw).errors).not.toHaveLength(0);
      expect(extractGenericStructural(sample.raw,'syslog_prefix_kv').errors).not.toHaveLength(0);
      const parsed=extractGenericStructural(sample.raw,'leef2_implicit_tab');
      expect(parsed.errors).toEqual([]);
      expect(parsed.fields).toEqual({leef_header:sample.header,leef_extension:sample.extension,
        generic:{mode:'leef2_implicit_tab',source_raw:sample.raw}});
      const prepared=buildAutomaticGenericStructuralDraft(sample.raw,createDraft());
      expect(prepared).not.toBeNull();
      expect(prepared!.draft.genericStructuralProfile).toBe('leef2_implicit_tab');
      expect(prepared!.suite.counts).toMatchObject({total:1,extracted:1,failures:0});
      expect(prepared!.suite.events[0]!.fields).toEqual(parsed.fields);
      // Compare mapped string values through the actual browser normalizer,
      // including intentional padding, quoting and literal Unicode separators.
      const event=prepared!.suite.events[0]!;
      for(const mapping of prepared!.draft.mappings.filter(item=>item.type==='string')){
        const vendor=prepared!.draft.guided!.groups[mapping.id]==='vendor_fields';
        const targetRecord=vendor?event.normalized[prepared!.draft.vendor] as Record<string,unknown>:event.normalized;
        expect(lookupFieldValue(targetRecord,mapping.target)).toEqual(lookupFieldValue(parsed.fields,mapping.source));
      }
      const converted=toBackendProject(prepared!.draft);
      expect(converted.ok).toBe(true);
      if(!converted.ok)throw new Error('Implicit TAB project did not translate');
      expect(()=>assertBackendProjectSupported(converted.project,capability())).not.toThrow();
      const earlier=capability();earlier.authoring.genericStructuralProfiles=['syslog_prefix_kv'];
      expect(()=>assertBackendProjectSupported(converted.project,earlier)).toThrow(/selected Generic Structural profile/);
    });
  }

  it('selects a single profile for a homogeneous implicit TAB batch',()=>{
    const source=leefFixture.positive.slice(0,2).map(sample=>sample.raw).join('\n');
    const result=buildAutomaticGenericStructuralDraft(source,createDraft());
    expect(result).not.toBeNull();
    expect(result!.draft.genericStructuralProfile).toBe('leef2_implicit_tab');
    expect(result!.suite.counts).toMatchObject({total:2,extracted:2,failures:0});
  });

  it('rejects a batch requiring two incompatible additional profiles in either order',()=>{
    const samples=[syslogFixture.positive[0]!.raw,leefFixture.positive[0]!.raw];
    for(const ordered of [samples,[...samples].reverse()]){
      expect(buildAutomaticGenericStructuralDraft(ordered.join('\n'),createDraft())).toBeNull();
    }
  });

  it('does not drop new-profile source paths beyond the automatic mapping bound',()=>{
    const prefix='%NOTICE: '+Array.from({length:20},()=> 'context').join(' ')+' ';
    const source='<134>Oct 19 08:23:59 ftd01 '+prefix+
      Array.from({length:53},(_,index)=>'extra'+index+'=value').join(' ');
    const parsed=extractGenericStructural(source,'syslog_prefix_kv');
    expect(parsed.errors).toEqual([]);
    expect((parsed.fields.generic as {mode:string}).mode).toBe('syslog_prefix_kv');
    expect(buildAutomaticGenericStructuralDraft(source,createDraft())).toBeNull();
  });

  it('accepts each advertised profile subset and rejects duplicate or unknown claims',async()=>{
    const respond=(value:unknown)=>(async()=>new Response(JSON.stringify(value),{
      status:200,headers:{'Content-Type':'application/json'},
    })) as typeof fetch;
    for(const supported of [[profiles[0]],[profiles[1]],[...profiles]]){
      const cap=capability();cap.authoring.genericStructuralProfiles=supported;
      await expect(fetchBackendCapabilities(respond(cap))).resolves.toMatchObject({
        authoring:{genericStructuralProfiles:supported},
      });
    }
    for(const unsupported of [[],[profiles[0],profiles[0]],['unreviewed']]){
      const cap=capability() as unknown as {authoring:{genericStructuralProfiles:string[]}};
      cap.authoring.genericStructuralProfiles=unsupported;
      await expect(fetchBackendCapabilities(respond(cap))).rejects.toThrow(/profile capability/);
    }
  });
});
