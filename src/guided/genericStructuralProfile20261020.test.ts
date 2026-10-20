import {describe,it,expect} from 'vitest';
import fixture from '../../tests/fixtures/roadmap-syslog-prefix-kv-20261020.json';
import {extractGenericStructural} from '../genericStructural';
import {createDraft} from '../model';
import {buildAutomaticGenericStructuralDraft} from './genericStructuralAutoDraft';
import {toBackendProject} from './backendAdapter';
import {assertBackendProjectSupported,fetchBackendCapabilities,type BackendCapabilities} from './backendCapabilities';

function capability():BackendCapabilities{
  return {
    contract:'host-customized-pair.v0.1',projectSchemaRevision:'0.1',
    authoring:{receiverProtocols:['udp','tcp'],extractionFormats:['generic_structural'],
      genericStructuralGrammar:'GENERIC_STRUCTURAL_ULTRA_COMPILER_V15',
      genericStructuralProfiles:['syslog_prefix_kv'],formatCoverage:'reviewed-bounded-subset',
      httpReceiver:false,multipleDistinctReceiverPorts:false,multiline:false,arbitraryRuby:false},
    import:{exactInternalPairsEditable:true,unknownLegacyRubyEditable:false,structuralInspectionOnly:true},
    verification:{engineVerified:false,targetImportVerified:false,liveListenerVerified:false,proprietaryLoaderVerified:false},
    limits:{maxProjectBodyBytes:256*1024,maxInspectBodyBytes:2*1024*1024},
  };
}

describe('explicit Syslog prefix and KV compiler profile',()=>{
  for(const sample of fixture.positive){
    it('preserves every reviewed source field for '+sample.name,()=>{
      expect(extractGenericStructural(sample.raw).errors).not.toHaveLength(0);
      const parsed=extractGenericStructural(sample.raw,'syslog_prefix_kv');
      expect(parsed.errors).toEqual([]);
      expect(parsed.fields).toMatchObject({
        syslog:{time_policy:'YEAR_AND_ZONE_UNKNOWN'},
        generic:{mode:'syslog_prefix_kv',prefix:sample.prefix,kv:sample.kv,source_raw:sample.raw},
      });
      const result=buildAutomaticGenericStructuralDraft(sample.raw,createDraft());
      expect(result).not.toBeNull();
      expect(result!.draft.genericStructuralProfile).toBe('syslog_prefix_kv');
      expect(result!.suite.counts.failures).toBe(0);
      expect(result!.suite.events[0]!.fields).toEqual(parsed.fields);
      const converted=toBackendProject(result!.draft);
      expect(converted.ok).toBe(true);
      if(!converted.ok)throw new Error('Profile translation failed');
      expect(converted.project.extraction).toEqual({format:'generic_structural',genericStructuralProfile:'syslog_prefix_kv'});
      expect(()=>assertBackendProjectSupported(converted.project,capability())).not.toThrow();
      const old=capability();delete old.authoring.genericStructuralProfiles;
      expect(()=>assertBackendProjectSupported(converted.project,old)).toThrow(/selected Generic Structural profile/);
    });
  }

  for(const sample of fixture.negative.filter(item=>item.name!=='multiline')){
    it('retains review for '+sample.name,()=>{
      expect(extractGenericStructural(sample.raw,'syslog_prefix_kv').errors).not.toHaveLength(0);
      expect(buildAutomaticGenericStructuralDraft(sample.raw,createDraft())).toBeNull();
    });
  }

  it('uses explicit line boundaries for a batch of two complete Syslog events',()=>{
    const sample=fixture.negative.find(item=>item.name==='multiline')!;
    expect(extractGenericStructural(sample.raw,'syslog_prefix_kv').errors).not.toHaveLength(0);
    const result=buildAutomaticGenericStructuralDraft(sample.raw,createDraft());
    expect(result).not.toBeNull();
    expect(result!.suite.counts).toMatchObject({total:2,extracted:2,failures:0});
    expect(result!.suite.events.map(event=>event.raw)).toEqual(sample.raw.split('\n'));
  });

  it('keeps existing generic records independent from the additional profile',()=>{
    const raw='<134>date=2023-02-23 time=22:49:29 type=event subtype=system status=success';
    const old=extractGenericStructural(raw);
    expect(old.errors).toEqual([]);
    expect(extractGenericStructural(raw,'syslog_prefix_kv')).toEqual(old);
    const result=buildAutomaticGenericStructuralDraft(raw,createDraft());
    expect(result).not.toBeNull();
    expect(result!.draft.genericStructuralProfile).toBeUndefined();
  });

  it('rejects unknown advertised profiles without changing older capability responses',async()=>{
    const respond=(value:unknown)=>(async()=>new Response(JSON.stringify(value),{
      status:200,headers:{'Content-Type':'application/json'},
    })) as typeof fetch;
    await expect(fetchBackendCapabilities(respond(capability()))).resolves.toMatchObject({
      authoring:{genericStructuralProfiles:['syslog_prefix_kv']},
    });
    const old=capability();delete old.authoring.genericStructuralProfiles;
    await expect(fetchBackendCapabilities(respond(old))).resolves.toMatchObject({
      authoring:{genericStructuralGrammar:'GENERIC_STRUCTURAL_ULTRA_COMPILER_V15'},
    });
    const bad=capability() as unknown as {authoring:{genericStructuralProfiles:string[]}};
    bad.authoring.genericStructuralProfiles=['unknown'];
    await expect(fetchBackendCapabilities(respond(bad))).rejects.toThrow(/profile capability/);
  });
});
