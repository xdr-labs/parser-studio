import {describe,expect,it} from 'vitest';
import leefControls from '../../tests/fixtures/roadmap-leef2-precedence-20261020.json';
import {extractGenericStructural} from '../genericStructural';
import {GENERIC_STRUCTURAL_MIXED_PROFILE_V1 as mixedProfile} from '../genericStructuralProfiles';
import {lookupFieldValue} from '../fieldPaths';
import {createDraft} from '../model';
import {MAX_DATASET_BYTES,MAX_EVENTS} from '../parser';
import {buildAutomaticGenericStructuralDraft} from './genericStructuralAutoDraft';
import {toBackendProject} from './backendAdapter';
import {assertBackendProjectSupported,fetchBackendCapabilities,type BackendCapabilities} from './backendCapabilities';
import {selectDraftFormat} from './draftFormatTransition';
import {validLocalDraft} from './localWorkspaceHistory';

const syslogRaw='<134>Oct 19 08:23:59 ftd01 %FTD-4-430002: Intrusion event detected src=192.0.2.40 dst=198.51.100.5 action=block user="  이가람  "';
const leefRaw='LEEF:2.0|  Example Vendor  |Access Log|1.0|notice|usrName=  문지수  \tsrc=192.0.2.6\tdst=198.51.100.4\tmsg=  café 허용  \taction=allowed';
const syslogFields={
  syslog:{pri:'134',month:'Oct',day:'19',time:'08:23:59',hostname:'ftd01',time_policy:'YEAR_AND_ZONE_UNKNOWN'},
  generic:{mode:'syslog_prefix_kv',prefix:'%FTD-4-430002: Intrusion event detected ',
    message_raw:syslogRaw.slice('<134>Oct 19 08:23:59 ftd01 '.length),source_raw:syslogRaw,
    kv:{src:'192.0.2.40',dst:'198.51.100.5',action:'block',user:'  이가람  '}},
};
const leefFields={
  leef_header:{version:'2.0',vendor:'  Example Vendor  ',product:'Access Log',product_version:'1.0',event_id:'notice'},
  leef_extension:{usrName:'  문지수  ',src:'192.0.2.6',dst:'198.51.100.4',msg:'  café 허용  ',action:'allowed'},
  generic:{mode:'leef2_implicit_tab',source_raw:leefRaw},
};
const expectedPaths=[
  ...Object.keys(syslogFields.syslog).map(key=>'syslog.'+key),
  'generic.prefix','generic.message_raw',
  ...Object.keys(syslogFields.generic.kv).map(key=>'generic.kv.'+key),
  ...Object.keys(leefFields.leef_header).map(key=>'leef_header.'+key),
  ...Object.keys(leefFields.leef_extension).map(key=>'leef_extension.'+key),
];
const samples=[{raw:syslogRaw,fields:syslogFields},{raw:leefRaw,fields:leefFields}];

function prepared(source=sampleSource()){
  const result=buildAutomaticGenericStructuralDraft(source,createDraft());
  if(!result)throw new Error('The mixed original source did not produce a reviewed draft');
  return result;
}
function sampleSource(){return syslogRaw+'\n'+leefRaw;}
function project(){
  const converted=toBackendProject(prepared().draft);
  if(!converted.ok)throw new Error('The mixed draft did not translate: '+JSON.stringify(converted.issues));
  return converted.project;
}
function capability(combined?:boolean):BackendCapabilities{
  return {
    contract:'host-customized-pair.v0.1',projectSchemaRevision:'0.1',
    authoring:{receiverProtocols:['udp','tcp'],extractionFormats:['generic_structural'],
      genericStructuralGrammar:'GENERIC_STRUCTURAL_ULTRA_COMPILER_V15',genericStructuralDedicatedFamilies:true,
      genericStructuralProfiles:['syslog_prefix_kv','leef2_implicit_tab'],
      ...(combined===undefined?{}:{genericStructuralMixedProfileV1:combined}),
      formatCoverage:'reviewed-bounded-subset',httpReceiver:false,
      multipleDistinctReceiverPorts:false,multiline:false,arbitraryRuby:false},
    import:{exactInternalPairsEditable:true,unknownLegacyRubyEditable:false,structuralInspectionOnly:true},
    verification:{engineVerified:false,targetImportVerified:false,liveListenerVerified:false,proprietaryLoaderVerified:false},
    limits:{maxProjectBodyBytes:262144,maxInspectBodyBytes:2097152},
  };
}
const respond=(value:unknown)=>(async()=>new Response(JSON.stringify(value),{
  status:200,headers:{'Content-Type':'application/json'},
})) as typeof fetch;

describe('explicit versioned Syslog prefix/KV and implicit-TAB LEEF combination',()=>{
  for(const [order,ordered] of [['Syslog first',samples],['LEEF first',[...samples].reverse()]] as const){
    for(const [boundary,separator] of [['LF','\n'],['CRLF','\r\n']] as const){
      it('retains the complete field union and original values: '+order+', '+boundary,()=>{
        const result=prepared(ordered.map(sample=>sample.raw).join(separator));
        expect(result.draft.genericStructuralProfile).toBe(mixedProfile);
        expect(result.suite.counts).toMatchObject({total:2,matched:2,extracted:2,normalized:2,failures:0});
        expect(result.suite.events.map(event=>event.raw)).toEqual(ordered.map(sample=>sample.raw));
        expect(new Set(result.draft.mappings.map(mapping=>mapping.source))).toEqual(new Set(expectedPaths));
        for(const [index,event] of result.suite.events.entries()){
          expect(event.fields).toEqual(ordered[index]!.fields);
          expect(event.normalized.parserstudio_source).toEqual(ordered[index]!.fields);
          for(const mapping of result.draft.mappings.filter(item=>item.type==='string')){
            const value=lookupFieldValue(event.fields,mapping.source);
            if(!value.found)continue;
            const vendor=result.draft.guided!.groups[mapping.id]==='vendor_fields';
            const output=vendor?event.normalized[result.draft.vendor] as Record<string,unknown>:event.normalized;
            expect(lookupFieldValue(output,mapping.target)).toEqual(value);
          }
        }
        const converted=toBackendProject(result.draft);
        expect(converted.ok).toBe(true);
        if(!converted.ok)throw new Error('Combined project did not translate');
        expect(converted.project.extraction).toEqual({format:'generic_structural',genericStructuralProfile:mixedProfile,genericStructuralFamilyGrammar:'dedicated'});
        const normalization=converted.project.normalization;
        const destinations=[...Object.values(normalization.topFields),...Object.values(normalization.nsFields)]
          .map(field=>field.normalized_name);
        destinations.push(...Object.values(normalization.vendorFields)
          .map(field=>converted.project.vendor+'.'+field.normalized_name));
        expect(new Set(destinations).size).toBe(destinations.length);
        // Matching source meanings in disjoint grammars are not a coalesce rule.
        expect(normalization.vendorFields['generic.kv.src']).toBeDefined();
        expect(normalization.vendorFields['leef_extension.src']).toBeDefined();
        expect(()=>assertBackendProjectSupported(converted.project,capability(true))).not.toThrow();
      });
    }
  }

  it('prefers existing single profiles and retains no-profile V15 behavior',()=>{
    expect(extractGenericStructural(syslogRaw).errors).not.toHaveLength(0);
    expect(extractGenericStructural(syslogRaw,'leef2_implicit_tab').errors).not.toHaveLength(0);
    expect(prepared(syslogRaw).draft.genericStructuralProfile).toBe('syslog_prefix_kv');
    expect(prepared(leefRaw).draft.genericStructuralProfile).toBe('leef2_implicit_tab');
    const old='<134>date=2023-02-23 time=22:49:29 type=event subtype=system status=success';
    const legacy=extractGenericStructural(old);
    expect(legacy.errors).toEqual([]);
    expect(extractGenericStructural(old,mixedProfile)).toEqual(legacy);
    expect(prepared(old).draft.genericStructuralProfile).toBeUndefined();
  });

  it('keeps a five-key Syslog record on its existing V15 route when a single LEEF profile covers the batch',()=>{
    const old=syslogRaw.replace(' detected ',' detected signature=1000123 ');
    const legacy=extractGenericStructural(old);
    expect(legacy.errors).toEqual([]);
    expect(extractGenericStructural(old,mixedProfile)).toEqual(legacy);
    expect(prepared(old).draft.genericStructuralProfile).toBeUndefined();
    const batch=prepared(old+'\n'+leefRaw);
    expect(batch.draft.genericStructuralProfile).toBe('leef2_implicit_tab');
    expect(batch.suite.events[0]!.fields).toEqual(legacy.fields);
  });

  for(const invalid of leefControls.negative){
    it('rejects owned malformed LEEF before any alternate grammar: '+invalid.name,()=>{
      expect(extractGenericStructural(invalid.raw,mixedProfile)).toMatchObject({fields:{}});
      expect(extractGenericStructural(invalid.raw,mixedProfile).errors).not.toHaveLength(0);
      for(const ordered of [[syslogRaw,invalid.raw],[invalid.raw,syslogRaw]])
        expect(buildAutomaticGenericStructuralDraft(ordered.join('\n'),createDraft())).toBeNull();
    });
  }

  it('keeps an unrelated unsupported event in review instead of selecting a partial batch',()=>{
    expect(buildAutomaticGenericStructuralDraft(sampleSource()+'\nunrecognized event content',createDraft())).toBeNull();
  });

  it('preserves all wide mixed-profile source paths within the expanded mapping limit',()=>{
    const wideSyslog='<134>Oct 19 08:23:59 edge01 Notice '+Array.from({length:20},()=> 'context').join(' ')+' '+
      Array.from({length:28},(_,index)=>'s'+index+'=value').join(' ');
    const wideLeef='LEEF:2.0|Example|Access|1.0|notice|'+
      Array.from({length:28},(_,index)=>'l'+index+'=value').join('\t');
    expect(prepared(wideSyslog).draft.genericStructuralProfile).toBe('syslog_prefix_kv');
    expect(prepared(wideLeef).draft.genericStructuralProfile).toBe('leef2_implicit_tab');
    expect(extractGenericStructural(wideSyslog,mixedProfile).errors).toEqual([]);
    expect(extractGenericStructural(wideLeef,mixedProfile).errors).toEqual([]);
    const result=buildAutomaticGenericStructuralDraft(wideSyslog+'\n'+wideLeef,createDraft());
    expect(result).not.toBeNull();
    expect(result!.draft.mappings.length).toBeGreaterThan(60);
    for(let index=0;index<28;index++){
      expect(result!.draft.mappings.some(rule=>rule.source.endsWith('.s'+index))).toBe(true);
      expect(result!.draft.mappings.some(rule=>rule.source.endsWith('.l'+index))).toBe(true);
    }
    expect(result!.suite.counts).toMatchObject({total:2,matched:2,extracted:2,failures:0});
  });

  it('does not truncate a mixed batch at the event or source-byte limits',()=>{
    const compact=[syslogRaw,'LEEF:2.0|Example|Access|1.0|notice|src=192.0.2.6\taction=ok'];
    const tooMany=Array.from({length:MAX_EVENTS+1},(_,index)=>compact[index%2]!).join('\n');
    expect(new TextEncoder().encode(tooMany).byteLength).toBeLessThan(MAX_DATASET_BYTES);
    expect(buildAutomaticGenericStructuralDraft(tooMany,createDraft())).toBeNull();
    const oversized=Array.from({length:MAX_EVENTS},(_,index)=>samples[index%2]!.raw).join('\n');
    expect(new TextEncoder().encode(oversized).byteLength).toBeGreaterThan(MAX_DATASET_BYTES);
    expect(buildAutomaticGenericStructuralDraft(oversized,createDraft())).toBeNull();
  });

  it('clears the combination on a format change while preserving the original saved draft',()=>{
    const draft=prepared().draft;
    expect(validLocalDraft(draft)).toBe(true);
    expect(selectDraftFormat(draft,'generic_structural').genericStructuralProfile).toBe(mixedProfile);
    expect(selectDraftFormat(draft,'csv').genericStructuralProfile).toBeUndefined();
    expect(validLocalDraft({...draft,format:'csv'})).toBe(false);
    expect(draft.genericStructuralProfile).toBe(mixedProfile);
  });
});

describe('combined profile capability without expanding the old profile advertisement',()=>{
  it('requires the exact new capability while accepting old and explicitly false responses',async()=>{
    const mixed=project();
    for(const claim of [undefined,false]){
      const cap=await fetchBackendCapabilities(respond(capability(claim)));
      let rejected:unknown;
      try{assertBackendProjectSupported(mixed,cap);}catch(error){rejected=error;}
      expect(rejected).toMatchObject({code:'BACKEND_PROFILE_UNSUPPORTED'});
      for(const raw of [syslogRaw,leefRaw]){
        const converted=toBackendProject(prepared(raw).draft);
        if(!converted.ok)throw new Error('Single-profile draft did not translate');
        expect(()=>assertBackendProjectSupported(converted.project,cap)).not.toThrow();
      }
    }
    const current=await fetchBackendCapabilities(respond(capability(true)));
    expect(current.authoring.genericStructuralProfiles).toEqual(['syslog_prefix_kv','leef2_implicit_tab']);
    expect(()=>assertBackendProjectSupported(mixed,current)).not.toThrow();
  });

  it('rejects truthy non-boolean claims and never accepts the combination through the legacy list',async()=>{
    const base=capability();
    for(const invalid of [null,'true',1,{},[]]){
      const body={...base,authoring:{...base.authoring,genericStructuralMixedProfileV1:invalid}};
      await expect(fetchBackendCapabilities(respond(body))).rejects.toThrow(/profile capability/);
    }
    for(const advertised of [[mixedProfile],['syslog_prefix_kv','leef2_implicit_tab',mixedProfile]]){
      const body={...base,authoring:{...base.authoring,genericStructuralProfiles:advertised}};
      await expect(fetchBackendCapabilities(respond(body))).rejects.toThrow(/profile capability/);
    }
    const unrelated={...base,authoring:{...base.authoring,extractionFormats:['json'],
      genericStructuralGrammar:undefined,genericStructuralProfiles:undefined,genericStructuralMixedProfileV1:true}};
    await expect(fetchBackendCapabilities(respond(unrelated))).rejects.toThrow(/profile capability/);
  });
});
