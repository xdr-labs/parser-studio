import {useMemo,useState} from 'react';
import type {Dispatch,SetStateAction} from 'react';
import {ArrowLeft,ArrowRight,CheckCircle2,CircleAlert,Search,ShieldCheck,WandSparkles,X} from 'lucide-react';
import type {MappingRule,ParserDraft,SuiteResult} from '../model';
import {listSafeLeafPaths,lookupFieldValue} from '../fieldPaths';
import {defaultGuidedOptions} from './contract';
import {suggestNormalizationCandidatesFromSuite,type NormalizationCandidate} from './normalizationCandidates';
import {validateNormalizationMappings,type NormalizationFindingCode} from './normalizationValidation';
import {
  findStellarMetadataField,searchStellarMetadataCatalog,STELLAR_METADATA_CATALOG,
  STELLAR_METADATA_CATALOG_PROVENANCE,
} from './stellarMetadataCatalog';

interface Props {
  draft:ParserDraft;
  setDraft:Dispatch<SetStateAction<ParserDraft>>;
  suite?:SuiteResult;
  selected:number;
  setSelected:(index:number)=>void;
  pending:boolean;
  onBack:()=>void;
  onContinue:()=>void;
}

const TYPES:MappingRule['type'][]=['string','integer','number','boolean','ip','port','timestamp'];
const BLOCKING=new Set<NormalizationFindingCode>([
  'TARGET_COLLISION','TYPE_ERROR','UNVERIFIED_TARGET','CATALOG_TYPE_MISMATCH',
  'TARGET_RESERVED','BACKEND_TYPE_UNSUPPORTED',
]);

function displayValue(value:unknown):string{
  if(value===undefined)return '—';
  if(typeof value==='string')return value.length>80?value.slice(0,77)+'…':value;
  const rendered=JSON.stringify(value);
  return rendered?.length>80?rendered.slice(0,77)+'…':rendered??String(value);
}
function sourceValues(suite:SuiteResult|undefined,source:string):string[]{
  if(!suite)return [];
  const values:string[]=[];
  for(const event of suite.events){
    const found=lookupFieldValue(event.fields,source);
    if(found.found&&!values.includes(displayValue(found.value)))values.push(displayValue(found.value));
    if(values.length===3)break;
  }
  return values;
}
function catalogState(mapping:MappingRule){
  if(mapping.target.startsWith('custom.'))return {label:'Custom field',kind:'custom' as const};
  const entry=findStellarMetadataField(mapping.target);
  if(entry?.mappable&&entry.mappingType===mapping.type)return {label:'Official catalog',kind:'verified' as const};
  return {label:'Needs review',kind:'review' as const};
}

export default function NormalizationMappingReview({
  draft,setDraft,suite,selected,setSelected,pending,onBack,onContinue,
}:Props){
  const [search,setSearch]=useState('');
  const [catalogQuery,setCatalogQuery]=useState('');
  const [activeMappingId,setActiveMappingId]=useState<string|null>(null);
  const candidates=useMemo(()=>suggestNormalizationCandidatesFromSuite(suite,draft.mappings),[suite,draft.mappings]);
  const findings=useMemo(()=>validateNormalizationMappings(suite,draft.mappings),[suite,draft.mappings]);
  const chosen=suite?.events[selected]??suite?.events[0];
  const sourceFields=useMemo(()=>{
    const result=new Set<string>();
    for(const event of suite?.events??[])for(const path of listSafeLeafPaths(event.fields))result.add(path);
    return [...result];
  },[suite]);
  const mappedSources=new Set(draft.mappings.map(mapping=>mapping.source));
  const officialCount=draft.mappings.filter(mapping=>catalogState(mapping).kind==='verified').length;
  const customCount=draft.mappings.filter(mapping=>mapping.target.startsWith('custom.')).length;
  const blocking=findings.filter(finding=>BLOCKING.has(finding.code));
  const candidateView=candidates.filter(candidate=>{
    const needle=search.trim().toLowerCase();
    return !needle||candidate.source.toLowerCase().includes(needle)||candidate.target.toLowerCase().includes(needle);
  });
  const catalogResults=searchStellarMetadataCatalog(catalogQuery,30);
  const highBulk=candidates.filter(candidate=>candidate.confidence==='HIGH'&&candidate.safeForBulk);

  const applyCandidate=(candidate:NormalizationCandidate)=>{
    setDraft(old=>{
      const existing=old.mappings.find(mapping=>mapping.source===candidate.source);
      const id=existing?.id??candidate.replacesMappingId??
        'stellar-'+candidate.source.replace(/[^A-Za-z0-9_-]/g,'_')+'-'+String(old.mappings.length+1);
      const next:MappingRule={id,source:candidate.source,target:candidate.target,type:candidate.type};
      const mappings=existing
        ?old.mappings.map(mapping=>mapping.id===existing.id?next:mapping)
        :[...old.mappings,next];
      const options=old.guided??defaultGuidedOptions();
      return {...old,mappings,guided:{...options,groups:{...options.groups,[id]:candidate.group}}};
    });
  };
  const applyHighConfidence=()=>{
    const approved=highBulk;
    if(!approved.length)return;
    setDraft(old=>{
      let mappings=[...old.mappings];
      const options=old.guided??defaultGuidedOptions();
      const groups={...options.groups};
      for(const candidate of approved){
        const index=mappings.findIndex(mapping=>mapping.source===candidate.source);
        const existing=index>=0?mappings[index]:undefined;
        const id=existing?.id??'stellar-'+candidate.source.replace(/[^A-Za-z0-9_-]/g,'_')+'-'+String(mappings.length+1);
        const next:MappingRule={id,source:candidate.source,target:candidate.target,type:candidate.type};
        if(index>=0)mappings[index]=next;else mappings.push(next);
        groups[id]=candidate.group;
      }
      return {...old,mappings,guided:{...options,groups}};
    });
  };
  const updateMapping=(id:string,key:'source'|'target'|'type',value:string)=>{
    setDraft(old=>{
      const options=old.guided??defaultGuidedOptions();
      const groups={...options.groups};
      const mappings=old.mappings.map(mapping=>{
        if(mapping.id!==id)return mapping;
        if(key==='type')return {...mapping,type:value as MappingRule['type']};
        if(key==='source')return {...mapping,source:value};
        const catalog=findStellarMetadataField(value);
        if(catalog?.mappable&&catalog.mappingType&&catalog.group){
          groups[id]=catalog.group;
          return {...mapping,target:value,type:catalog.mappingType};
        }
        if(value.startsWith('custom.'))groups[id]='vendor_fields';
        return {...mapping,target:value};
      });
      return {...old,mappings,guided:{...options,groups}};
    });
  };
  const removeMapping=(id:string)=>{
    setDraft(old=>{
      const options=old.guided??defaultGuidedOptions();
      const groups={...options.groups};delete groups[id];
      return {...old,mappings:old.mappings.filter(mapping=>mapping.id!==id),
        guided:{...options,groups}};
    });
  };
  const applyCatalogField=(entryName:string)=>{
    if(!activeMappingId)return;
    updateMapping(activeMappingId,'target',entryName);
    setCatalogQuery('');setActiveMappingId(null);
  };

  const findingCounts=new Map<NormalizationFindingCode,number>();
  for(const finding of findings)findingCounts.set(finding.code,(findingCounts.get(finding.code)??0)+1);

  return <section aria-label="Map Fields stage" className="normalization-review">
    <div className="normalization-title-row">
      <div>
        <h2>Map Fields</h2>
        <p>Review how extracted source fields become Stellar Cyber normalized fields. Source values remain unchanged and available for comparison.</p>
      </div>
      <span className="normalization-catalog-badge"><ShieldCheck size={15}/>
        Stellar metadata {STELLAR_METADATA_CATALOG_PROVENANCE.release} · public vendor documentation
      </span>
    </div>

    <div className="normalization-runtime-note" role="note">
      <strong>Catalog verified · target runtime not verified</strong>
      <span>The field names and documented types below are pinned to the public Stellar Cyber metadata dictionary. A real DP/sensor ingestion test is still a separate gate.</span>
    </div>

    <div className="normalization-kpis" aria-label="Normalization mapping summary">
      <div><span>Extracted fields</span><strong>{sourceFields.length}</strong></div>
      <div><span>Official mappings</span><strong>{officialCount}</strong></div>
      <div><span>Custom mappings</span><strong>{customCount}</strong></div>
      <div><span>Unmapped source fields</span><strong>{sourceFields.filter(field=>!mappedSources.has(field)).length}</strong></div>
      <div className={blocking.length?'attention':''}><span>Blocking issues</span><strong>{blocking.length}</strong></div>
    </div>

    <section className="normalization-suggestions" aria-label="Automatic normalization suggestions">
      <div className="normalization-section-head">
        <div>
          <h3>Automatic suggestions</h3>
          <p>Only official scalar destinations with compatible observed values are suggested. Ambiguous, reserved, object and unsupported fields are skipped.</p>
        </div>
        <button type="button" className="auto-parser-primary" disabled={!highBulk.length||pending}
          onClick={applyHighConfidence}><WandSparkles size={14}/>Apply {highBulk.length} high-confidence suggestion{highBulk.length===1?'':'s'}</button>
      </div>
      <label className="normalization-search"><Search size={14}/><span className="sr-only">Search mapping suggestions</span>
        <input aria-label="Search normalization suggestions" value={search}
          placeholder="Search source or Stellar field" onChange={event=>setSearch(event.target.value)}/>
      </label>
      {candidateView.length===0?<p className="normalization-empty">No additional official mapping suggestion needs review for this sample.</p>:
        <div className="normalization-candidate-list">
          {candidateView.map(candidate=><article key={candidate.source} className={'normalization-candidate '+candidate.confidence.toLowerCase()}>
            <div className="normalization-source">
              <strong>{candidate.source}</strong>
              <small>{sourceValues(suite,candidate.source).join(' · ')||'No displayable sample value'}</small>
              {candidate.currentTarget&&<span>Current: {candidate.currentTarget}</span>}
            </div>
            <ArrowRight size={17} aria-hidden="true"/>
            <div className="normalization-target">
              <strong>{candidate.target}</strong>
              <span>{candidate.type} · Official standard field</span>
              <small>{candidate.method==='EXACT_DICTIONARY_NAME'?'Exact catalog name':'Reviewed alias'} · seen in {candidate.observed}/{candidate.total} event{candidate.total===1?'':'s'}</small>
            </div>
            <span className={'normalization-confidence '+candidate.confidence.toLowerCase()}>{candidate.confidence}</span>
            <button type="button" aria-label={'Apply official mapping '+candidate.source}
              onClick={()=>applyCandidate(candidate)}>Use mapping</button>
            <p>{candidate.explanation}</p>
          </article>)}
        </div>}
    </section>

    <section className="normalization-editor" aria-label="Normalization mapping editor">
      <div className="normalization-section-head">
        <div><h3>Review mappings</h3>
          <p>Edit a destination or type, or remove a mapping. Removing it never deletes the extracted source field.</p></div>
      </div>
      <datalist id="stellar-metadata-field-list">
        {STELLAR_METADATA_CATALOG.filter(entry=>entry.mappable).map(entry=><option value={entry.name} key={entry.name}/>)}
      </datalist>
      {draft.mappings.map((mapping,index)=>{
        const state=catalogState(mapping);
        const group=draft.guided?.groups[mapping.id]??'vendor_fields';
        return <article className={'normalization-map-row '+state.kind} key={mapping.id}
          aria-label={'Normalization mapping '+(index+1)}>
          <div className="normalization-map-status">
            {state.kind==='verified'?<CheckCircle2 size={16}/>:state.kind==='review'?<CircleAlert size={16}/>:<ShieldCheck size={16}/>}
            <span>{state.label}</span>
          </div>
          <label>Source field
            <input aria-label={'Normalized source '+index} value={mapping.source}
              onChange={event=>updateMapping(mapping.id,'source',event.target.value)}/>
          </label>
          <ArrowRight size={16} className="normalization-row-arrow" aria-hidden="true"/>
          <label>Stellar / output field
            <input aria-label={'Normalized destination '+index} list="stellar-metadata-field-list"
              value={mapping.target} onChange={event=>updateMapping(mapping.id,'target',event.target.value)}/>
          </label>
          <label>Type
            <select aria-label={'Normalized type '+index} value={mapping.type}
              onChange={event=>updateMapping(mapping.id,'type',event.target.value)}>
              {TYPES.map(type=><option value={type} key={type}>{type}</option>)}
            </select>
          </label>
          <div className="normalization-map-meta">
            <span>{state.kind==='verified'?'Official standard field':group==='vendor_fields'?'Custom/vendor field':'Reviewed output field'}</span>
            <span>{sourceValues(suite,mapping.source).length} sample value{sourceValues(suite,mapping.source).length===1?'':'s'} shown</span>
          </div>
          <div className="normalization-map-actions">
            <button type="button" onClick={()=>{setActiveMappingId(mapping.id);setCatalogQuery(mapping.target.startsWith('custom.')?'':mapping.target);}}>
              Find Stellar field
            </button>
            <button type="button" aria-label={'Remove normalization '+index} onClick={()=>removeMapping(mapping.id)}>
              <X size={14}/>Unmap
            </button>
          </div>
        </article>;
      })}
    </section>

    {activeMappingId&&<section className="normalization-catalog-search" aria-label="Search official Stellar metadata catalog">
      <div className="normalization-section-head"><div><h3>Official metadata catalog</h3>
        <p>{STELLAR_METADATA_CATALOG.length} fields pinned from {STELLAR_METADATA_CATALOG_PROVENANCE.release}. Non-scalar and reserved fields remain visible but cannot be selected.</p></div>
        <button type="button" onClick={()=>setActiveMappingId(null)}><X size={14}/>Close</button>
      </div>
      <label><Search size={14}/><span className="sr-only">Search Stellar metadata catalog</span>
        <input autoFocus aria-label="Search Stellar metadata catalog" value={catalogQuery}
          placeholder="srcip, action, timestamp…" onChange={event=>setCatalogQuery(event.target.value)}/></label>
      <div className="normalization-catalog-results">
        {catalogResults.map(entry=><div key={entry.name}>
          <strong>{entry.name}</strong>
          <span>{entry.documentedTypes.join(' / ')}</span>
          <small>{entry.descriptions[0]??(entry.mappable?'Official standard field':(entry.reason??'Not directly mappable'))}</small>
          <button type="button" disabled={!entry.mappable} onClick={()=>applyCatalogField(entry.name)}>Use</button>
        </div>)}
      </div>
    </section>}

    <section className="normalization-validation" aria-label="Normalization validation" role="status">
      <div className="normalization-section-head"><div><h3>Whole-sample checks</h3>
        <p>Every mapping is checked against every current sample event. Mapping edits automatically invalidate prior generated evidence.</p></div>
        <span className={blocking.length?'normalization-confidence review':'normalization-confidence high'}>
          {blocking.length?blocking.length+' blocking issue'+(blocking.length===1?'':'s'):'READY FOR LOCAL TEST'}
        </span>
      </div>
      {findings.length===0?<p className="normalization-pass"><CheckCircle2 size={15}/>No local mapping issues detected.</p>:
        <div className="normalization-finding-summary">
          {[...findingCounts.entries()].map(([code,count])=><div key={code}>
            <strong>{code}</strong><span>{count}</span>
            <small>{findings.filter(item=>item.code===code).slice(0,4).map(item=>
              (item.event?'event '+item.event+' · ':'')+item.source+' → '+item.target).join(' | ')}</small>
          </div>)}
        </div>}
    </section>

    {chosen&&<section className="normalization-comparison" aria-label="Normalization comparison">
      <div className="normalization-section-head">
        <div><h3>Result preview</h3><p>Compare the selected event before and after normalization, then switch events to review more samples.</p></div>
        <label>Review event
          <select aria-label="Normalization review event" value={chosen.id}
            onChange={event=>setSelected(Math.max(0,(suite?.events??[]).findIndex(item=>item.id===event.target.value)))}>
            {(suite?.events??[]).map(entry=><option value={entry.id} key={entry.id}>Event {entry.line} · {entry.status}</option>)}
          </select>
        </label>
      </div>
      <div className="normalization-diff-list" aria-label="Normalization changes only">
        {draft.mappings.map(mapping=>{
          const found=lookupFieldValue(chosen.fields,mapping.source);
          const after=chosen.normalized[mapping.target];
          return <div key={mapping.id}>
            <strong>{mapping.source}</strong><span>{found.found?displayValue(found.value):'Not present'}</span>
            <ArrowRight size={14}/><strong>{mapping.target}</strong>
            <span>{after===undefined?(pending?'Refreshing preview…':'Not emitted'):displayValue(after)}</span>
          </div>;
        })}
      </div>
      <details className="auto-parser-recipe">
        <summary>Full selected-event comparison</summary>
        <div className="auto-parser-preview normalization-full-preview">
          <div><h3>Original · Browser only</h3><pre>{chosen.raw}</pre></div>
          <div><h3>Extracted source</h3><pre>{JSON.stringify(chosen.fields,null,2)}</pre></div>
          <div><h3>Normalized · Browser only</h3><pre>{JSON.stringify(chosen.normalized,null,2)}</pre></div>
        </div>
      </details>
    </section>}

    <div className="auto-parser-actions">
      <button type="button" onClick={onBack}><ArrowLeft size={14}/>Back to Review Fields</button>
      <button type="button" className="auto-parser-primary" disabled={pending||!suite||blocking.length>0}
        onClick={onContinue}>Create Parser <ArrowRight size={16}/></button>
    </div>
  </section>;
}
