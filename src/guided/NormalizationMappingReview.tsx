import {useMemo,useState} from 'react';
import type {Dispatch,SetStateAction} from 'react';
import {ArrowLeft,ArrowRight,CheckCircle2,CircleAlert,Search,ShieldCheck,WandSparkles,X} from 'lucide-react';
import type {MappingRule,ParserDraft,SuiteResult} from '../model';
import {listSafeLeafPaths,lookupFieldValue} from '../fieldPaths';
import {defaultGuidedOptions} from './contract';
import {suggestNormalizationCandidatesFromSuite,type NormalizationCandidate} from './normalizationCandidates';
import {isBlockingNormalizationFinding,validateNormalizationMappings,
  type NormalizationFindingCode} from './normalizationValidation';
import {HelpTip,StageGuide} from './BeginnerHelp';
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
const TYPE_LABEL:Record<MappingRule['type'],string>={
  string:'Text',integer:'Whole number',number:'Number',boolean:'Yes / No',
  ip:'IP address',port:'Network port',timestamp:'Date & time',
};
function eventStatusLabel(status:string){
  if(status==='pass')return 'Looks good';
  if(status==='warning')return 'Check details';
  return 'Needs attention';
}

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
function catalogState(mapping:MappingRule,group:string){
  if(group==='vendor_fields')return {label:'Vendor field',kind:'custom' as const};
  const entry=findStellarMetadataField(mapping.target);
  if(entry?.mappable&&entry.mappingType===mapping.type)return {label:'Matched to Stellar',kind:'verified' as const};
  return {label:'Check this mapping',kind:'review' as const};
}
const FINDING_LABEL:Record<NormalizationFindingCode,string>={
  TARGET_COLLISION:'Two fields use the same Stellar destination',
  TYPE_ERROR:'A sample value does not fit the selected value type',
  SOURCE_NOT_FOUND:'This source field is missing from some sample logs',
  UNVERIFIED_TARGET:'This destination is not in the checked Stellar field list',
  CATALOG_TYPE_MISMATCH:'The selected value type does not match the Stellar field',
  TARGET_RESERVED:'This Stellar field is managed by the system',
  BACKEND_TYPE_UNSUPPORTED:'This Stellar field cannot be mapped directly here',
};

/** Vendor-only lists longer than this are folded so the matched fields stay easy to reach. */
const VENDOR_LIST_COLLAPSE_AT=12;

export default function NormalizationMappingReview({
  draft,setDraft,suite,selected,setSelected,pending,onBack,onContinue,
}:Props){
  const [vendorListOpen,setVendorListOpen]=useState<boolean|null>(null);
  const [search,setSearch]=useState('');
  const [catalogQuery,setCatalogQuery]=useState('');
  const [activeMappingId,setActiveMappingId]=useState<string|null>(null);
  const groups=draft.guided?.groups??{};
  const candidates=useMemo(()=>suggestNormalizationCandidatesFromSuite(suite,draft.mappings,groups),[suite,draft.mappings,groups]);
  const findings=useMemo(()=>validateNormalizationMappings(suite,draft.mappings,groups),[suite,draft.mappings,groups]);
  const chosen=suite?.events[selected]??suite?.events[0];
  const sourceDisplay=(source:string)=>draft.format==='generic_structural'?'parserstudio_source.'+source:source;
  const sourceFields=useMemo(()=>{
    const result=new Set<string>();
    for(const event of suite?.events??[])for(const path of listSafeLeafPaths(event.fields))result.add(path);
    return [...result];
  },[suite]);
  const mappedSources=new Set(draft.mappings.map(mapping=>mapping.source));
  const officialCount=draft.mappings.filter(mapping=>catalogState(mapping,groups[mapping.id]??'vendor_fields').kind==='verified').length;
  const vendorCount=draft.mappings.filter(mapping=>(groups[mapping.id]??'vendor_fields')==='vendor_fields').length;
  const blocking=findings.filter(finding=>isBlockingNormalizationFinding(finding.code));
  // Notes that do not block (a field some sample logs simply do not carry).
  const noteSources=new Set(findings.filter(finding=>!isBlockingNormalizationFinding(finding.code)).map(finding=>finding.source));
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
        groups[id]='vendor_fields';
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
        <h2>Map Fields <HelpTip label="Map Fields"
          text="This step connects the field names found in your log to Stellar Cyber's standard field names. Your original values are kept; only the destination field name changes."/></h2>
        <p>Match the fields Parser Studio found to the Stellar Cyber field names you want to use.</p>
      </div>
      <span className="normalization-catalog-badge"><ShieldCheck size={15}/>
        Stellar field dictionary {STELLAR_METADATA_CATALOG_PROVENANCE.release}
      </span>
    </div>
    <StageGuide title="Recommended path">
      Apply the recommended matches first, check a few sample results below, and edit only the fields that do not match what you expect.
    </StageGuide>

    <div className="normalization-runtime-note" role="note">
      <strong>Suggestions come from Stellar Cyber's published field list</strong>
      <span>This step only prepares field names inside Parser Studio. Nothing is sent to a Stellar Cyber system from this screen.</span>
    </div>

    <div className="normalization-kpis" aria-label="Field mapping summary">
      <div><span>Fields found</span><strong>{sourceFields.length}</strong></div>
      <div><span>Matched to Stellar</span><strong>{officialCount}</strong></div>
      <div><span>Vendor-only fields</span><strong>{vendorCount}</strong></div>
      <div><span>Left out of output</span><strong>{sourceFields.filter(field=>!mappedSources.has(field)).length}</strong></div>
      <div className={blocking.length?'attention':''}><span>Must fix before continuing</span><strong>{blocking.length}</strong></div>
    </div>

    {draft.format==='generic_structural'&&<div className="normalization-runtime-note" role="group"
      aria-label="Original line copy">
      <label>
        <input type="checkbox" checked={draft.omitSourceRaw!==true}
          onChange={event=>setDraft(old=>{
            const next={...old};
            if(event.target.checked)delete next.omitSourceRaw;else next.omitSourceRaw=true;
            return next;
          })}/>
        {' '}Copy the full original line into every record (parserstudio_source ... source_raw)
      </label>
      <span>On (default): each output record also carries the whole original log line, so the output is about twice the size of the log. Turn it off to keep only the parsed fields. A field you mapped from source_raw still works, and your original log is not changed.</span>
    </div>}

    <section className="normalization-suggestions" aria-label="Recommended field matches">
      <div className="normalization-section-head">
        <div>
          <h3>Recommended matches <HelpTip label="Recommended matches"
            text="Parser Studio compares field names and sample values with Stellar Cyber's published field dictionary. A recommendation is automatic only when the observed values fit the expected kind of data."/></h3>
          <p>Start with the recommended matches. Fields that are ambiguous or system-managed are left alone for you to review.</p>
        </div>
        <button type="button" className="auto-parser-primary"
          aria-label={'Apply '+highBulk.length+' recommended match'+(highBulk.length===1?'':'es')}
          disabled={!highBulk.length||pending}
          onClick={applyHighConfidence}><WandSparkles size={14}/>Apply {highBulk.length} recommended match{highBulk.length===1?'':'es'}</button>
      </div>
      <label className="normalization-search"><Search size={14}/><span className="sr-only">Search mapping suggestions</span>
        <input aria-label="Search normalization suggestions" value={search}
          placeholder="Search source or Stellar field" onChange={event=>setSearch(event.target.value)}/>
      </label>
      {candidateView.length===0?<p className="normalization-empty">No additional official mapping suggestion needs review for this sample.</p>:
        <div className="normalization-candidate-list">
          {candidateView.map(candidate=><article key={candidate.source} className={'normalization-candidate '+candidate.confidence.toLowerCase()}>
            <div className="normalization-source">
              <strong>{sourceDisplay(candidate.source)}</strong>
              <small>{sourceValues(suite,candidate.source).join(' · ')||'No displayable sample value'}</small>
              {candidate.currentTarget&&<span>Current: {candidate.currentTarget}</span>}
            </div>
            <ArrowRight size={17} aria-hidden="true"/>
            <div className="normalization-target">
              <strong>{candidate.target}</strong>
              <span>{candidate.type} · Stellar field</span>
              <small>{candidate.method==='EXACT_DICTIONARY_NAME'?'Same name as Stellar field':'Common security-log name'} · value seen in {candidate.observed}/{candidate.total} event{candidate.total===1?'':'s'}</small>
            </div>
            <span className={'normalization-confidence '+candidate.confidence.toLowerCase()}>
              {candidate.confidence==='HIGH'?'Recommended':'Check first'}
            </span>
            <button type="button" aria-label={'Apply official mapping '+candidate.source}
              onClick={()=>applyCandidate(candidate)}>Use this match</button>
            <p>{candidate.explanation}</p>
          </article>)}
        </div>}
    </section>

    <section className="normalization-editor" aria-label="Field mapping editor">
      <div className="normalization-section-head">
        <div><h3>Review field matches <HelpTip label="Review field matches"
          text="Left is the field Parser Studio found in your log. Right is the field name that will be used in Stellar Cyber. Change the right side only when the suggested destination is wrong for your data."/></h3>
          <p>You can change a Stellar field or value type, or remove a mapping. Removing a mapping means that field does not appear in the generated parser output. Your original log is not changed.</p></div>
      </div>
      <datalist id="stellar-metadata-field-list">
        {STELLAR_METADATA_CATALOG.filter(entry=>entry.mappable).map(entry=><option value={entry.name} key={entry.name}/>)}
      </datalist>
      {(()=>{
      const renderRow=(mapping:MappingRule,index:number)=>{
        const group=draft.guided?.groups[mapping.id]??'vendor_fields';
        const state=catalogState(mapping,group);
        return <article className={'normalization-map-row '+state.kind} key={mapping.id}
          aria-label={'Field mapping '+(index+1)}>
          <div className="normalization-map-status">
            {state.kind==='verified'?<CheckCircle2 size={16}/>:state.kind==='review'?<CircleAlert size={16}/>:<ShieldCheck size={16}/>}
            <span>{state.label}</span>
          </div>
          <label>Field found in the log <HelpTip label="Field found in the log"
            text="This is the field name Parser Studio extracted from your source log. Change it only if the extraction itself used the wrong field name."/>
            <input aria-label={'Source field '+index} value={sourceDisplay(mapping.source)}
              onChange={event=>{
                const value=event.target.value;
                const prefix='parserstudio_source.';
                updateMapping(mapping.id,'source',
                  draft.format==='generic_structural'&&value.startsWith(prefix)
                    ?value.slice(prefix.length):value);
              }}/>
          </label>
          <ArrowRight size={16} className="normalization-row-arrow" aria-hidden="true"/>
          <label>{group==='vendor_fields'?'Vendor field name':'Stellar field name'} <HelpTip
            label={group==='vendor_fields'?'Vendor field name':'Stellar field name'}
            text={group==='vendor_fields'
              ?'This field is not mapped to the published Stellar dictionary. The generated parser keeps it under the '+(draft.vendor||'vendor')+' vendor namespace instead of inventing a Stellar field name.'
              :'This is where the value will appear in the normalized Stellar Cyber event. Use Choose Stellar field if you are unsure which name to use.'}/>
            <input aria-label={'Stellar field '+index} list="stellar-metadata-field-list"
              value={mapping.target} onChange={event=>updateMapping(mapping.id,'target',event.target.value)}/>
          </label>
          <label>Value type <HelpTip label="Value type"
            text="The kind of value expected here, such as IP address, port, whole number, text, or timestamp. Parser Studio checks your sample values against this choice."/>
            <select aria-label={'Value type '+index} value={mapping.type}
              onChange={event=>updateMapping(mapping.id,'type',event.target.value)}>
              {TYPES.map(type=><option value={type} key={type}>{TYPE_LABEL[type]}</option>)}
            </select>
          </label>
          <div className="normalization-map-meta">
            <span>{state.kind==='verified'?'Uses a Stellar standard field':group==='vendor_fields'?'Generated as '+(draft.vendor||'vendor')+'.'+mapping.target:'Needs your review'}</span>
            <span>{sourceValues(suite,mapping.source).length} example value{sourceValues(suite,mapping.source).length===1?'':'s'} shown</span>
          </div>
          <div className="normalization-map-actions">
            <button type="button" aria-label="Choose Stellar field"
              onClick={()=>{setActiveMappingId(mapping.id);setCatalogQuery(group==='vendor_fields'?'':mapping.target);}}>
              Choose Stellar field
            </button>
            <button type="button" aria-label={'Remove normalization '+index}
              title="Removes this mapping. The field will not appear in the generated parser output; your original log is not changed." onClick={()=>removeMapping(mapping.id)}>
              <X size={14}/>Leave out of output
            </button>
          </div>
        </article>;
      };
      const rows=draft.mappings.map((mapping,index)=>({mapping,index,
        vendor:(draft.guided?.groups[mapping.id]??'vendor_fields')==='vendor_fields'}));
      const lead=rows.filter(row=>!row.vendor);
      const vendorRows=rows.filter(row=>row.vendor);
      const collapsible=lead.length>0&&vendorRows.length>VENDOR_LIST_COLLAPSE_AT;
      if(!collapsible)return rows.map(row=>renderRow(row.mapping,row.index));
      return <>
        {lead.map(row=>renderRow(row.mapping,row.index))}
        <details className="normalization-vendor-list" open={vendorListOpen??false}
          onToggle={event=>setVendorListOpen(event.currentTarget.open)}>
          <summary>Vendor-only fields ({vendorRows.length}) · kept under the {draft.vendor||'vendor'} name, not matched to Stellar</summary>
          <p className="normalization-vendor-note">These fields have no Stellar standard name. Open the list to rename one or leave it out of the output; leaving them as they are is fine.</p>
          {vendorRows.map(row=>renderRow(row.mapping,row.index))}
        </details>
      </>;
      })()}
    </section>

    {activeMappingId&&<section className="normalization-catalog-search" aria-label="Stellar field chooser">
      <div className="normalization-section-head"><div><h3>Choose a Stellar field <HelpTip label="Stellar field list"
        text="Search Stellar Cyber's published field names. Some system-managed or grouped fields are shown for reference but cannot be selected directly."/></h3>
        <p>Search the published Stellar field list by name or description, then choose the field that best matches your source value.</p></div>
        <button type="button" onClick={()=>setActiveMappingId(null)}><X size={14}/>Close</button>
      </div>
      <label><Search size={14}/><span className="sr-only">Search Stellar field list</span>
        <input autoFocus aria-label="Search Stellar field list" value={catalogQuery}
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

    <section className="normalization-validation" aria-label="Field mapping checks" role="status">
      <div className="normalization-section-head"><div><h3>Check all sample logs <HelpTip label="Check all sample logs"
        text="Parser Studio checks every current sample against every mapping, not just the event you are viewing. This catches missing fields, wrong value types, and duplicate destinations before parser files are created."/></h3>
        <p>Each field match is checked across the full sample so a single unusual event cannot be hidden by the others.</p></div>
        <span className={blocking.length||noteSources.size?'normalization-confidence review':'normalization-confidence high'}>
          {blocking.length?'Fix '+blocking.length+' issue'+(blocking.length===1?'':'s')+' to continue'
            :noteSources.size?noteSources.size+' field'+(noteSources.size===1?'':'s')+' to double-check'
            :'No mapping problems found'}
        </span>
      </div>
      {findings.length===0?<p className="normalization-pass"><CheckCircle2 size={15}/>All current field mappings passed the sample checks.</p>:
        <div className="normalization-finding-summary">
          {[...findingCounts.entries()].map(([code,count])=><div key={code}>
            <strong>{FINDING_LABEL[code]}</strong><span>{count}</span>
            <small>{findings.filter(item=>item.code===code).slice(0,4).map(item=>
              (item.event?'event '+item.event+' · ':'')+item.source+' → '+item.target).join(' | ')}</small>
          </div>)}
        </div>}
      {!blocking.length&&findings.length>0&&<p className="normalization-empty">You can still continue. These notes do not block Create Parser.</p>}
    </section>

    {chosen&&<section className="normalization-comparison" aria-label="Field mapping comparison">
      <div className="normalization-section-head">
        <div><h3>See what will change <HelpTip label="Result preview"
          text="This preview shows the value found in the source log and the Stellar field where that value will appear. Switch events to make sure the mapping works for more than one example."/></h3><p>Check a few events before continuing, especially when the product sends several event types.</p></div>
        <label>Review event
          <select aria-label="Normalization review event" value={chosen.id}
            onChange={event=>setSelected(Math.max(0,(suite?.events??[]).findIndex(item=>item.id===event.target.value)))}>
            {(suite?.events??[]).map(entry=><option value={entry.id} key={entry.id}>Event {entry.line} · {eventStatusLabel(entry.status)}</option>)}
          </select>
        </label>
      </div>
      <div className="normalization-diff-list" aria-label="Field changes only">
        {draft.mappings.map(mapping=>{
          const found=lookupFieldValue(chosen.fields,mapping.source);
          const group=draft.guided?.groups[mapping.id]??'vendor_fields';
          const vendorRoot=chosen.normalized[draft.vendor];
          const afterResult=group==='vendor_fields'&&vendorRoot&&typeof vendorRoot==='object'&&!Array.isArray(vendorRoot)
            ?lookupFieldValue(vendorRoot as Record<string,unknown>,mapping.target)
            :lookupFieldValue(chosen.normalized,mapping.target);
          const after=afterResult.found?afterResult.value:undefined;
          const displayTarget=group==='vendor_fields'?(draft.vendor||'vendor')+'.'+mapping.target:mapping.target;
          return <div key={mapping.id}>
            <strong>{sourceDisplay(mapping.source)}</strong><span>{found.found?displayValue(found.value):'Not present'}</span>
            <ArrowRight size={14}/><strong>{displayTarget}</strong>
            <span>{after===undefined?(pending?'Refreshing preview…':'Not emitted'):displayValue(after)}</span>
          </div>;
        })}
      </div>
      <details className="auto-parser-recipe">
        <summary>See original, fields found, and Stellar output · Full selected-event comparison</summary>
        <div className="auto-parser-preview normalization-full-preview">
          <div><h3>Original log</h3><pre>{chosen.raw}</pre></div>
          <div><h3>Fields Parser Studio found</h3><pre>{JSON.stringify(chosen.fields,null,2)}</pre></div>
          <div><h3>Stellar output preview</h3><pre>{JSON.stringify(chosen.normalized,null,2)}</pre></div>
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
