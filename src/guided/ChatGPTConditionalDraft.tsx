import {useEffect,useMemo,useState} from 'react';
import type {Dispatch,SetStateAction} from 'react';
import type {ParserDraft,SuiteResult} from '../model';
import type {BackendCapabilities} from './backendCapabilities';
import {fetchBackendCapabilities,assertBackendProjectSupported} from './backendCapabilities';
import {toBackendProject} from './backendAdapter';
import {validateBackendProject,generateBackendPair,type GeneratedPair} from './backendClient';
import {verifyGeneratedPair} from './artifactPackageClient';
import ReviewedEventProfilesPanel from './ReviewedEventProfilesPanel';
import {validateNamedLogs,type NamedLogType} from './namedLogTypes';
import {checkNamedParserCoverage} from './chatGptSourceContext';

type Props={
  draft:ParserDraft;
  setDraft:Dispatch<SetStateAction<ParserDraft>>;
  sample:string;
  namedLogTypes?:NamedLogType[]|null;
  suite?:SuiteResult;
  pending:boolean;
  runPreview:(draft:ParserDraft,source?:string)=>Promise<SuiteResult>;
  onAutoParser:()=>void;
};

/** Reuses the exact reviewed conditional compiler shared with Auto Parser.
 * The restricted AI Recipe v0.2 has no conditional-routing stage. Never
 * project per-type mappings into an ordinary recipe or claim native support.
 */
export default function ChatGPTConditionalDraft({
  draft,setDraft,sample,suite,pending,runPreview,onAutoParser,namedLogTypes=null,
}:Props){
  const [capability,setCapability]=useState<{source:string;value:BackendCapabilities}|null>(null);
  const [availability,setAvailability]=useState<'CHECKING'|'READY'|'UNAVAILABLE'>('CHECKING');
  const [busy,setBusy]=useState(false);
  const [notice,setNotice]=useState('');
  const [generated,setGenerated]=useState<{identity:string;pair:GeneratedPair}|null>(null);
  const identity=useMemo(()=>JSON.stringify([sample,draft,namedLogTypes]),
    [sample,draft,namedLogTypes]);
  useEffect(()=>{
    let cancelled=false;
    setCapability(null);
    setAvailability('CHECKING');
    if(!sample.trim()||!suite||suite.counts.total<2||pending){
      setAvailability('UNAVAILABLE');
      return ()=>{cancelled=true;};
    }
    void fetchBackendCapabilities().then(value=>{
      if(cancelled)return;
      setCapability({source:sample,value});
      setAvailability(value.authoring.conditionalEventProfiles===true&&
        value.authoring.conditionalEventProfilesUnknownPolicy==='reject'?'READY':'UNAVAILABLE');
    }).catch(()=>{if(!cancelled)setAvailability('UNAVAILABLE');});
    return ()=>{cancelled=true;};
  },[sample,suite?.counts.total,pending]);
  useEffect(()=>{setNotice('');setGenerated(null);},[identity]);

  const supported=availability==='READY'&&capability?.source===sample;
  const complete=(result:SuiteResult)=>result.counts.total>1&&
    result.counts.matched===result.counts.total&&
    result.counts.extracted===result.counts.total&&
    result.counts.normalized===result.counts.total&&result.counts.failures===0&&
    result.events.length===result.counts.total&&
    result.events.every(event=>event.extracted&&event.normalizedOk);
  const generate=async()=>{
    if(busy||pending||!supported||!draft.eventProfiles||!sample.trim())return;
    setBusy(true);setGenerated(null);setNotice('');
    try{
      const local=await runPreview(draft,sample);
      if(!complete(local))throw new Error('Every log must pass before one conditional parser can be generated.');
      if(namedLogTypes){
        if(!validateNamedLogs(namedLogTypes).ok)
          throw new Error('Complete each named log type before generating a combined parser.');
        const perType=await Promise.all(namedLogTypes.map(group=>
          runPreview(draft,group.sample)));
        const coverage=checkNamedParserCoverage(draft,namedLogTypes,perType);
        if(!coverage.ok)throw new Error('Log type review required: '+coverage.reason);
      }
      const routed=new Set(local.events.map(event=>event.eventFamily));
      if(routed.size!==draft.eventProfiles.variants.length||
        draft.eventProfiles.variants.some(variant=>!routed.has(variant.name)))
        throw new Error('Each approved type must appear in the current sample and be recognized.');
      const adapted=toBackendProject(draft);
      if(!adapted.ok||!adapted.project.normalization.eventProfiles)
        throw new Error('Conditional routing is not representable by the backend.');
      assertBackendProjectSupported(adapted.project,capability!.value);
      const checked=await validateBackendProject(adapted.project);
      if(!checked.ok)throw new Error('The backend rejected the conditional parser draft.');
      const pair=await generateBackendPair(adapted.project);
      await verifyGeneratedPair(pair);
      setGenerated({identity,pair});
      setNotice('One reviewed conditional parser DRAFT is ready. No target installation or log transmission occurred.');
    }catch(error){
      setNotice(error instanceof Error?error.message:'The conditional parser was not generated.');
    }finally{setBusy(false);}
  };
  const download=(filename:string,content:string)=>{
    const url=URL.createObjectURL(new Blob([content],{type:'application/octet-stream'}));
    const anchor=document.createElement('a');
    anchor.href=url;anchor.download=filename;document.body.append(anchor);anchor.click();anchor.remove();
    window.setTimeout(()=>URL.revokeObjectURL(url),1000);
  };
  if(!sample.trim()||!suite||suite.counts.total<2)return null;
  return <section aria-label="ChatGPT multiple event types" className="auto-parser-recipe">
    <h3>Create one parser for several log types</h3>
    <p>Keep all original events in the combined local sample. If the product has an explicit
      event-type field, review a shared parser with separate mappings per type. Labels
      such as Threat or User organize the examples only; they are not parsing rules.</p>
    {draft.format==='auto'&&<p role="note">
      First identify a supported source format in Auto Parser, then return here.
      Automatic format detection does not invent an event-type discriminator.
      <button type="button" onClick={onAutoParser}>Review source format in Auto Parser</button>
    </p>}
    <ReviewedEventProfilesPanel
      suite={suite} draft={draft} setDraft={setDraft} source={sample}
      pending={pending||busy} highlightNamed={true}
      backendCapabilities={supported?capability.value:undefined}/>
    {availability==='UNAVAILABLE'&&<p role="note">Conditional compiler support could
      not be verified. Parser Studio will not generate an unverified combined parser.</p>}
    {draft.eventProfiles&&<div className="auto-parser-result"
      aria-label="Approved conditional parser">
      <strong>{draft.eventProfiles.variants.length} explicitly reviewed event types</strong>
      <p>Unknown event types are rejected. Generate with the validated backend,
        not the single-profile ChatGPT Recipe v0.2 importer, which cannot represent
        event-specific routing rules.</p>
      <button type="button" className="auto-parser-primary"
        disabled={busy||pending||!supported}
        onClick={()=>{void generate();}}>
        {busy?'Validating all log types…':'Validate & Generate One Multi-Type Parser'}
      </button>
      {generated?.identity===identity&&<div aria-label="Combined parser downloads">
        <p>Two integrity-checked DRAFT files are available. Native Stellar installation
          and sensor ingestion remain unverified.</p>
        {generated.pair.files.map(file=><button type="button" key={file.name}
          onClick={()=>download(file.name,file.content)}>Download {file.name}</button>)}
      </div>}
    </div>}
    {notice&&<p role="status">{notice}</p>}
  </section>;
}
