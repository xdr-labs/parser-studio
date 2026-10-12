import {useEffect,useMemo,useRef,useState} from 'react';
import type {Dispatch,SetStateAction} from 'react';
import {ArrowLeft,ArrowRight,CheckCircle2,Download,FileArchive,FileText,
  LockKeyhole,ShieldAlert} from 'lucide-react';
import type {ParserDraft,SuiteResult} from '../model';
import {toBackendProject} from './backendAdapter';
import {fetchBackendCapabilities,assertBackendProjectSupported,
  type BackendCapabilities} from './backendCapabilities';
import {fetchBackendSchemaGuide} from './backendSchemaGuide';
import {validateBackendProject,generateBackendPair,type GeneratedPair} from './backendClient';
import {verifyGeneratedPair,packageGeneratedPair} from './artifactPackageClient';
import {analyzeLogEnvelopes,assessEnvelopeCompilation} from './autoParserEnvelope';
import {prepareAutoParserDraft} from './autoParserDraft';
import {buildReviewableRecipe,type RecipeReview} from './parserRecipeV2';
import type {EventBoundary} from './contract';

interface Props {
 draft:ParserDraft;
 setDraft:Dispatch<SetStateAction<ParserDraft>>;
 sample:string;setSample:(text:string)=>void;
 datasetName:string;setDatasetName:(name:string)=>void;
 suite?:SuiteResult;pending:boolean;
 runPreview:(candidate:ParserDraft,raw?:string)=>Promise<SuiteResult>;
 onEditDetails:()=>void;onExpert:()=>void;
}
const MAX_LOCAL_TEXT=64*1024;
const STEPS=['Add Logs','Review Results','Test & Generate'] as const;
type Evidence={key:string;status:'PASS'|'FAILED';total:number;issues:string[]};
type Pair={key:string;value:GeneratedPair};
type Zip={key:string;filename:string;sha256:string};
function download(filename:string,content:string|ArrayBuffer,binary=false){
 const object=new Blob([content],{type:binary?'application/zip':'application/octet-stream'});
 const url=URL.createObjectURL(object);
 const anchor=document.createElement('a');
 anchor.href=url;anchor.download=filename;document.body.append(anchor);anchor.click();anchor.remove();
 window.setTimeout(()=>URL.revokeObjectURL(url),1000);
}
const readable:Record<string,string>={
 UNTRUSTED_PREVIEW:'The local preview could not be verified; run it again.',
 SOURCE_CHANGED:'The log source changed. Review the current events again.',
 MIXED_OR_UNKNOWN:'The sample has mixed, malformed, or unrecognized events. Separate families in Edit Details; no log line will be discarded.',
 BOUNDARY_REVIEW:'The record boundaries are ambiguous. Open Edit Details to review multiline messages.',
 COMPILER_UNSUPPORTED:'The backend cannot safely compile the detected envelope and body.',
 COLUMNS_REQUIRED:'CSV columns require names before a parser can be generated. Open Edit Details.',
 BACKEND_UNAVAILABLE:'The local backend capabilities are unavailable. No parser is generated.',
 BACKEND_UNTRUSTED:'The backend returned an untrusted capability or verification claim.',
 SOURCE_LIMIT:'The sample is empty or exceeds the safe 64 KiB / 500 event limit.',
 MODEL_REVIEW_REQUIRED:'Some fields or classification rules require review. Open Edit Details to repair the draft.',
};
function statusMessage(reason:string){return readable[reason]??'Review the unsupported candidate in Edit Details.';}
export default function AutoParser({
 draft,setDraft,sample,setSample,datasetName,setDatasetName,suite,pending,
 runPreview,onEditDetails,onExpert,
}:Props){
 const [step,setStep]=useState<0|1|2>(0);
 const [selected,setSelected]=useState(0);
 const [busy,setBusy]=useState(false);
 const [message,setMessage]=useState('');
 const [reviewed,setReviewed]=useState<{source:string;mappingCount:number;requiresApproval:boolean}|null>(null);
 const [capability,setCapability]=useState<{source:string;value:BackendCapabilities}|null>(null);
 const [evidence,setEvidence]=useState<Evidence|null>(null);
 const [pair,setPair]=useState<Pair|null>(null);
 const [zip,setZip]=useState<Zip|null>(null);
 const [recipe,setRecipe]=useState<{key:string;value:RecipeReview}|null>(null);
 const epoch=useRef(0);
 const identity=JSON.stringify([draft,sample]);
 const currentRef=useRef(identity);currentRef.current=identity;
 const report=useMemo(()=>analyzeLogEnvelopes(sample,
   (draft.guided?.eventBoundary??'single-line') as EventBoundary),
   [sample,draft.guided?.eventBoundary]);
 useEffect(()=>{
   epoch.current++;setEvidence(null);setPair(null);setZip(null);setRecipe(null);setMessage('');
 },[identity]);
 const assessment=assessEnvelopeCompilation(report,
   capability?.source===sample?capability.value:null);
 const currentReview=reviewed?.source===sample?reviewed:null;
 const currentPair=pair?.key===identity?pair.value:null;
 const currentEvidence=evidence?.key===identity?evidence:null;
 const currentZip=zip?.key===identity?zip:null;
 const currentRecipe=recipe?.key===identity?recipe.value:null;
 const records=suite?.events??[];
 const chosen=records[selected]??records[0];
 const canReview=Boolean(sample.trim())&&!pending&&!!suite&&
   report.complete&&report.sourceCount>0&&!busy;
 const canGenerate=step===2&&!!currentReview&&!!suite&&!pending&&
   !busy&&assessment.status==='DRAFT_COMPILABLE';
 const confirmed=()=>{
   const record=suite;
   return !!record && record.engine==='browser-preview'&&
     record.nativeFluentdVerified===false&&record.stellarExportVerified===false&&
     record.counts.total>0&&record.counts.total===report.sourceCount&&
     record.counts.matched===record.counts.total&&
     record.counts.extracted===record.counts.total&&
     record.counts.normalized===record.counts.total&&
     record.counts.failures===0;
 };
 async function review(){
   if(!canReview||!suite)return;
   const token=++epoch.current, expected=identity;
   setBusy(true);setMessage('');setEvidence(null);setPair(null);
   try{
     const cap=await fetchBackendCapabilities();
     if(token!==epoch.current||currentRef.current!==expected)return;
     setCapability({source:sample,value:cap});
     const compiler=assessEnvelopeCompilation(report,cap);
     const next=prepareAutoParserDraft(sample,draft,suite,report,compiler);
     if(!next.ok){setMessage(statusMessage(next.reason));return;}
     setDraft(next.draft);setReviewed({
       source:sample,mappingCount:next.automaticMappingCount,
       requiresApproval:next.requiresApproval,
     });
     setStep(1);setSelected(0);
   }catch{
     if(token===epoch.current)setMessage(readable.BACKEND_UNAVAILABLE);
   }finally{if(token===epoch.current)setBusy(false);}
 }
 async function generate(){
   if(!canGenerate||!confirmed()||!suite)return;
   const token=++epoch.current, expected=identity;
   setBusy(true);setMessage('');setPair(null);setZip(null);
   try{
     const local=await runPreview(draft,sample);
     if(token!==epoch.current||currentRef.current!==expected)return;
     if(local.engine!=='browser-preview'||local.nativeFluentdVerified!==false||
       local.stellarExportVerified!==false||
       local.counts.total!==report.sourceCount||local.counts.total===0||
       local.counts.matched!==local.counts.total||
       local.counts.extracted!==local.counts.total||
       local.counts.normalized!==local.counts.total||local.counts.failures!==0){
       setEvidence({key:expected,status:'FAILED',total:local.counts.total,
         issues:['The full local sample suite has unmatched, failed or unverified events.']});
       return;
     }
     const translated=toBackendProject(draft);
     if(!translated.ok){
       setEvidence({key:expected,status:'FAILED',total:local.counts.total,
         issues:['The draft contains unsupported mapping or classification settings.']});
       return;
     }
     const schema=await fetchBackendSchemaGuide();
     const cap=await fetchBackendCapabilities();
     if(token!==epoch.current||currentRef.current!==expected)return;
     if(schema.revision!=='0.1'||!schema.formats.includes(translated.project.extraction.format))
       throw new Error('Unsupported compiler schema');
     assertBackendProjectSupported(translated.project,cap);
     const validated=await validateBackendProject(translated.project);
     if(token!==epoch.current||currentRef.current!==expected)return;
     if(!validated.ok){
       setEvidence({key:expected,status:'FAILED',total:local.counts.total,
         issues:validated.issues.map(i=>i.code).slice(0,8)});
       return;
     }
     const generated=await generateBackendPair(translated.project);
     await verifyGeneratedPair(generated);
     if(token!==epoch.current||currentRef.current!==expected)return;
     setCapability({source:sample,value:cap});
     setEvidence({key:expected,status:'PASS',total:local.counts.total,issues:[]});
     setPair({key:expected,value:generated});
   }catch{
     if(token===epoch.current&&currentRef.current===expected){
       setEvidence({key:expected,status:'FAILED',total:report.sourceCount,
         issues:['The current draft could not pass verified backend compilation and file integrity checks.']});
     }
   }finally{if(token===epoch.current)setBusy(false);}
 }
 async function previewRecipe(){
   if(!suite||busy||pending)return;
   const token=++epoch.current,expected=identity;
   setBusy(true);setRecipe(null);
   try{
     const result=await buildReviewableRecipe(sample,draft,suite);
     if(token===epoch.current&&currentRef.current===expected)
       setRecipe({key:expected,value:result});
   }catch{
     if(token===epoch.current&&currentRef.current===expected)
       setRecipe({key:expected,value:{ok:false,reason:'UNTRUSTED_PREVIEW'}});
   }finally{if(token===epoch.current)setBusy(false);}
 }
 async function zipPair(){
   if(!currentPair||!capability||!draft.guided||busy)return;
   const token=++epoch.current,expected=identity;
   setBusy(true);setMessage('');
   try{
     const archive=await packageGeneratedPair(currentPair,'1.0.0',
       capability.value,draft.guided.receiver.port);
     if(token!==epoch.current||currentRef.current!==expected)return;
     download(archive.filename,archive.bytes,true);
     setZip({key:expected,filename:archive.filename,sha256:archive.sha256});
   }catch{if(token===epoch.current)setMessage('ZIP verification failed; the two original DRAFT files remain available.');}
   finally{if(token===epoch.current)setBusy(false);}
 }
 async function upload(file:File|undefined){
   if(!file)return;
   if(file.size>MAX_LOCAL_TEXT){setMessage('The selected file exceeds 64 KiB. Reduce the file first.');return;}
   try{
     const value=new TextDecoder('utf-8',{fatal:true}).decode(await file.arrayBuffer());
     setSample(value);setDatasetName(file.name);setSelected(0);setStep(0);
   }catch{setMessage('Only bounded, valid UTF-8 text files can be opened locally.');}
 }
 return <main className="auto-parser-workspace" aria-label="Auto Parser v2">
   <header className="auto-parser-intro">
     <span className="pane-index">AUTO PARSER 2.0 · LOCAL FIRST</span>
     <h1>From raw logs to a parser draft in three steps.</h1>
     <p>Paste samples without selecting JSON, CEF, Regex or Ruby. Review every
       recognized event and optional field mapping before creating matched DRAFT files.</p>
     <div className="auto-parser-links">
       <button type="button" onClick={onEditDetails}>Edit Details · Six-step Builder</button>
       <button type="button" onClick={onExpert}>Expert Workbench</button>
     </div>
   </header>
   <nav aria-label="Auto Parser steps" className="auto-parser-steps">
     {STEPS.map((label,index)=><button type="button" key={label}
       aria-current={index===step?'step':undefined}
       disabled={index===1&&!currentReview||index===2&&!currentReview}
       className={index===step?'active':''}
       onClick={()=>setStep(index as 0|1|2)}>
       <span>{index+1}</span>{label}
     </button>)}
   </nav>
   <div className="auto-parser-body">
     {step===0&&<section aria-label="Add Logs stage">
       <h2>Add Logs</h2>
       <p>Paste or upload one event per line. Sample data stays inside this browser.
         Choose at least two representative events to improve coverage.</p>
       <div className="auto-parser-source-toolbar">
         <label>Local UTF-8 file
           <input type="file" aria-label="Auto Parser file upload"
             accept=".txt,.log,.json,.csv,text/plain"
             onChange={e=>{const file=e.currentTarget.files?.[0];
               e.currentTarget.value='';void upload(file);}}/>
         </label>
         <small>{datasetName} · Maximum 64 KiB / 500 events</small>
       </div>
       <textarea spellCheck={false} rows={10} aria-label="Auto Parser raw logs"
         placeholder="Paste representative raw log events here. No format selection needed."
         value={sample} onChange={e=>{setSample(e.target.value);
           setDatasetName('Pasted logs · Browser session only');setSelected(0);}}/>
       <div className="auto-parser-ledger" aria-label="Automatic event accounting">
         <strong>{report.accounted}/{report.sourceCount} events analyzed locally</strong>
         <span>{report.unsupported} require review · Native parser NOT VERIFIED</span>
         {report.families.map(x=><span key={x.envelope+'/'+x.body}>
           {x.envelope==='none'?'Standalone':x.envelope.toUpperCase()} / {x.body.toUpperCase()}
           {' · '}{x.count}</span>)}
       </div>
       <p className="auto-parser-note">Unknown, malformed, RFC3164 and multiline events
         cannot be silently dropped or marked compiler-ready.</p>
       <button type="button" className="auto-parser-primary"
         disabled={!canReview} onClick={()=>{void review();}}>
         {busy?'Checking the backend…':'Review Detected Results'} <ArrowRight size={16}/>
       </button>
     </section>}
     {step===1&&<section aria-label="Review Results stage">
       <h2>Review Results</h2>
       <p>The original sample remains unchanged. Source values appear only in your local
         event inspector; extracted/normalized values are never sent as raw logs.</p>
       <div className="auto-parser-summary">
         <span>Browser events <strong>{report.sourceCount}</strong></span>
         <span>Need review <strong>{report.unsupported}</strong></span>
         <span>Mapping rules <strong>{draft.mappings.length}</strong></span>
       </div>
       {!!currentReview?.mappingCount&&<p className="auto-parser-note">
         {currentReview.mappingCount} conservative custom-field suggestions were prepared
         from safe source names. They are not an official Stellar dictionary.</p>}
       {currentReview?.requiresApproval&&<p className="auto-parser-note">
         Existing edited mapping rules were preserved. Confirm them in Edit Details
         before generating files.</p>}
       <label>Choose a source event
         <select aria-label="Auto Parser review event" value={chosen?.id??''}
           onChange={e=>setSelected(Math.max(0,records.findIndex(x=>x.id===e.target.value)))}>
           {records.map((entry)=><option key={entry.id} value={entry.id}>
             Event {entry.line} · {entry.status.toUpperCase()}</option>)}
         </select></label>
       {chosen&&<div className="auto-parser-preview" aria-label="Browser-only event inspector">
         <div><h3>Original · Browser only</h3><pre>{chosen.raw}</pre></div>
         <div><h3>Extracted</h3><pre>{JSON.stringify(chosen.fields,null,2)}</pre></div>
         <div><h3>Normalized · Browser only</h3><pre>{JSON.stringify(chosen.normalized,null,2)}</pre></div>
       </div>}
       <div className="auto-parser-map-list" aria-label="Suggested field mappings">
         {draft.mappings.map((rule)=><div key={rule.id}>
           <strong>{rule.source}</strong> <ArrowRight size={13}/>
           <span>{rule.target}</span><small>{rule.type} · User-custom field, not official catalog</small>
         </div>)}
       </div>
       <p className="auto-parser-note">If any names, field meanings or timestamps are
         uncertain, use Edit Details; your raw samples and accepted rules are preserved.</p>
       <div className="auto-parser-actions">
         <button type="button" onClick={()=>setStep(0)}><ArrowLeft size={15}/> Back to Logs</button>
         <button type="button" onClick={onEditDetails}>Adjust Mapping in Edit Details</button>
         <button type="button" className="auto-parser-primary" disabled={pending||!suite}
           onClick={()=>setStep(2)}>Test & Generate <ArrowRight size={16}/></button>
       </div>
     </section>}
     {step===2&&<section aria-label="Test and Generate stage">
       <h2>Test &amp; Generate</h2>
       <p>Run every sample through the local Web Worker, then validate the typed
         authoring contract with the real backend and verify both DRAFT file SHA-256 hashes.
         No parser deployment or sensor test occurs.</p>
       <div className="auto-parser-summary">
         <span>Events <strong>{report.sourceCount}</strong></span>
         <span>Locally matched <strong>{suite?.counts.matched??0}</strong></span>
         <span>Normalized <strong>{suite?.counts.normalized??0}</strong></span>
         <span>Errors <strong>{suite?.counts.failures??0}</strong></span>
       </div>
       {!confirmed()&&<p className="auto-parser-warning" role="note">
         Not all sample events passed the current local preview. Review those events
         in Edit Details before attempting backend generation.</p>}
       <button type="button" className="auto-parser-primary" disabled={!canGenerate||!confirmed()}
         onClick={()=>{void generate();}}>
         {busy?'Testing the full sample…':'Run Tests & Generate DRAFT Files'}
       </button>
       {currentEvidence&&<div className="auto-parser-result" aria-label="Auto Parser test evidence">
         <strong>{currentEvidence.status==='PASS'?'Schema/Hashes PASS · Native Unverified':
           'Generation Not Verified'}</strong>
         <span>{currentEvidence.total} browser events reviewed ·
           Stellar DP target import NOT VERIFIED</span>
         {currentEvidence.issues.map((issue,i)=><span key={i}>{issue}</span>)}
       </div>}
       {currentPair&&<div className="auto-parser-download" aria-label="Generated Auto Parser DRAFT pair">
         <strong><CheckCircle2 size={17}/> Two DRAFT files verified</strong>
         {currentPair.files.map(file=><button key={file.name} type="button"
           onClick={()=>download(file.name,file.content)}>
           <FileText size={15}/>{file.name} <Download size={15}/>
         </button>)}
         <button type="button" disabled={busy}
           onClick={()=>{void zipPair();}}><FileArchive size={16}/> Download Verified DRAFT ZIP</button>
         {currentZip&&<small>ZIP SHA-256: {currentZip.sha256} · {currentZip.filename}</small>}
       </div>}
       <details className="auto-parser-recipe" aria-label="ParserRecipe v0.2 review">
         <summary>Advanced · Review ParserRecipe v0.2 (not compilable)</summary>
         <p>This is a local-only staged review, not a native compiler or a deployment.
           The current backend accepts ParserProject v0.1 only; the original v0.1
           contract is preserved independently and no recipe is sent to the backend.</p>
         <button type="button" disabled={busy||pending||!suite}
           onClick={()=>{void previewRecipe();}}>Review Staged Recipe</button>
         {currentRecipe&&(currentRecipe.ok
           ? <div role="status" aria-label="Review-only staged recipe">
             <strong>REVIEW_ONLY · Native and target NOT VERIFIED</strong>
             <span>{currentRecipe.recipe.stages.length} allowlisted stages ·
               {currentRecipe.recipe.sample.events} events ·
               Source SHA-256 {currentRecipe.recipe.sample.sha256.slice(0,12)}…</span>
             <span>v0.1 snapshot: {currentRecipe.lossReport.status} ·
               v0.2 compiler NOT AVAILABLE</span>
             <p>{currentRecipe.recipe.stages.map(stage=>stage.op).join(' → ')}</p>
           </div>
           : <p role="status">Review cannot be generated safely: {statusMessage(currentRecipe.reason)}</p>)}
       </details>
       <p className="auto-parser-note"><LockKeyhole size={14}/> No API key, DP install or sensor send.
         Native Fluentd compatibility and real Stellar Cyber import remain unverified.</p>
       <div className="auto-parser-actions">
         <button type="button" onClick={()=>setStep(1)}><ArrowLeft size={14}/> Review Results</button>
         <button type="button" onClick={onEditDetails}>Edit Details & Advanced Verification</button>
       </div>
     </section>}
     {message&&<p role="alert" className="auto-parser-warning"><ShieldAlert size={16}/> {message}</p>}
   </div>
 </main>;
}
