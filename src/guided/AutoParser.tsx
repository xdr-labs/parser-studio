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
import {matchKnownParserFingerprints,type FingerprintMatchReport} from './knownParserFingerprints';
import type {StructuralMiningReport} from './localPatternMining';
import {createPrivacySafeAIPrompt,importReviewOnlyAIRecipe,
  proposeV01FieldMappingFromAI,type AIPromptResult,type AIImportResult} from './aiRecipeExchange';
import {readApprovedPatterns,saveApprovedMapping,prepareApprovedPatternDraft,
  forgetApprovedPattern,type ApprovedPattern} from './approvedPatterns';
import {prepareBoundedPathCandidate} from './boundedPathReview';
import {proposeReviewableMapping,compareCandidate,
 type CandidateComparison} from './autoParserRegression';
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
 const [fingerprints,setFingerprints]=useState<{key:string;value:FingerprintMatchReport}|null>(null);
 const [structural,setStructural]=useState<{key:string;value:StructuralMiningReport}|null>(null);
 const [aiPrompt,setAIPrompt]=useState<{key:string;value:AIPromptResult}|null>(null);
 const [aiText,setAIText]=useState('');
 const [boundedPath,setBoundedPath]=useState('');
 const [aiImport,setAIImport]=useState<{key:string;value:AIImportResult}|null>(null);
 const [aiCopyNotice,setAICopyNotice]=useState('');
 const [approvedPatterns,setApprovedPatterns]=useState<ApprovedPattern[]>(()=>readApprovedPatterns());
 const [selectedPattern,setSelectedPattern]=useState('');
 const [saveAfterApproval,setSaveAfterApproval]=useState(false);
 const [reviewMetrics,setReviewMetrics]=useState({compared:0,approved:0,blocked:0});
 const [holdout,setHoldout]=useState('');
 const [repair,setRepair]=useState<{key:string;candidate:ParserDraft;
   comparison:CandidateComparison;source:string;target:string}|null>(null);
 const [repairNotice,setRepairNotice]=useState('');
 const epoch=useRef(0);
 const identity=JSON.stringify([draft,sample]);
 const currentRef=useRef(identity);currentRef.current=identity;
 const report=useMemo(()=>analyzeLogEnvelopes(sample,
   (draft.guided?.eventBoundary??'single-line') as EventBoundary),
   [sample,draft.guided?.eventBoundary]);
 useEffect(()=>{
   epoch.current++;setEvidence(null);setPair(null);setZip(null);setRecipe(null);
   setRepair(null);setRepairNotice('');setFingerprints(null);setStructural(null);
   setAIPrompt(null);setAIText('');setAIImport(null);setAICopyNotice('');
   setBoundedPath('');
   setSaveAfterApproval(false);
   setBusy(false);setMessage('');
 },[identity]);
 const assessment=assessEnvelopeCompilation(report,
   capability?.source===sample?capability.value:null);
 const currentReview=reviewed?.source===sample?reviewed:null;
 const currentPair=pair?.key===identity?pair.value:null;
 const currentEvidence=evidence?.key===identity?evidence:null;
 const currentZip=zip?.key===identity?zip:null;
 const currentRecipe=recipe?.key===identity?recipe.value:null;
 const currentFingerprints=fingerprints?.key===identity?fingerprints.value:null;
 const currentStructural=structural?.key===identity?structural.value:null;
 const currentAIPrompt=aiPrompt?.key===identity?aiPrompt.value:null;
 const currentAIImport=aiImport?.key===identity?aiImport.value:null;
 const repairKey=JSON.stringify([identity,holdout]);
 const currentRepair=repair?.key===repairKey?repair:null;
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
 async function compareRepair(){
   if(!suite||busy||pending)return;
   const token=++epoch.current,expected=identity,requestedHoldout=holdout;
   setBusy(true);setRepair(null);setRepairNotice('');
   try{
     const suggestion=proposeReviewableMapping(sample,draft,suite);
     if(!suggestion.ok){setRepairNotice('No safe one-field repair is available: '+suggestion.reason);return;}
     if(holdout&&new TextEncoder().encode(holdout).byteLength>MAX_LOCAL_TEXT){
       setRepairNotice('Holdout exceeds 64 KiB; reduce the input.');return;
     }
     const candidate=await runPreview(suggestion.candidate,sample);
     const held=holdout?{
       source:holdout,baseline:await runPreview(draft,holdout),
       candidate:await runPreview(suggestion.candidate,holdout),
     }:undefined;
     if(token!==epoch.current||currentRef.current!==expected||holdout!==requestedHoldout)return;
     const comparison=compareCandidate({source:sample,baseline:suite,candidate,holdout:held});
     setRepair({key:JSON.stringify([expected,requestedHoldout]),
       candidate:suggestion.candidate,comparison,
       source:suggestion.mapping.source,target:suggestion.mapping.target});
     setReviewMetrics(x=>({...x,compared:x.compared+1,
       blocked:x.blocked+Number(!comparison.acceptedWithoutRegression)}));
   }catch{
     if(token===epoch.current&&currentRef.current===expected)
       setRepairNotice('Local regression could not be verified. No rules were changed.');
   }finally{if(token===epoch.current)setBusy(false);}
 }
 async function compareStoredPattern(){
   if(!suite||busy||pending)return;
   const item=approvedPatterns.find(x=>x.id===selectedPattern);
   if(!item){setRepairNotice('Select one previously approved browser-local mapping.');return;}
   const proposal=prepareApprovedPatternDraft(draft,item);
   if(!proposal.ok){setRepairNotice('Stored mapping cannot be reused: '+proposal.reason);return;}
   const token=++epoch.current,expected=identity,requestedHoldout=holdout;
   setBusy(true);setRepair(null);setRepairNotice('');
   try{
     if(holdout&&new TextEncoder().encode(holdout).byteLength>MAX_LOCAL_TEXT)
       throw new Error('HOLDOUT_LIMIT');
     const candidate=await runPreview(proposal.draft,sample);
     const held=holdout?{source:holdout,
       baseline:await runPreview(draft,holdout),
       candidate:await runPreview(proposal.draft,holdout)}:undefined;
     if(token!==epoch.current||currentRef.current!==expected||holdout!==requestedHoldout)return;
     const comparison=compareCandidate({source:sample,baseline:suite,candidate,holdout:held});
     setRepair({key:JSON.stringify([expected,requestedHoldout]),
       candidate:proposal.draft,comparison,source:proposal.source,target:proposal.target});
     setReviewMetrics(x=>({...x,compared:x.compared+1,
       blocked:x.blocked+Number(!comparison.acceptedWithoutRegression)}));
   }catch{
     if(token===epoch.current&&currentRef.current===expected)
       setRepairNotice('Stored mapping regression was not verified; no rules changed.');
   }finally{if(token===epoch.current)setBusy(false);}
 }
 function approveRepair(){
   if(!currentRepair||!currentRepair.comparison.acceptedWithoutRegression||
      currentRepair.comparison.holdoutStatus!=='TESTED'||busy||pending)return;
   const accepted=currentRepair;
   if(saveAfterApproval){
     try{
       const mapping=accepted.candidate.mappings.at(-1);
       if(!mapping)throw new Error('INVALID_MAPPING');
       saveApprovedMapping({draft:accepted.candidate,mapping,
         comparison:accepted.comparison});
       setApprovedPatterns(readApprovedPatterns());
     }catch{
       setRepairNotice('Mapping approved for this draft; local pattern save was unavailable.');
     }
   }
   setDraft(accepted.candidate);setRepair(null);
   setReviewMetrics(x=>({...x,approved:x.approved+1}));
 }
 function findKnownTemplates(){
   if(!suite||busy||pending)return;
   try{setFingerprints({key:identity,value:matchKnownParserFingerprints(sample,suite)});}
   catch{setFingerprints(null);setMessage('The local template review could not verify this exact source.');}
 }
 async function mineUnknownShapes(){
   if(!suite||busy||pending)return;
   const token=++epoch.current,expected=identity;
   setBusy(true);setStructural(null);
   try{
     const value=await new Promise<StructuralMiningReport>((resolve,reject)=>{
       const worker=new Worker(new URL('./patternMiner.worker.ts',import.meta.url),{type:'module'});
       let settled=false;
       const finish=(value?:StructuralMiningReport)=>{
         if(settled)return;settled=true;window.clearTimeout(timeout);worker.terminate();
         if(value)resolve(value);else reject(new Error('Worker unavailable'));
       };
       const timeout=window.setTimeout(()=>finish(),1800);
       worker.onmessage=(event:MessageEvent<{report?:StructuralMiningReport}>)=>
         finish(event.data.report);
       worker.onerror=()=>finish();
       worker.postMessage({source:sample});
     });
     if(token===epoch.current&&currentRef.current===expected)
       setStructural({key:expected,value});
   }catch{
     if(token===epoch.current&&currentRef.current===expected)
       setMessage('Local structural grouping was unavailable; no source was uploaded.');
   }finally{if(token===epoch.current)setBusy(false);}
 }
 async function prepareAIPrompt(){
   if(!suite||busy||pending)return;
   const token=++epoch.current,expected=identity;
   setBusy(true);setAIPrompt(null);setAICopyNotice('');
   try{
     const value=await createPrivacySafeAIPrompt(sample,draft,suite);
     if(token===epoch.current&&currentRef.current===expected)
       setAIPrompt({key:expected,value});
   }catch{
     if(token===epoch.current&&currentRef.current===expected)
       setAIPrompt({key:expected,value:{ok:false,reason:'UNTRUSTED_PREVIEW'}});
   }finally{if(token===epoch.current)setBusy(false);}
 }
 async function copyAIPrompt(){
   if(!currentAIPrompt?.ok)return;
   try{await navigator.clipboard.writeText(currentAIPrompt.prompt);
     setAICopyNotice('Privacy-safe prompt copied by explicit user action.');}
   catch{setAICopyNotice('Clipboard access denied. Select and copy the visible prompt manually.');}
 }
 async function reviewAIImport(){
   if(!suite||busy||pending)return;
   const token=++epoch.current,expected=identity;
   setBusy(true);setAIImport(null);
   try{
     const value=await importReviewOnlyAIRecipe(aiText,sample,draft,suite);
     if(token===epoch.current&&currentRef.current===expected)
       setAIImport({key:expected,value});
   }catch{
     if(token===epoch.current&&currentRef.current===expected)
       setAIImport({key:expected,value:{ok:false,reason:'UNTRUSTED_RECIPE'}});
   }finally{if(token===epoch.current)setBusy(false);}
 }
 async function compareSimplePath(){
   if(!suite||busy||pending)return;
   const proposed=prepareBoundedPathCandidate(boundedPath,sample,draft,suite);
   if(!proposed.ok){setRepairNotice('Simple path cannot become a safe parser mapping: '+proposed.reason);return;}
   const token=++epoch.current,expected=identity,requestedHoldout=holdout;
   setBusy(true);setRepair(null);setRepairNotice('');
   try{
     if(!holdout||new TextEncoder().encode(holdout).byteLength>MAX_LOCAL_TEXT)
       throw new Error('HOLDOUT_REQUIRED');
     const candidate=await runPreview(proposed.candidate,sample);
     const held={source:holdout,baseline:await runPreview(draft,holdout),
       candidate:await runPreview(proposed.candidate,holdout)};
     if(token!==epoch.current||currentRef.current!==expected||holdout!==requestedHoldout)return;
     const comparison=compareCandidate({source:sample,baseline:suite,candidate,holdout:held});
     setRepair({key:JSON.stringify([expected,requestedHoldout]),
       candidate:proposed.candidate,comparison,
       source:proposed.source,target:proposed.target});
     setReviewMetrics(x=>({...x,compared:x.compared+1,
       blocked:x.blocked+Number(!comparison.acceptedWithoutRegression)}));
     setRepairNotice('Safe path field proposed in Full-sample regression; manual approval is still required.');
   }catch{
     if(token===epoch.current&&currentRef.current===expected)
       setRepairNotice('Simple path review needs an independent holdout. No rules changed.');
   }finally{if(token===epoch.current)setBusy(false);}
 }
 async function compareImportedAIMapping(){
   if(!currentAIImport||!suite||busy||pending)return;
   const proposed=proposeV01FieldMappingFromAI(currentAIImport,sample,draft,suite);
   if(!proposed.ok){setRepairNotice('Imported staged changes cannot be safely mapped to v0.1: '+proposed.reason);return;}
   const token=++epoch.current,expected=identity,requestedHoldout=holdout;
   setBusy(true);setRepair(null);setRepairNotice('');
   try{
     if(!holdout||new TextEncoder().encode(holdout).byteLength>MAX_LOCAL_TEXT)
       throw new Error('HOLDOUT_REQUIRED');
     const candidate=await runPreview(proposed.candidate,sample);
     const held={source:holdout,baseline:await runPreview(draft,holdout),
       candidate:await runPreview(proposed.candidate,holdout)};
     if(token!==epoch.current||currentRef.current!==expected||holdout!==requestedHoldout)return;
     const comparison=compareCandidate({source:sample,baseline:suite,candidate,holdout:held});
     setRepair({key:JSON.stringify([expected,requestedHoldout]),
       candidate:proposed.candidate,comparison,
       source:proposed.source,target:proposed.target});
     setReviewMetrics(x=>({...x,compared:x.compared+1,
       blocked:x.blocked+Number(!comparison.acceptedWithoutRegression)}));
     setRepairNotice('AI-proposed field is a reviewed candidate in Full-sample regression; approval remains a separate action.');
   }catch{
     if(token===epoch.current&&currentRef.current===expected)
       setRepairNotice('AI mapping comparison requires a valid independent holdout. No rules changed.');
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
       <details className="auto-parser-recipe" aria-label="Public synthetic parser fingerprints">
         <summary>Optional · Match familiar log patterns</summary>
         <p>Compare all event field names against reviewed public-synthetic starter shapes.
           Results are local hints only: no log values leave the browser, no template is
           automatically applied, and no native parser compatibility is implied.</p>
         <button type="button" disabled={busy||pending||!suite}
           onClick={findKnownTemplates}>Find Reviewed Pattern Hints</button>
         <button type="button" disabled={busy||pending||!suite}
           onClick={()=>{void mineUnknownShapes();}}>Group Unknown Text Locally</button>
         {currentStructural&&<div role="status" aria-label="Local structural hints">
           <strong>{currentStructural.unknownCount} unknown events ·
             {currentStructural.groupedCount} grouped · Browser worker only</strong>
           {currentStructural.groups.map((group,i)=><span key={i}>
             {group.count} events · {group.fingerprint} · REVIEW ONLY
           </span>)}
           <span>Structural hints are not regex expressions or native parsers.</span>
         </div>}
         {currentFingerprints&&<div role="status" aria-label="Reviewed pattern hints">
           <strong>{currentFingerprints.status} · {currentFingerprints.sourceCount} original events</strong>
           {currentFingerprints.hints.length===0&&
             <span>No safe single-family public-synthetic pattern was matched.</span>}
           {currentFingerprints.hints.map(hint=><span key={hint.id}>
             {hint.label}: {hint.matchedFieldCount}/{hint.expectedFieldCount} required fields
             consistently seen · Review only, not automatically applied
           </span>)}
         </div>}
       </details>
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
       <details className="auto-parser-recipe" aria-label="Whole-sample regression and holdout review">
         <summary>Review safe repair · Full-sample and holdout regression</summary>
         <p>Compare one suggested missing-field mapping against the entire original sample.
           Supply independent log events as holdout input to enable approval. Every
           event and field-shape change is audited locally. Nothing is auto-applied,
           stored, or sent to the backend.</p>
         <label>Independent holdout events (optional for comparison; required for approval)
           <textarea aria-label="Independent holdout logs" rows={4}
             value={holdout} onChange={e=>{setHoldout(e.target.value);setRepair(null);setRepairNotice('');}}
             placeholder="Paste fresh events not used to suggest fields; kept in browser memory." />
         </label>
         <button type="button" disabled={busy||pending||!suite}
           onClick={()=>{void compareRepair();}}>Compare One Safe Repair</button>
         {repairNotice&&<p role="status">{repairNotice}</p>}
         {currentRepair&&<div aria-label="Candidate regression comparison" role="status">
           <strong>Candidate only · Approval required · Native NOT VERIFIED</strong>
           <span>{currentRepair.source} → {currentRepair.target} (one proposed mapping)</span>
           <span>Original events: {currentRepair.comparison.baseline.accounted}/
             {currentRepair.comparison.baseline.sourceCount} accounted ·
             Previous passes: {currentRepair.comparison.baseline.positiveBefore} ·
             Candidate passes: {currentRepair.comparison.baseline.positiveAfter}</span>
           <span>Regressions: {currentRepair.comparison.baseline.regressions} ·
             Added field shapes: {currentRepair.comparison.baseline.fieldAdditions} ·
             Removed: {currentRepair.comparison.baseline.fieldRemovals} ·
             Type changes: {currentRepair.comparison.baseline.typeChanges}</span>
           <span>Holdout: {currentRepair.comparison.holdoutStatus} ·
             {currentRepair.comparison.holdout?.sourceCount??0} events ·
             {currentRepair.comparison.holdout?.regressions??0} regressions</span>
           {currentRepair.comparison.baseline.families.map(f=><span key={f.family}>
             {f.family}: {f.count} events · Passed {f.beforePassed} → {f.afterPassed}
           </span>)}
           {currentRepair.comparison.baseline.issues.map(i=><span key={i.reason}>
             {i.reason}: {i.count}
           </span>)}
           <label className="auto-parser-persist-label">
             <input type="checkbox" checked={saveAfterApproval}
               onChange={e=>setSaveAfterApproval(e.target.checked)}/>
             Also save approved mapping names/types to browser-local pattern library (no sample values)
           </label>
           <button type="button" disabled={busy||pending||
             !currentRepair.comparison.acceptedWithoutRegression||
             currentRepair.comparison.holdoutStatus!=='TESTED'}
             onClick={approveRepair}>

             Approve Reviewed Mapping
           </button>
           {currentRepair.comparison.holdoutStatus!=='TESTED'&&
             <p>Holdout NOT TESTED — approval requires new independent events.</p>}
           {!currentRepair.comparison.acceptedWithoutRegression&&
             <p>Regression detected — approval blocked. Previous passing events must not regress.</p>}
         </div>}
       </details>
       <details className="auto-parser-recipe" aria-label="Reusable approved mapping patterns">
         <summary>Optional · Reuse previously approved mapping</summary>
         <p>Only explicitly stored source/target names, types and anonymized
           regression counts are kept in this browser. Reuse requires the same
           source family, a new full-sample comparison and a fresh independent
           holdout. Nothing is silently applied or uploaded.</p>
         <label>Select browser-local reviewed mapping
           <select aria-label="Approved mapping pattern" value={selectedPattern}
             onChange={e=>setSelectedPattern(e.target.value)}>
             <option value="">Choose a saved mapping</option>
             {approvedPatterns.map(item=><option key={item.id} value={item.id}>
               {item.family}: {item.mapping.source} → {item.mapping.target}
             </option>)}
           </select>
         </label>
         <button type="button" disabled={!selectedPattern||busy||pending||!suite}
           onClick={()=>{void compareStoredPattern();}}>Compare Saved Pattern with Holdout</button>
         <button type="button" disabled={!selectedPattern||busy}
           onClick={()=>{
             if(!window.confirm('Forget the selected browser-local mapping signature? This does not change current parser rules.'))return;
             if(forgetApprovedPattern(selectedPattern)){
               setApprovedPatterns(readApprovedPatterns());setSelectedPattern('');
             }else setRepairNotice('Unable to remove the selected browser-local mapping.');
           }}>Forget Selected Saved Pattern</button>
         <span>{approvedPatterns.length} approved browser-local mapping signatures</span>
       </details>
       <div className="auto-parser-note" aria-label="Local review session metrics">
         Session-only review counts: {reviewMetrics.compared} compared ·
         {reviewMetrics.approved} user approved · {reviewMetrics.blocked} regression blocks.
         Not a measured human usability study; no telemetry or raw samples are sent.
       </div>
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
     <details className="auto-parser-recipe" aria-label="Optional privacy-safe AI recipe exchange">
       <summary>Optional · Copy AI Prompt / Paste Reviewed AI Recipe</summary>
       <p>Nothing is sent automatically to an LLM or external service. A generated
         prompt contains only event counts, source digest and detected format families,
         never raw log lines, addresses, usernames, or observed field values.
         Copy only if you choose to share this limited metadata externally.
         AI suggestions are untrusted review candidates, NOT runnable Ruby/Regex/JSONata.</p>
       <button type="button" disabled={busy||pending||!suite}
         onClick={()=>{void prepareAIPrompt();}}>Prepare Privacy-Safe AI Prompt</button>
       {currentAIPrompt&&(currentAIPrompt.ok
         ? <div aria-label="Privacy-safe AI prompt" role="status">
           <strong>SCHEMA-ONLY · No raw logs · No automatic upload</strong>
           {!currentAIPrompt.currentProjectImportReady&&<span>
             Current parser draft is not backend-compatible. The prompt requests
             plain-English review rather than a fabricated import-ready recipe.
           </span>}
           <textarea aria-label="Copyable AI prompt" readOnly rows={8}
             value={currentAIPrompt.prompt}/>
           <button type="button" onClick={()=>{void copyAIPrompt();}}>Copy Prompt Manually</button>
           {aiCopyNotice&&<span>{aiCopyNotice}</span>}
         </div>
         : <p role="status">Prompt unavailable: {currentAIPrompt.reason}</p>)}
       <label>Optional simple JSONata-compatible property path only (no functions or expressions)
         <input type="text" aria-label="Safe JSONata-style field path" maxLength={128}
           value={boundedPath} placeholder="$.event.user" onChange={e=>setBoundedPath(e.target.value)}/>
       </label>
       <button type="button" disabled={!boundedPath.trim()||busy||pending||!suite}
         onClick={()=>{void compareSimplePath();}}>Compare Safe Field Path with Holdout</button>
       <p>Only eight or fewer dot-separated property names are supported.
         No general JSONata, Regex or Ruby is executed. Full-sample comparison,
         independent holdout and explicit approval are required before use.</p>
       <label>Paste a v0.2 JSON recipe suggested by an external assistant (maximum 32 KiB)
         <textarea aria-label="Pasted AI review-only recipe" rows={5} spellCheck={false}
           maxLength={32768} value={aiText} onChange={e=>{
             setAIText(e.target.value);setAIImport(null);}}/>
       </label>
       <button type="button" disabled={!aiText.trim()||busy||pending||!suite}
         onClick={()=>{void reviewAIImport();}}>Validate AI Recipe for Review Only</button>
       {currentAIImport&&(currentAIImport.ok
         ? <div role="status" aria-label="Validated AI recipe review">
           <strong>REVIEW_ONLY · Explicit user approval required</strong>
           <span>{currentAIImport.report.sampleEvents} original events ·
             {currentAIImport.report.changedStageCount} changed stages ·
             {currentAIImport.report.addedMappings} new mappings ·
             {currentAIImport.report.removedMappings} removed mappings</span>
           <span>v0.2 backend compiler NOT AVAILABLE. No recipe imported into parser
             rules or sent to the backend. Review unsupported operations in Edit Details.</span>
           <button type="button" disabled={busy||pending||!suite}
             onClick={()=>{void compareImportedAIMapping();}}>
             Compare One Compatible AI Mapping with Holdout
           </button>
           <span>Only a single additive, compatible v0.1 field mapping can be
             considered; the independent holdout and user approval are required in
             Full-sample regression. Other AI stage changes remain review-only.</span>
         </div>
         : <p role="status">AI recipe rejected: {currentAIImport.reason}. No rules changed.</p>)}
     </details>
     {message&&<p role="alert" className="auto-parser-warning"><ShieldAlert size={16}/> {message}</p>}
   </div>
 </main>;
}
