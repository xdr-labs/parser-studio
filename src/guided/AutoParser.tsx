import {useEffect,useMemo,useRef,useState} from 'react';
import type {Dispatch,SetStateAction} from 'react';
import {ArrowLeft,ArrowRight,CheckCircle2,Download,FileArchive,FileText,
  LockKeyhole,ShieldAlert} from 'lucide-react';
import {createDraft,type ParserDraft,type SuiteResult} from '../model';
import {toBackendProject} from './backendAdapter';
import {fetchBackendCapabilities,assertBackendProjectSupported,
  type BackendCapabilities} from './backendCapabilities';
import {fetchBackendSchemaGuide} from './backendSchemaGuide';
import {validateBackendProject,generateBackendPair,type GeneratedPair} from './backendClient';
import {verifyGeneratedPair,packageGeneratedPair} from './artifactPackageClient';
import {analyzeLogEnvelopes,assessEnvelopeCompilation} from './autoParserEnvelope';
import {prepareAutoParserDraft} from './autoParserDraft';
import {buildReviewableRecipe,type RecipeReview} from './parserRecipeV2';
import {compileReviewedRecipeV02,type ReviewedRecipeCompilation} from './recipeV2BackendClient';
import {matchKnownParserFingerprints,type FingerprintMatchReport} from './knownParserFingerprints';
import type {StructuralMiningReport} from './localPatternMining';
import {checkPrivateDrain3Availability,runPrivateDrain3Review,
  type Drain3Availability,type Drain3Report} from './drain3OfflineClient';
import {splitEvents,MAX_EVENTS} from '../parser';
import {parseJavaStacktrace} from '../javaStacktrace';
import {defaultGuidedOptions} from './contract';
import {reviewLogicalBoundaries,type LogicalBoundaryReport} from './logicalBoundaryReview';


import ArtifactRevisionHistoryPanel from './ArtifactRevisionHistoryPanel';
import AutoParserAIReview from './AutoParserAIReview';
import {requestMultiPassPreview,type MultiPassSourcePreview} from './multipassPreviewClient';
import {buildMultiPassSourceHighlights,type MultiPassSourceSelection} from './multipassSourceHighlights';
import AutoParserResultTools from './AutoParserResultTools';
import type {ApprovedTestLabStatus} from './approvedTestLabSession';
import AutoParserLocalReplay from './AutoParserLocalReplay';
import {readApprovedPatterns,saveApprovedMapping,prepareApprovedPatternDraft,
  forgetApprovedPattern,type ApprovedPattern} from './approvedPatterns';

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
 activeSession:ApprovedTestLabStatus|null;
 onSessionUpdate:(next:ApprovedTestLabStatus|null)=>void;
 onChatGPT:()=>void;
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
 MIXED_OR_UNKNOWN:'The sample contains an unsupported family combination, malformed, or unrecognized events. Only explicitly allowed one-line JSON/KV/CEF/LEEF can share a parser; no log line will be discarded.',
 BOUNDARY_REVIEW:'The record boundaries are ambiguous. Review explicit event framing or use ChatGPT Assisted Parser.',
 COMPILER_UNSUPPORTED:'The backend cannot safely compile the detected envelope and body.',
 COLUMNS_REQUIRED:'CSV requires named columns; use ChatGPT Assisted Parser if the format cannot be recognized.',
 BACKEND_UNAVAILABLE:'The local backend capabilities are unavailable. No parser is generated.',
 BACKEND_UNTRUSTED:'The backend returned an untrusted capability or verification claim.',
 SOURCE_LIMIT:'The sample is empty or exceeds the safe 64 KiB / 500 event limit.',
 MODEL_REVIEW_REQUIRED:'Review the detected field mappings on this screen before generating.',
};
function statusMessage(reason:string){return readable[reason]??'Try the other supported method, ChatGPT Assisted Parser.';}
export default function AutoParser({
 draft,setDraft,sample,setSample,datasetName,setDatasetName,suite,pending,
 runPreview,activeSession,onSessionUpdate,onChatGPT,
}:Props){
 const [step,setStep]=useState<0|1|2>(0);
 const [selected,setSelected]=useState(0);
 const [multiPass,setMultiPass]=useState<{raw:string;result:MultiPassSourcePreview}|null>(null);
 const [multiPassNotice,setMultiPassNotice]=useState('');
 const [multiPassBusy,setMultiPassBusy]=useState(false);
 const [selectedMultiPass,setSelectedMultiPass]=useState<MultiPassSourceSelection|null>(null);
 const [busy,setBusy]=useState(false);
 const [message,setMessage]=useState('');
 const [reviewed,setReviewed]=useState<{source:string;mappingCount:number;requiresApproval:boolean}|null>(null);
 const [capability,setCapability]=useState<{source:string;value:BackendCapabilities}|null>(null);
 const [csvApprovedKey,setCsvApprovedKey]=useState('');
 // Review is revoked on every input edit, including edit-then-revert.
 // A prior confirmation must never authorize a newly changed source/schema.
 useEffect(()=>setCsvApprovedKey(''),[sample,draft.csvColumns,draft.csvDelimiter]);
 const [evidence,setEvidence]=useState<Evidence|null>(null);
 const [pair,setPair]=useState<Pair|null>(null);
 const [zip,setZip]=useState<Zip|null>(null);
 const [recipe,setRecipe]=useState<{key:string;value:RecipeReview}|null>(null);
 const [recipeCompiled,setRecipeCompiled]=useState<{key:string;value:ReviewedRecipeCompilation}|null>(null);
 const [recipeCompilerError,setRecipeCompilerError]=useState('');
 const [fingerprints,setFingerprints]=useState<{key:string;value:FingerprintMatchReport}|null>(null);
 const [structural,setStructural]=useState<{key:string;value:StructuralMiningReport}|null>(null);
 const [drainAvailability,setDrainAvailability]=useState<'UNCHECKED'|'ERROR'|Drain3Availability>('UNCHECKED');
 const [drainConsent,setDrainConsent]=useState(false);
 const [drainHoldout,setDrainHoldout]=useState('');
 const [drainResult,setDrainResult]=useState<{key:string;holdout:string;value:Drain3Report}|null>(null);
 const [drainNotice,setDrainNotice]=useState('');
 const [logicalReview,setLogicalReview]=useState<{key:string;value:LogicalBoundaryReport}|null>(null);
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
   setRecipeCompiled(null);setRecipeCompilerError('');
   setRepair(null);setRepairNotice('');setFingerprints(null);setStructural(null);
   setDrainAvailability('UNCHECKED');setDrainConsent(false);
   setDrainResult(null);setDrainNotice('');
   setLogicalReview(null);
   setSaveAfterApproval(false);
   setBusy(false);setMessage('');
 },[identity]);
 // A local suggestion only: explicit source-framing confirmation is required.
 // Never promote arbitrary newline grouping or silently rewrite edited mappings.
 const javaFramedCandidate=useMemo(()=>{
   if(draft.format!=='auto'||!sample.includes('\n\n')||
      sample.includes('\r')||
      new TextEncoder().encode(sample).byteLength>MAX_LOCAL_TEXT||
      JSON.stringify(draft.mappings)!==JSON.stringify(createDraft().mappings)||
      draft.guided?.receiver.framing!=='newline'||
      (draft.guided?.eventBoundary??'single-line')!=='single-line')
     return false;
   const records=splitEvents(sample,'blank-line',MAX_EVENTS+1);
   return records.length>=2&&records.length<=MAX_EVENTS&&
     records.every(r=>parseJavaStacktrace(r.raw).errors.length===0);
 },[sample,draft]);
 const adoptFramedJava=()=>{
   if(!javaFramedCandidate)return;
   setDraft(old=>{
     if(old.format!=='auto'||!javaFramedCandidate)return old;
     const opts=old.guided??defaultGuidedOptions();
     return {...old,format:'java_stacktrace',
       mappings:[
         {id:'java-class',source:'exception_class',target:'custom.exception_class',type:'string'},
         {id:'java-count',source:'frame_count',target:'custom.frame_count',type:'integer'},
         {id:'java-cause',source:'cause_class',target:'custom.cause_class',type:'string'},
       ],
       guided:{...opts,eventBoundary:'blank-line',enrichment:[],
         groups:{'java-class':'top_fields','java-count':'top_fields',
           'java-cause':'ns_fields'},
         classification:{defaultIndex:'Syslog',rules:[]},
         receiver:{...opts.receiver,protocols:['tcp'],framing:'blank_line_java'}
       }
     };
   });
 };
 const csvFound=report.families.some(f=>f.envelope==='none'&&f.body==='csv');
 const csvSchemaKey=JSON.stringify([sample,draft.csvColumns,draft.csvDelimiter]);
 const csvApproved=!csvFound||csvApprovedKey===csvSchemaKey;
 const csvColumns=draft.csvColumns.split(',').map(x=>x.trim());
 const csvNamesValid=csvColumns.length>=2&&csvColumns.length<=100&&
   csvColumns.every(x=>/^[A-Za-z][A-Za-z0-9_]{0,63}$/.test(x))&&
   new Set(csvColumns).size===csvColumns.length&&
   [',',';','\t'].includes(draft.csvDelimiter??'INVALID');
 const localAssessment=assessEnvelopeCompilation(report,
   capability?.source===sample?capability.value:null);
 const assessment=csvFound&&csvApproved&&report.families.length===1&&
   report.families[0]?.body==='csv'&&
   localAssessment.status==='COLUMNS_REQUIRED'&&
   capability?.source===sample&&
   capability.value.authoring.extractionFormats.includes('csv')?{
     status:'DRAFT_COMPILABLE' as const,format:'csv' as const,bodyFormat:null,
     nativeVerified:false as const,targetVerified:false as const,
   }:localAssessment;
 const currentReview=reviewed?.source===sample?reviewed:null;
 const currentPair=pair?.key===identity?pair.value:null;
 const currentEvidence=evidence?.key===identity?evidence:null;
 const currentZip=zip?.key===identity?zip:null;
 const currentRecipe=recipe?.key===identity?recipe.value:null;
 const currentRecipeCompiled=recipeCompiled?.key===identity?recipeCompiled.value:null;
 const currentFingerprints=fingerprints?.key===identity?fingerprints.value:null;
 const currentStructural=structural?.key===identity?structural.value:null;
 const currentDrain=drainResult?.key===identity&&
   drainResult.holdout===drainHoldout?drainResult.value:null;
 const currentLogicalReview=logicalReview?.key===identity?logicalReview.value:null;
 const repairKey=JSON.stringify([identity,holdout]);
 const currentRepair=repair?.key===repairKey?repair:null;
 const records=suite?.events??[];
 const chosen=records[selected]??records[0];
 const canReview=Boolean(sample.trim())&&!pending&&!!suite&&
   report.complete&&report.sourceCount>0&&!busy&&csvApproved;
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
     const baseline=assessEnvelopeCompilation(report,cap);
     const compiler=csvFound&&csvApproved&&report.families.length===1&&
       baseline.status==='COLUMNS_REQUIRED'&&cap.authoring.extractionFormats.includes('csv')?
       {status:'DRAFT_COMPILABLE' as const,format:'csv' as const,
        bodyFormat:null,nativeVerified:false as const,targetVerified:false as const}:
       baseline;
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
 async function probeDrain3(){
   if(busy||pending)return;
   const token=++epoch.current,expected=identity;
   setBusy(true);setDrainNotice('');setDrainResult(null);
   try{
     const availability=await checkPrivateDrain3Availability();
     if(token===epoch.current&&currentRef.current===expected){
       setDrainAvailability(availability);setDrainConsent(false);
     }
   }catch{
     if(token===epoch.current&&currentRef.current===expected){
       setDrainAvailability('ERROR');
       setDrainNotice('The private offline miner capability could not be verified.');
     }
   }finally{if(token===epoch.current)setBusy(false);}
 }
 async function runApprovedDrain3(){
   if(drainAvailability!=='AVAILABLE'||!drainConsent||busy||pending||!suite)return;
   const expected=identity,requestedHoldout=drainHoldout;
   const records=splitEvents(sample,'single-line',MAX_EVENTS+1);
   const hold=drainHoldout.trim()?splitEvents(drainHoldout,'single-line',MAX_EVENTS+1):[];
   if(!records.length||records.length>MAX_EVENTS||hold.length>MAX_EVENTS||
     records.some((entry,i)=>entry.raw!==suite.events[i]?.raw||
       entry.line!==suite.events[i]?.line)||
     suite.counts.total!==records.length){
     setDrainNotice('Original browser source accounting is not current; run local review again.');
     return;
   }
   const token=++epoch.current;
   setBusy(true);setDrainResult(null);setDrainNotice('');
   try{
     const result=await runPrivateDrain3Review(
       records.map(item=>item.raw),hold.map(item=>item.raw),true);
     if(token===epoch.current&&currentRef.current===expected&&
       drainHoldout===requestedHoldout)
       setDrainResult({key:expected,holdout:requestedHoldout,value:result});
   }catch{
     if(token===epoch.current&&currentRef.current===expected)
       setDrainNotice('Private Drain3 request rejected or unavailable. No mapping changed.');
   }finally{if(token===epoch.current)setBusy(false);}
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
 async function previewRecipe(){
   if(!suite||busy||pending)return;
   const token=++epoch.current,expected=identity;
   setBusy(true);setRecipe(null);setRecipeCompiled(null);setRecipeCompilerError('');
   try{
     const result=await buildReviewableRecipe(sample,draft,suite);
     if(token===epoch.current&&currentRef.current===expected)
       setRecipe({key:expected,value:result});
   }catch{
     if(token===epoch.current&&currentRef.current===expected)
       setRecipe({key:expected,value:{ok:false,reason:'UNTRUSTED_PREVIEW'}});
   }finally{if(token===epoch.current)setBusy(false);}
 }
 async function compileReviewedRecipe(){
   if(!currentRecipe||!currentRecipe.ok||!currentPair||busy||pending)return;
   const token=++epoch.current,expected=identity;
   setBusy(true);setRecipeCompiled(null);setRecipeCompilerError('');
   try{
     const result=await compileReviewedRecipeV02({
       recipe:currentRecipe.recipe,legacyProject:currentRecipe.legacyProject,
     },currentPair);
     if(token===epoch.current&&currentRef.current===expected)
       setRecipeCompiled({key:expected,value:result});
   }catch{
     if(token===epoch.current&&currentRef.current===expected)
       setRecipeCompilerError('The backend could not verify the strict v0.2 stages against the current DRAFT pair. The original v0.1 files remain available.');
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
 async function previewMultiPass(){
  if(!sample.trim()||multiPassBusy)return;
  const original=sample;setMultiPass(null);setSelectedMultiPass(null);setMultiPassNotice('');setMultiPassBusy(true);
  try{
   const result=await requestMultiPassPreview(original);
   setMultiPass({raw:original,result});
  }catch{setMultiPassNotice('Local Multi-Pass service unavailable or untrusted. Browser preview remains separate.');}
  finally{setMultiPassBusy(false);}
 }
 const currentMultiPass=multiPass?.raw===sample?multiPass.result:null;
 const currentMultiPassHighlights=currentMultiPass?buildMultiPassSourceHighlights(sample,currentMultiPass):null;
 return <main className="auto-parser-workspace" aria-label="Auto Parser v2">
   <header className="auto-parser-intro">
     <span className="pane-index">AUTO PARSER 2.0 · LOCAL FIRST</span>
     <h1>From raw logs to a parser draft in three steps.</h1>
     <p>Paste samples without selecting JSON, CEF, Regex or Ruby. Review every
       recognized event and optional field mapping before creating matched DRAFT files.</p>
     <div className="auto-parser-links">
       <button type="button" onClick={onChatGPT}>Try ChatGPT Assisted Parser</button>
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
       <p>Paste or upload representative events. Most sources use one line
         per event; strictly framed Java exceptions can be reviewed as complete
         multiline records. Your sample stays in this browser.</p>
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
       <div className="stellar-multipass-panel" aria-label="Local Multi-Pass source engine">
         <button type="button" disabled={!sample.trim()||multiPassBusy} onClick={()=>void previewMultiPass()}>
           {multiPassBusy?'Running local Multi-Pass…':'Run Local Multi-Pass Source Preview'}
         </button>
         <small>Explicit local request only · Source extraction, not native Ruby/CONF verification</small>
         {multiPassNotice&&<p role="status">{multiPassNotice}</p>}
         {currentMultiPass&&<div role="status">
           <strong>{currentMultiPass.status} · {currentMultiPass.syntax}</strong>
           <p>Extracted fields and source byte spans are shown below. Residuals remain available for AI correction.</p>
           <pre>{JSON.stringify(currentMultiPass.fields,null,2)}</pre>
           {currentMultiPassHighlights?.ok&&<div className="stellar-source-map" aria-label="Multi-Pass source highlights">
             {currentMultiPassHighlights.segments.map((segment,i)=>segment.kind==='plain'?
               <span key={i}>{segment.text}</span>:
               <button type="button" key={i}
                 className={'stellar-source-segment '+segment.kind+(selectedMultiPass?.startByte===segment.selection.startByte&&selectedMultiPass.endByte===segment.selection.endByte?' selected':'')}
                 aria-label={segment.kind==='field'?`Correct extracted field ${segment.selection.path} bytes ${segment.selection.startByte}-${segment.selection.endByte}`:`Improve unparsed bytes ${segment.selection.startByte}-${segment.selection.endByte}`}
                 onClick={()=>setSelectedMultiPass(segment.selection)}>{segment.text}</button>)}</div>}
           {currentMultiPassHighlights&&!currentMultiPassHighlights.ok&&<p className="auto-parser-warning">
             Exact source highlighting is unavailable because the engine returned ambiguous byte ranges. No source selection was accepted.</p>}
           <div className="stellar-span-actions">{currentMultiPass.spans.map((span,i)=><button type="button" key={'f'+i} className="stellar-span-chip"
             onClick={()=>{const item=currentMultiPassHighlights?.ok?currentMultiPassHighlights.selectable.find(x=>x.kind==='field'&&x.path===span.path&&x.startByte===span.startByte&&x.endByte===span.endByte):undefined;if(item)setSelectedMultiPass(item);}}>
             Correct {span.path} [{span.startByte}–{span.endByte}]</button>)}</div>
           <div className="stellar-span-actions">{currentMultiPass.residuals.map((span,i)=><button type="button" key={'r'+i}
             className="stellar-residual-chip" onClick={()=>{const item=currentMultiPassHighlights?.ok?currentMultiPassHighlights.selectable.find(x=>x.kind==='residual'&&x.startByte===span.startByte&&x.endByte===span.endByte):undefined;if(item)setSelectedMultiPass(item);}}>
             Improve Unparsed [{span.startByte}–{span.endByte}]</button>)}</div>
           {selectedMultiPass&&currentMultiPass.status!=='RAW_ONLY'&&<div className="stellar-selected-source" role="status">
             {selectedMultiPass.kind==='field'?`Selected extracted field: ${selectedMultiPass.path}`:'Selected unparsed source region'} · UTF-8 bytes {selectedMultiPass.startByte}–{selectedMultiPass.endByte}
           </div>}
           {selectedMultiPass&&currentMultiPass.status!=='RAW_ONLY'&&<AutoParserAIReview raw={sample} status="partial" onChatGPT={onChatGPT}
             initialByteRange={selectedMultiPass} selectionContext={{kind:selectedMultiPass.kind,path:selectedMultiPass.path}}
             source={sample} draft={draft} suite={suite} onApplyCandidate={setDraft}/>}
           {currentMultiPass.status==='RAW_ONLY'&&<AutoParserAIReview raw={sample} status="unsupported" onChatGPT={onChatGPT}
             source={sample} draft={draft} suite={suite} onApplyCandidate={setDraft}/>}

         </div>}
       </div>
       <div className="auto-parser-ledger" aria-label="Automatic event accounting">
         <strong>{report.accounted}/{report.sourceCount} events analyzed locally</strong>
         <span>{report.unsupported} require review · Native parser NOT VERIFIED</span>
         {report.families.map(x=><span key={x.envelope+'/'+x.body}>
           {x.envelope==='none'?'Standalone':x.envelope.toUpperCase()} / {x.body.toUpperCase()}
           {' · '}{x.count}</span>)}
       </div>
       {csvFound&&<div className="auto-parser-recipe" aria-label="Review CSV column names">
         <strong>CSV rows detected — confirm each column name</strong>
         <p>CSV rows do not contain field names. Name the columns in the
           order they appear in a CSV row, and choose its data separator.
           Parser Studio will test every row before generating files.</p>
         <label>Column names, separated by commas
           <input aria-label="Reviewed CSV column names" value={draft.csvColumns}
             maxLength={4096}
             onChange={e=>setDraft(old=>({...old,csvColumns:e.target.value}))}/>
         </label>
         <label>Separator in your CSV rows
           <select aria-label="Reviewed CSV data separator"
             value={draft.csvDelimiter??','}
             onChange={e=>setDraft(old=>({...old,
               csvDelimiter:e.target.value as ','|';'|'\t'}))}>
             <option value=",">Comma (,)</option>
             <option value=";">Semicolon (;)</option>
             <option value={'\t'}>Tab</option>
           </select>
         </label>
         <button type="button" disabled={!csvNamesValid||pending}
           onClick={()=>setCsvApprovedKey(csvSchemaKey)}>
           I Confirm These CSV Column Names
         </button>
         <p role="status">{csvApproved?
           'CSV field names reviewed. Automatic parser testing is ready.':
           'Review required: CSV names and separator must be confirmed before analysis.'}</p>
       </div>}
       {javaFramedCandidate&&<div className="auto-parser-warning"
         aria-label="Explicit Java TCP framing confirmation">
         <strong>Java exception stack traces detected locally</strong>
         <p>Only supported when the sender transmits complete bounded Java
           exceptions via TCP, each followed by LF LF (an empty line).
           This is not automatic stream reassembly. Confirm the transport
           contract before generating a DRAFT parser.</p>
         <button type="button" onClick={adoptFramedJava}>
           I Confirm TCP Java Events Are Separated by LF LF
         </button>
       </div>}
       {sample.trim()&&report.unsupported>0&&<div className="stellar-ai-unrecognized" aria-label="Unsupported log AI fallback">
         <strong>Some source events need assistance</strong>
         <p>{report.unsupported} of {report.sourceCount} events were not fully recognized. The original input is preserved; unsupported events are not silently discarded or marked parser-ready.</p>
         <AutoParserAIReview raw={sample} status="unsupported" onChatGPT={onChatGPT} source={sample} draft={draft} suite={suite}/>
       </div>}
       <p className="auto-parser-note">Unknown, malformed, unsupported RFC3164 variants and multiline events
         cannot be silently dropped or marked compiler-ready.</p>
       <details className="auto-parser-recipe" aria-label="Local logical boundary review">
         <summary>Optional · Review multiline log boundaries (browser only)</summary>
         <p>Preview potential multiline JSON objects and Java stack traces using
           physical source line numbers. Every nonempty line is accounted for;
           no observed log values, stack frames or JSON fields are returned.
           This review alone does not configure a Fluentd multiline event
           breaker, change input or enable native parser generation.
           Only the separate explicitly confirmed TCP LF LF Java subset can
           create a reviewed Native-capable DRAFT parser.</p>
         <button type="button" disabled={!sample.trim()||busy||pending}
           onClick={()=>setLogicalReview({
             key:identity,value:reviewLogicalBoundaries(sample)
           })}>Review Logical Event Boundaries</button>
         {currentLogicalReview&&<div role="status" aria-label="Reviewed logical boundaries">
           <strong>{currentLogicalReview.status} ·
             {currentLogicalReview.accountedNonEmptyLines}/{currentLogicalReview.nonEmptyLines}
             nonempty physical lines accounted</strong>
           <span>{currentLogicalReview.multilineEventCount} candidate multiline events ·
             {currentLogicalReview.ambiguousCount} unresolved boundaries ·
             Native and DP target NOT VERIFIED</span>
           {currentLogicalReview.groups.slice(0,12).map((group,i)=><span key={i}>
             Lines {group.firstLine}–{group.lastLine} ·
             {group.kind} · {group.status}
           </span>)}
           {currentLogicalReview.groups.length>12&&<span>
             {currentLogicalReview.groups.length-12} further local groups,
             included in source accounting
           </span>}
           {currentLogicalReview.status!=='NO_MULTILINE'&&<span>
             Logical boundary analysis alone cannot qualify a native parser.
             Only separately reviewed TCP LF LF Java or JSON source framing
             can be compiled into a DRAFT parser.
           </span>}
         </div>}
       </details>
       <details className="auto-parser-recipe" aria-label="Optional isolated Drain3 mining">
         <summary>Optional · Real Drain3 pattern mining (private backend)</summary>
         <p>Unlike the browser-only structural hints, this optional feature transfers
           your selected raw training and holdout records to a separately authenticated,
           same-origin private Parser Studio backend. No external LLM, vendor service,
           automatic parser edit, storage or DP deployment is involved.
           You must separately confirm consent. Review the source before sending.</p>
         <button type="button" disabled={busy||pending}
           onClick={()=>{void probeDrain3();}}>
           Check Private Drain3 Availability (No Sample Transfer)
         </button>
         {drainAvailability==='DISABLED'&&<p role="status">
           Private Drain3 is disabled or not authorized. Browser-only structural hints
           remain available without raw log transfer.
         </p>}
         {drainAvailability==='ERROR'&&<p role="status">
           The private backend returned an unverified Drain3 capability.
         </p>}
         {drainAvailability==='AVAILABLE'&&<>
           <label className="auto-parser-persist-label">
             <input type="checkbox" checked={drainConsent}
               onChange={e=>{
                 setDrainConsent(e.target.checked);
                 setDrainResult(null);setDrainNotice('');
               }}/>
             I explicitly approve sending my current raw log sample and optional
             holdout to this private same-origin backend for one-time Drain3 analysis.
           </label>
           <label>Optional independent holdout log lines (not used for training)
             <textarea aria-label="Drain3 independent holdout logs" rows={3}
               spellCheck={false} maxLength={MAX_LOCAL_TEXT}
               value={drainHoldout}
               onChange={e=>{
                 setDrainHoldout(e.target.value);setDrainResult(null);
                 setDrainNotice('');
               }}/>
           </label>
           <button type="button" disabled={!drainConsent||busy||pending||
             !sample.trim()||!suite}
             onClick={()=>{void runApprovedDrain3();}}>
             Analyze with Approved Private Drain3
           </button>
         </>}
         {drainNotice&&<p role="status">{drainNotice}</p>}
         {currentDrain&&<div role="status" aria-label="Verified private Drain3 review">
           <strong>{currentDrain.engine} · REVIEW ONLY ·
             {currentDrain.accounted}/{currentDrain.sourceCount} events accounted</strong>
           <span>{currentDrain.groupCount} clusters ·
             {currentDrain.holdoutMatched}/{currentDrain.holdoutCount} independent
             holdout records matched (user-selected, independence not verified)</span>
           {currentDrain.groups.map(group=><span key={group.clusterId}>
             {group.clusterId}: {group.shape} ·
             {group.trainingCount} training records ·
             {group.holdoutMatches} holdout matches
           </span>)}
           <span>No raw fields returned · No native parser or DP target verification</span>
         </div>}
       </details>
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
       {report.events.some(event=>event.timePolicy==='YEAR_AND_ZONE_UNKNOWN')&&
         <p className="auto-parser-warning" role="note">
           RFC3164 header has no year or timezone. It is preserved as text;
           no event timestamp is inferred. Review the actual source time
           before mapping any event-time field.
         </p>}
       {!!currentReview?.mappingCount&&<p className="auto-parser-note">
         {currentReview.mappingCount} conservative custom-field suggestions were prepared
         from safe source names. They are not an official Stellar dictionary.</p>}
       {currentReview?.requiresApproval&&<p className="auto-parser-note">
         Your edited field mappings were preserved. Check them below before generating.</p>}
       <label>Choose a source event
         <select aria-label="Auto Parser review event" value={chosen?.id??''}
           onChange={e=>setSelected(Math.max(0,records.findIndex(x=>x.id===e.target.value)))}>
           {records.map((entry)=><option key={entry.id} value={entry.id}>
             Event {entry.line} · {entry.status.toUpperCase()}</option>)}
         </select></label>
       <div className="stellar-review-columns">
       {chosen&&<div className="auto-parser-preview" aria-label="Browser-only event inspector">
         <div><h3>Original · Browser only</h3><pre>{chosen.raw}</pre></div>
         <div><h3>Extracted</h3><pre>{JSON.stringify(chosen.fields,null,2)}</pre></div>
         <div><h3>Normalized · Browser only</h3><pre>{JSON.stringify(chosen.normalized,null,2)}</pre></div>
       </div>}
       {chosen&&suite&&!pending?<AutoParserAIReview raw={chosen.raw} status={chosen.status} onChatGPT={onChatGPT} source={sample} draft={draft} suite={suite} onApplyCandidate={setDraft}/>:
        <div className="stellar-ai-review" role="status" aria-label="Improve with AI preview status">
          <h3>Improve with AI</h3><p>Refreshing the current browser preview before AI correction can be reviewed.</p>
        </div>}
       </div>
       <div className="auto-parser-map-list" aria-label="Suggested field mappings">
         {draft.mappings.map((rule)=><div key={rule.id}>
           <strong>{rule.source}</strong> <ArrowRight size={13}/>
           <span>{rule.target}</span><small>{rule.type} · User-custom field, not official catalog</small>
         </div>)}
       </div>
       <details className="auto-parser-recipe" aria-label="Adjust detected field mapping">
         <summary>Need to change a field? Review mappings here</summary>
         <p>Only supported, reviewable field names and data types can generate parser files.
           Changing a mapping clears generated evidence until you test again.</p>
         {draft.mappings.map((mapping,index)=><div className="two-path-mapping-editor" key={mapping.id}>
           <label>Source field
             <input aria-label={'Mapping source '+index} value={mapping.source} maxLength={128}
               onChange={e=>setDraft(old=>({...old,mappings:old.mappings.map(m=>m.id===mapping.id?
                 {...m,source:e.target.value}:m)}))}/>
           </label>
           <label>Output field
             <input aria-label={'Mapping target '+index} value={mapping.target} maxLength={128}
               onChange={e=>setDraft(old=>({...old,mappings:old.mappings.map(m=>m.id===mapping.id?
                 {...m,target:e.target.value}:m)}))}/>
           </label>
           <label>Data type
             <select aria-label={'Mapping type '+index} value={mapping.type}
               onChange={e=>setDraft(old=>({...old,mappings:old.mappings.map(m=>m.id===mapping.id?
                 {...m,type:e.target.value as typeof m.type}:m)}))}>
               {(['string','integer','boolean','ip','port','timestamp'] as const)
                 .map(type=><option key={type} value={type}>{type}</option>)}
             </select>
           </label>
         </div>)}
       </details>
       <div className="auto-parser-actions">
         <button type="button" onClick={()=>setStep(0)}><ArrowLeft size={15}/> Back to Logs</button>
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
         Not all sample events passed. Review detected fields and mappings above
         before generating your parser.</p>}
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
         <strong><CheckCircle2 size={17}/> Two DRAFT files verified for SHA-256 integrity · Native NOT VERIFIED</strong>
         {currentPair.files.map(file=><button key={file.name} type="button"
           onClick={()=>download(file.name,file.content)}>
           <FileText size={15}/>{file.name} <Download size={15}/>
         </button>)}
         <button type="button" disabled={busy}
           onClick={()=>{void zipPair();}}><FileArchive size={16}/> Download Verified DRAFT ZIP</button>
         {currentZip&&<small>ZIP SHA-256: {currentZip.sha256} · {currentZip.filename}</small>}
       </div>}
       {currentPair&&<ArtifactRevisionHistoryPanel
         projectId={currentPair.manifest.projectId}
         draftKey={identity}
         pair={currentPair}
         listenerPort={draft.guided?.receiver.port??null}
         onDownload={(filename,bytes)=>download(filename,bytes,true)}
       />}
       {currentPair&&<AutoParserLocalReplay sample={sample} draft={draft}/>}
       {currentPair&&<AutoParserResultTools
         projectId={currentPair.manifest.projectId??''}
         listenerPort={draft.guided?.receiver.port??0}
         sourceFormat={draft.format}
         activeSession={activeSession} onSessionUpdate={onSessionUpdate}
       />}
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
         <summary>Advanced · Review and validate ParserRecipe v0.2 stages</summary>
         <p>Review is local-only. On explicit request, a supporting backend can
           validate these allowlisted stages against the unchanged ParserProject
           v0.1 and prove that both generated DRAFT file hashes are identical.
           Native user-parser or Stellar target compatibility is NOT VERIFIED.
           Unknown operators, unsupported RFC3164 variants, mixed formats and multiline remain unsupported.</p>
         <button type="button" disabled={busy||pending||!suite}
           onClick={()=>{void previewRecipe();}}>Review Staged Recipe</button>
         {currentRecipe&&(currentRecipe.ok
           ? <div role="status" aria-label="Review-only staged recipe">
             <strong>REVIEW_ONLY · Native and target NOT VERIFIED</strong>
             <span>{currentRecipe.recipe.stages.length} allowlisted stages ·
               {currentRecipe.recipe.sample.events} events ·
               Source SHA-256 {currentRecipe.recipe.sample.sha256.slice(0,12)}…</span>
             <span>v0.1 snapshot: {currentRecipe.lossReport.status} ·
               v0.2 restricted compilation needs backend capability verification</span>
             <p>{currentRecipe.recipe.stages.map(stage=>stage.op).join(' → ')}</p>
             <button type="button" disabled={!currentPair||busy||pending}
               onClick={()=>{void compileReviewedRecipe();}}>
               Validate and Compile Strict v0.2 DRAFT Pair
             </button>
             {!currentPair&&<span>First generate the v0.1 DRAFT pair to compare exact hashes.</span>}
           </div>
           : <p role="status">Review cannot be generated safely: {statusMessage(currentRecipe.reason)}</p>)}
         {recipeCompilerError&&<p role="status">{recipeCompilerError}</p>}
         {currentRecipeCompiled&&<div role="status" aria-label="v0.2 exact compiler evidence">
           <strong>v0.2 STRICT COMPILER PASS · v0.1 pair SHA MATCHED</strong>
           <span>Stages: {currentRecipeCompiled.receipt.stageCount} ·
             Events claimed: {currentRecipeCompiled.receipt.sampleEventCount} ·
             Recipe SHA-256 {currentRecipeCompiled.receipt.recipeSha256.slice(0,16)}…</span>
           <span>Native user parser NOT VERIFIED · Source hash is not independently
             checked by the backend · Stellar DP import NOT VERIFIED</span>
         </div>}
       </details>
       <p className="auto-parser-note"><LockKeyhole size={14}/> No API key, DP install or sensor send.
         Native Fluentd compatibility and real Stellar Cyber import remain unverified.</p>
       <div className="auto-parser-actions">
         <button type="button" onClick={()=>setStep(1)}><ArrowLeft size={14}/> Review Results</button>
         <button type="button" onClick={onChatGPT}>Ask ChatGPT for Unfamiliar Logs</button>
       </div>
     </section>}
     {message&&<p role="alert" className="auto-parser-warning"><ShieldAlert size={16}/> {message}</p>}
   </div>
 </main>;
}
