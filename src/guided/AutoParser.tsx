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
import {selectDraftFormat} from './draftFormatTransition';
import {buildReviewableRecipe,type RecipeReview} from './parserRecipeV2';
import {compileReviewedRecipeV02,type ReviewedRecipeCompilation} from './recipeV2BackendClient';
import {checkNativeProjectVerificationAvailability,verifyNativeProject,
  NativeProjectVerificationUnavailable,type NativeProjectVerificationReport}
  from './nativeProjectVerificationClient';
import {matchKnownParserFingerprints,type FingerprintMatchReport} from './knownParserFingerprints';
import {materializeStructuralGroupSource,type StructuralHint,type StructuralMiningReport} from './localPatternMining';
import NormalizationMappingReview from './NormalizationMappingReview';
import {HelpTip,StageGuide} from './BeginnerHelp';
import {checkPrivateDrain3Availability,runPrivateDrain3Review,
  type Drain3Availability,type Drain3Report} from './drain3OfflineClient';
import {inferConsistentCsvColumnCount,inspectCsvColumnShapes,splitEvents,MAX_EVENTS} from '../parser';
import {parseJavaStacktrace} from '../javaStacktrace';
import {defaultGuidedOptions,DEFAULT_PARSER_LISTENER_PORT} from './contract';
import {reviewLogicalBoundaries,type LogicalBoundaryReport} from './logicalBoundaryReview';
import {buildSourceReviewedGenericStructuralDraft} from './genericStructuralAutoDraft';
import {parserIdentitySlug} from './parserIdentity';
import {inspectZeekReview} from './zeekReview';


import AutoParserAIReview from './AutoParserAIReview';
import {requestMultiPassBatchPreview,requestMultiPassPreview,type MultiPassSourcePreview} from './multipassPreviewClient';
import {buildMultiPassSourceHighlights,type MultiPassSourceSelection} from './multipassSourceHighlights';
import AutoParserLocalReplay from './AutoParserLocalReplay';
import PythonTestSenderPanel from './PythonTestSenderPanel';
import ManualSourceBoundaryReview from './ManualSourceBoundaryReview';
import SampleUnionReview from './SampleUnionReview';
import ReviewedEventProfilesPanel from './ReviewedEventProfilesPanel';
import NamedLogTypesPanel from './NamedLogTypesPanel';
import NamedLogTypeReview from './NamedLogTypeReview';
import {analyzeNamedLogs,validateNamedLogs,type NamedLogType} from './namedLogTypes';
import {originalContainerCompilerGate} from './sourceContainerCompilerGate';
import DeclaredRelayProfilePanel from './DeclaredRelayProfilePanel';
import ExistingParserReviewPanel from './ExistingParserReviewPanel';
import BeginnerAnalysisPanel from './BeginnerAnalysisPanel';
import AnalysisProgressPanel from './AnalysisProgressPanel';
import {useAnalysisRun} from './useAnalysisRun';
import {readApprovedPatterns,saveApprovedMapping,prepareApprovedPatternDraft,
  forgetApprovedPattern,type ApprovedPattern} from './approvedPatterns';

import {proposeReviewableMapping,compareCandidate,
 type CandidateComparison} from './autoParserRegression';
import type {EventBoundary} from './contract';

interface Props {
 draft:ParserDraft;
 setDraft:Dispatch<SetStateAction<ParserDraft>>;
 sample:string;setSample:(text:string)=>void;
 namedLogTypes:NamedLogType[]|null;
 onEnableNamedLogTypes:()=>void;
 onChangeNamedLogTypes:(groups:NamedLogType[])=>void;
 onExitNamedLogTypes:()=>void;
 datasetName:string;setDatasetName:(name:string)=>void;
 suite?:SuiteResult;pending:boolean;
 runPreview:(candidate:ParserDraft,raw?:string)=>Promise<SuiteResult>;
 onChatGPT:()=>void;
 advanced:boolean;
}
const MAX_LOCAL_TEXT=64*1024;
const STEPS=['Add Logs','Review Fields','Map Fields','Create Parser'] as const;
const STEP_HELP=[
  'Paste or upload representative logs, then let Parser Studio find the structure and fields.',
  'Check that Parser Studio found the values you expect. You do not need to understand parser syntax.',
  'Match the fields that were found to Stellar Cyber field names. High-confidence matches can be applied together.',
  'Test every sample again and create downloadable parser files. Nothing is deployed automatically.',
] as const;
type Evidence={key:string;status:'PASS'|'FAILED';total:number;issues:string[]};
type Pair={key:string;value:GeneratedPair};
type Zip={key:string;filename:string;sha256:string};
type ParserSetOrigin={
 source:string;datasetName:string;sourceCount:number;draft:ParserDraft;
 fingerprint:string;groupCount:number;groupSource:string;
};
type NativeEvidence={key:string;status:'PASS'|'UNAVAILABLE'|'FAILED';
 report?:NativeProjectVerificationReport;message:string};
type MultiPassReview={raw:string;events:Array<{startByte:number;endByte:number;preview:MultiPassSourcePreview}>;metadataLines?:number;transportFramingParts?:number};
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
 COMPILER_UNSUPPORTED:'Parser Studio can read this log, but it cannot safely create parser files for this structure yet. Review the detected fields or use ChatGPT Assisted Parser.',
 ORIGINAL_CONTAINER_NOT_IN_DRAFT_COMPILER:'These original stream or container boundaries are available for source inspection, but the downloadable parser does not yet support this exact transport format. Your original logs were preserved. Review them or use ChatGPT Assisted Parser.',
 COLUMNS_REQUIRED:'This log has positional values without verified column names. Enter names from the product log definition for an eligible CSV stream, or use ChatGPT Assisted Parser for wrapped or mixed formats. The source fields remain intact.',
 BACKEND_UNAVAILABLE:'The local parser creation service is not available. Your analyzed fields are preserved; try again after the service is running.',
 BACKEND_UNTRUSTED:'Parser Studio cannot trust the response from the local parser creation service. No parser files were created.',
 BACKEND_PROFILE_UNSUPPORTED:'The connected parser creation service does not support this draft\'s log structure yet. Update or restart the development backend, then choose Re-check parser support and Review Fields. Your original logs and parsed fields are preserved.',
 SOURCE_LIMIT:'The sample is empty or exceeds the safe 64 KiB / 500 event limit.',
 MODEL_REVIEW_REQUIRED:'Parser Studio found source values, but their names, types or repeated occurrences cannot be mapped to one safe parser automatically. Use a trusted log field definition or ChatGPT Assisted Parser to review those choices. No source value was discarded.',
};
function statusMessage(reason:string){return readable[reason]??'Try the other supported method, ChatGPT Assisted Parser.';}
function friendlyEventStatus(status:string){
 return status==='pass'?'Ready':status==='warning'?'Check details':'Needs attention';
}
function sourceAnalysisLabel(status:string){
  if(status==='SOURCE_PARSED')return 'Fields found';
  if(status==='PARTIAL')return 'Needs review';
  if(status==='RAW_ONLY')return 'Not yet understood';
  if(status==='STRUCTURED_EMPTY')return 'Structure found, no fields yet';
  return 'Needs review';
}
function backendReviewMessage(error:unknown){
 const detail=error instanceof Error?error.message:'';
 if(/HTTP|request failed|fetch|network|unavailable/i.test(detail))
   return 'The parser creation service is unavailable or access was denied. Log analysis succeeded and your parsed fields are preserved. Try again after the local backend is reachable and authorized.';
 if(/capabilit|contract|allowlist|bounded|authoring|verification flags|inconsistent/i.test(detail))
   return 'Parser Studio components are out of sync. Log analysis succeeded, but this UI cannot create parser files with the connected backend version. Update or restart the development backend, then try again. Your parsed fields are preserved.';
 return 'Parser Studio could not start parser creation with the connected backend. Your parsed fields are preserved; open Tools & Diagnostics for technical details or retry after the backend is updated.';
}
export default function AutoParser({
 draft,setDraft,sample,setSample,datasetName,setDatasetName,suite,pending,
 runPreview,onChatGPT,advanced,namedLogTypes,onEnableNamedLogTypes,
 onChangeNamedLogTypes,onExitNamedLogTypes,
}:Props){
 const sourceLogRef=useRef<HTMLTextAreaElement|null>(null);
 const [zeekOrigin,setZeekOrigin]=useState<{source:string;draft:ParserDraft;datasetName:string;dataRows:string}|null>(null);
 const zeekSuggestion=useMemo(()=>inspectZeekReview(sample),[sample]);
 const [step,setStep]=useState<0|1|2|3>(0);
 const [furthestStep,setFurthestStep]=useState<0|1|2|3>(0);
 const [navigationHint,setNavigationHint]=useState('');
 const [selected,setSelected]=useState(0);
 const [multiPass,setMultiPass]=useState<MultiPassReview|null>(null);
 const [multiPassNotice,setMultiPassNotice]=useState('');
 const [multiPassEvent,setMultiPassEvent]=useState(0);
 const [selectedMultiPass,setSelectedMultiPass]=useState<MultiPassSourceSelection|null>(null);
 const [busy,setBusy]=useState(false);
 const [message,setMessage]=useState('');
 const [reviewBlock,setReviewBlock]=useState<{key:string;reason:string}|null>(null);
 const [reviewed,setReviewed]=useState<{source:string;mappingCount:number;requiresApproval:boolean}|null>(null);
 const [capability,setCapability]=useState<{source:string;value:BackendCapabilities}|null>(null);
 const [csvApprovedKey,setCsvApprovedKey]=useState('');
 const pendingNeutralCsvApproval=useRef('');
 // Review is revoked on every manual input edit, including edit-then-revert.
 // The one exception is the explicit beginner action that fills neutral
 // field_### names and approves exactly that generated schema in one action.
 useEffect(()=>{
   const key=JSON.stringify([sample,draft.csvColumns,draft.csvDelimiter]);
   if(pendingNeutralCsvApproval.current===key){
     pendingNeutralCsvApproval.current='';
     setCsvApprovedKey(key);
   }else setCsvApprovedKey('');
 },[sample,draft.csvColumns,draft.csvDelimiter]);
 const [evidence,setEvidence]=useState<Evidence|null>(null);
 const [pair,setPair]=useState<Pair|null>(null);
 const [zip,setZip]=useState<Zip|null>(null);
 const [recipe,setRecipe]=useState<{key:string;value:RecipeReview}|null>(null);
 const [recipeCompiled,setRecipeCompiled]=useState<{key:string;value:ReviewedRecipeCompilation}|null>(null);
 const [recipeCompilerError,setRecipeCompilerError]=useState('');
 const [nativeEvidence,setNativeEvidence]=useState<NativeEvidence|null>(null);
 const [nativeAvailability,setNativeAvailability]=useState<'UNCHECKED'|'AVAILABLE'|'UNAVAILABLE'|'ERROR'>('UNCHECKED');
 const [fingerprints,setFingerprints]=useState<{key:string;value:FingerprintMatchReport}|null>(null);
 const [structural,setStructural]=useState<{key:string;value:StructuralMiningReport}|null>(null);
 const [parserSetOrigin,setParserSetOrigin]=useState<ParserSetOrigin|null>(null);
 const parserSetOriginRef=useRef<ParserSetOrigin|null>(null);
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
 const identity=JSON.stringify([draft,sample,namedLogTypes]);
 const analysisRun=useAnalysisRun(identity);
 const multiPassBusy=analysisRun.progress!==null;
 const currentRef=useRef(identity);currentRef.current=identity;
 const report=useMemo(()=>analyzeLogEnvelopes(sample,
   (draft.guided?.eventBoundary??'single-line') as EventBoundary,draft.forwarder),
   [sample,draft.guided?.eventBoundary,draft.forwarder]);
 useEffect(()=>{
   epoch.current++;setEvidence(null);setPair(null);setZip(null);setRecipe(null);
   setRecipeCompiled(null);setRecipeCompilerError('');setNativeEvidence(null);setNativeAvailability('UNCHECKED');
   setRepair(null);setRepairNotice('');setFingerprints(null);setStructural(null);
   setDrainAvailability('UNCHECKED');setDrainConsent(false);
   setDrainResult(null);setDrainNotice('');
   setLogicalReview(null);
   setSaveAfterApproval(false);
   setBusy(false);setMessage('');setReviewBlock(null);
 },[identity]);
 useEffect(()=>{setStep(0);setFurthestStep(0);},[sample]);
 // Changing type names or group membership revokes previously reviewed
 // parser routes even when the concatenated source is byte-identical.
 useEffect(()=>{setReviewed(null);setStep(0);setFurthestStep(0);},[namedLogTypes]);
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
     return {...selectDraftFormat(old,'java_stacktrace'),
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
 const multiPassCsvEvidence=multiPass?.raw===sample&&multiPass.events.length>0&&
   multiPass.events.every(event=>event.preview.syntax.toUpperCase().includes('CSV'));
 const csvFound=report.families.some(f=>f.envelope==='none'&&f.body==='csv');
 const csvReviewActive=csvFound&&(draft.format==='csv'||advanced||
   (draft.format==='auto'&&(report.unsupported===0||Boolean(multiPassCsvEvidence))));
 const csvSchemaKey=JSON.stringify([sample,draft.csvColumns,draft.csvDelimiter]);
 const csvApproved=!csvReviewActive||csvApprovedKey===csvSchemaKey;
 const csvColumns=draft.csvColumns.split(',').map(x=>x.trim());
 const csvNamesValid=csvColumns.length>=2&&csvColumns.length<=100&&
   csvColumns.every(x=>/^[A-Za-z][A-Za-z0-9_]{0,63}$/.test(x))&&
   new Set(csvColumns).size===csvColumns.length&&
   [',',';','\t'].includes(draft.csvDelimiter??'INVALID');
 const csvSourceRecords=csvReviewActive?splitEvents(sample,report.boundary,MAX_EVENTS+1):[];
 const reportCsvEventNumbers=report.events.map((event,index)=>event.body==='csv'?index+1:-1)
   .filter(index=>index>0);
 const csvReviewEventNumbers=reportCsvEventNumbers.length?reportCsvEventNumbers:
   (multiPassCsvEvidence?csvSourceRecords.map((_,index)=>index+1):[]);
 const csvReviewSample=csvReviewEventNumbers.map(eventNumber=>csvSourceRecords[eventNumber-1]?.raw)
   .filter((value):value is string=>typeof value==='string').join('\n');
 const csvSupportedShapeCounts=csvReviewActive?
   ([',',';','\t'] as const).map(delimiter=>inferConsistentCsvColumnCount(csvReviewSample,delimiter))
     .filter((count):count is number=>count!==null):[];
 const csvConsistentShapeAvailable=!csvReviewActive||csvSupportedShapeCounts.length>0;
 const csvSubsetInspection=csvReviewActive?
   inspectCsvColumnShapes(csvReviewSample,draft.csvDelimiter??','):{groups:[],invalidEventNumbers:[]};
 const csvSelectedShapeInspection={
   groups:csvSubsetInspection.groups.map(group=>({...group,
     eventNumbers:group.eventNumbers.map(number=>csvReviewEventNumbers[number-1]??number)})),
   invalidEventNumbers:csvSubsetInspection.invalidEventNumbers.map(
     number=>csvReviewEventNumbers[number-1]??number),
 };
 const csvSelectedShapeGroups=csvSelectedShapeInspection.groups;
 const neutralCsvColumnCount=csvReviewActive?
   inferConsistentCsvColumnCount(csvReviewSample,draft.csvDelimiter??','):null;
 const csvSelectedShapeMatchesNames=Boolean(neutralCsvColumnCount&&
   csvColumns.length===neutralCsvColumnCount);
 // Exactly two fully quoted columns have strong source grammar but the
 // generic auto preview cannot assign positional meaning on its own.
 // Once the user reviews both column names, use the existing CSV extractor.
 // Wider CSV records retain their proven Auto Parser mapping workflow.
 // This does NOT approve mixed/ambiguous rows, forge column semantics, or
 // skip the subsequent mapping/compiler review.
 const csvFullyReviewedSource=neutralCsvColumnCount===2&&
   report.complete&&report.unsupported===0&&
   report.families.length===1&&report.families[0]?.envelope==='none'&&
   report.families[0]?.body==='csv';
 const formatCsvEventNumbers=(numbers:number[]):string=>{
   const ranges:string[]=[];let start=numbers[0],end=numbers[0];
   for(const value of numbers.slice(1)){
     if(end!==undefined&&value===end+1){end=value;continue;}
     if(start!==undefined&&end!==undefined)ranges.push(start===end?String(start):start+'–'+end);
     start=end=value;
   }
   if(start!==undefined&&end!==undefined)ranges.push(start===end?String(start):start+'–'+end);
   return ranges.join(', ');
 };
 const prepareZeekRows=()=>{
   if(!zeekSuggestion)return;
   setZeekOrigin({source:sample,draft,datasetName,dataRows:zeekSuggestion.dataRows});
   setDraft(old=>{
     const opts=old.guided??defaultGuidedOptions();
     const mappings=zeekSuggestion.columns.split(',').map((name,index)=>({
       id:'zeek-column-'+String(index+1),source:name,target:name,type:'string' as const,
     }));
     return {...selectDraftFormat(old,'csv'),csvColumns:zeekSuggestion.columns,
       csvDelimiter:'\t',mappings,guided:{...opts,
         groups:Object.fromEntries(mappings.map(mapping=>[mapping.id,'vendor_fields' as const])),
         classification:{defaultIndex:'Syslog',rules:[]}}};
   });
   setSample(zeekSuggestion.dataRows);
   setDatasetName('Zeek data rows · Header saved for in-session restore');
   setSelected(0);
 };
 const restoreZeekRows=()=>{
   if(!zeekOrigin)return;
   setDraft(zeekOrigin.draft);
   setSample(zeekOrigin.source);
   setDatasetName(zeekOrigin.datasetName);
   setZeekOrigin(null);
 };
 const suggestNeutralCsvColumns=()=>{
   if(!neutralCsvColumnCount)return;
   const names=Array.from({length:neutralCsvColumnCount},
     (_,index)=>'field_'+String(index+1).padStart(3,'0')).join(',');
   const delimiter=draft.csvDelimiter??',';
   const key=JSON.stringify([sample,names,delimiter]);
   pendingNeutralCsvApproval.current=key;
   setDraft(old=>{
     const next={...old,csvColumns:names,csvDelimiter:delimiter};
     return old.format==='auto'&&csvFullyReviewedSource?selectDraftFormat(next,'csv'):next;
   });
   setCsvApprovedKey(key);
 };
 const confirmCsvColumns=()=>{
   if(!csvNamesValid||!csvSelectedShapeMatchesNames)return;
   setCsvApprovedKey(csvSchemaKey);
   if(csvFullyReviewedSource&&draft.format==='auto')
     setDraft(old=>selectDraftFormat(old,'csv'));
 };
 const localAssessment=assessEnvelopeCompilation(report,
   capability?.source===sample?capability.value:null);
 const assessment=csvReviewActive&&csvApproved&&report.families.length===1&&
   report.families[0]?.body==='csv'&&
   localAssessment.status==='COLUMNS_REQUIRED'&&
   capability?.source===sample&&
   capability.value.authoring.extractionFormats.includes('csv')?{
     status:'DRAFT_COMPILABLE' as const,format:'csv' as const,bodyFormat:null,
     nativeVerified:false as const,targetVerified:false as const,
   }:localAssessment;
 const currentReview=reviewed?.source===sample?reviewed:null;
 const namedLogValidation=namedLogTypes?validateNamedLogs(namedLogTypes):null;
 const namedAnalysis=useMemo(()=>namedLogTypes&&multiPass?.raw===sample?
   analyzeNamedLogs(namedLogTypes,multiPass.events):null,
   [namedLogTypes,multiPass,sample]);
 const namedLogReady=!namedLogTypes||(namedLogValidation?.ok===true&&
   namedAnalysis!==null&&namedAnalysis.unassigned===0&&
   namedAnalysis.groups.every(group=>group.events>0&&!group.boundaryWarning));
 const originalContainerGate=useMemo(()=>originalContainerCompilerGate(
   sample,multiPass?.raw===sample?multiPass:null),[sample,multiPass]);
 function navigateToStep(target:0|1|2|3){
   if(target===0){setNavigationHint('');setStep(0);return;}
   if(!currentReview){
     setNavigationHint('Start with Add Logs. Analyze the sample and review the detected fields before moving to later steps.');
     setStep(0);return;
   }
   if(target===3&&furthestStep<3){
     setNavigationHint('Review the Stellar field mappings first. Parser Studio moved you to Map Fields instead of skipping the required review.');
     setFurthestStep(old=>Math.max(old,2) as 0|1|2|3);setStep(2);return;
   }
   setNavigationHint('');
   setFurthestStep(old=>Math.max(old,target) as 0|1|2|3);
   setStep(target);
 }
 const currentPair=pair?.key===identity?pair.value:null;
 const currentEvidence=evidence?.key===identity?evidence:null;
 const currentZip=zip?.key===identity?zip:null;
 const currentRecipe=recipe?.key===identity?recipe.value:null;
 const currentRecipeCompiled=recipeCompiled?.key===identity?recipeCompiled.value:null;
 const currentNativeEvidence=nativeEvidence?.key===identity?nativeEvidence:null;
 const currentFingerprints=fingerprints?.key===identity?fingerprints.value:null;
 const currentStructural=structural?.key===identity?structural.value:null;
 const parserSetCandidates=currentStructural?.status==='CANDIDATES'?
   currentStructural.groups.filter(group=>group.count>=3):[];
 const parserSetCovered=parserSetCandidates.reduce((sum,group)=>sum+group.count,0);
 const currentDrain=drainResult?.key===identity&&
   drainResult.holdout===drainHoldout?drainResult.value:null;
 const currentLogicalReview=logicalReview?.key===identity?logicalReview.value:null;
 const repairKey=JSON.stringify([identity,holdout]);
 const currentRepair=repair?.key===repairKey?repair:null;
 const records=suite?.events??[];
 const chosen=records[selected]??records[0];
 const multiPassSourceComplete=multiPass?.raw===sample&&multiPass.events.length>0&&
   multiPass.events.every(event=>event.preview.status==='SOURCE_PARSED');
 const parserRuleReviewEventIndexes=report.events.map((event,index)=>
   event.status!=='RECOGNIZED'?index:-1).filter(index=>index>=0);
 const parserRuleReviewRequired=Boolean(multiPassSourceComplete&&draft.format==='auto'&&parserRuleReviewEventIndexes.length>0);
 const beginnerAuthoritativeComplete=Boolean(multiPassSourceComplete&&!parserRuleReviewRequired);
 const browserSuiteComplete=!!suite&&suite.engine==='browser-preview'&&
   suite.nativeFluentdVerified===false&&suite.stellarExportVerified===false&&
   suite.counts.total>0&&suite.counts.matched===suite.counts.total&&
   suite.counts.extracted===suite.counts.total&&suite.counts.normalized===suite.counts.total&&
   suite.counts.failures===0;
 const reviewedCandidateComplete=draft.format!=='auto'&&browserSuiteComplete;
 const browserExtractionComplete=!!suite&&suite.engine==='browser-preview'&&
   suite.counts.total>0&&suite.counts.matched===suite.counts.total&&
   suite.counts.extracted===suite.counts.total&&suite.counts.failures===0;
 const neutralCsvComplete=csvReviewActive&&csvApproved&&csvNamesValid&&browserExtractionComplete;
 const beginnerResolved=beginnerAuthoritativeComplete||reviewedCandidateComplete||neutralCsvComplete;
 const explicitBackendProject=useMemo(()=>draft.format==='auto'?null:toBackendProject(draft),[draft]);
 const explicitDraftCompilable=useMemo(()=>{
   if(!browserSuiteComplete||!explicitBackendProject?.ok||capability?.source!==sample)return false;
   try{assertBackendProjectSupported(explicitBackendProject.project,capability.value);return true;}
   catch{return false;}
 },[browserSuiteComplete,explicitBackendProject,capability,sample]);
 const currentReviewBlock=reviewBlock?.key===identity?reviewBlock:null;
 const canReview=Boolean(sample.trim())&&!pending&&!!suite&&
   report.complete&&report.sourceCount>0&&!busy&&!currentReviewBlock&&
   csvApproved&&(advanced||beginnerResolved)&&namedLogReady;
 const canGenerate=step===3&&!originalContainerGate&&namedLogReady&&
   !!currentReview&&!currentReviewBlock&&!!suite&&!pending&&
   !busy&&(assessment.status==='DRAFT_COMPILABLE'||explicitDraftCompilable);
 const confirmed=()=>{
   const record=suite;
   return !originalContainerGate&&namedLogReady&&!!record &&
     record.engine==='browser-preview'&&
     record.nativeFluentdVerified===false&&record.stellarExportVerified===false&&
     record.counts.total>0&&record.counts.total===report.sourceCount&&
     record.counts.matched===record.counts.total&&
     record.counts.extracted===record.counts.total&&
     record.counts.normalized===record.counts.total&&
     record.counts.failures===0;
 };
 async function review(){
   if(!canReview||!suite)return;
   if(originalContainerGate){
     // A browser JSON match is not evidence that the downloadable parser
     // supports the original Audit/CRI/Docker/schema/transport wrapper.
     // Advanced Tools must obey the same source-to-compiler trust boundary.
     setMessage('');
     setReviewBlock({key:identity,reason:'ORIGINAL_CONTAINER_NOT_IN_DRAFT_COMPILER'});
     return;
   }
   const token=++epoch.current, expected=identity;
   setBusy(true);setMessage('');setEvidence(null);setPair(null);
   try{
     const cap=await fetchBackendCapabilities();
     if(token!==epoch.current||currentRef.current!==expected)return;
     setCapability({source:sample,value:cap});
     if(draft.format!=='auto'&&browserSuiteComplete){
       const translated=toBackendProject(draft);
       if(!translated.ok){
         setMessage('The reviewed parser contains an unsupported field or classification setting.');
         return;
       }
       assertBackendProjectSupported(translated.project,cap);
       setReviewed({source:sample,mappingCount:draft.mappings.length,requiresApproval:false});
       setFurthestStep(1);setStep(1);setSelected(0);return;
     }
     const baseline=assessEnvelopeCompilation(report,cap);
     const compiler=csvReviewActive&&csvApproved&&report.families.length===1&&
       baseline.status==='COLUMNS_REQUIRED'&&cap.authoring.extractionFormats.includes('csv')?
       {status:'DRAFT_COMPILABLE' as const,format:'csv' as const,
        bodyFormat:null,nativeVerified:false as const,targetVerified:false as const}:
       baseline;
     const next=prepareAutoParserDraft(sample,draft,suite,report,compiler);
     if(!next.ok){setReviewBlock({key:expected,reason:next.reason});setMessage('');return;}
     setDraft(next.draft);setReviewed({
       source:sample,mappingCount:next.automaticMappingCount,
       requiresApproval:next.requiresApproval,
     });
     setFurthestStep(1);setStep(1);setSelected(0);
   }catch(error){
     if(token===epoch.current&&currentRef.current===expected){
       if(error instanceof Error&&'code' in error&&error.code==='BACKEND_PROFILE_UNSUPPORTED'){
         setReviewBlock({key:expected,reason:'BACKEND_PROFILE_UNSUPPORTED'});
         setMessage('');
       }else setMessage(backendReviewMessage(error));
     }
   }finally{if(token===epoch.current)setBusy(false);}
 }
 async function generate(){
   if(!canGenerate||!confirmed()||!suite)return;
   const token=++epoch.current, expected=identity;
   setBusy(true);setMessage('');setPair(null);setZip(null);setNativeEvidence(null);
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
 function useParserSetGroup(group:StructuralHint){
   if(parserSetOrigin||busy||pending)return;
   const selectedGroup=materializeStructuralGroupSource(sample,group);
   if(!selectedGroup.ok){
     setMessage(selectedGroup.reason==='HOLDOUT_REQUIRED'
       ?'This structural group needs at least three events so a repair can use one training event and two independent holdouts.'
       :'Parser Studio could not reproduce this structural group from the unchanged source. No logs were selected.');
     return;
   }
   const origin:ParserSetOrigin={source:sample,datasetName,sourceCount:report.sourceCount,draft,
     fingerprint:group.fingerprint,groupCount:selectedGroup.count,groupSource:selectedGroup.source};
   parserSetOriginRef.current=origin;setParserSetOrigin(origin);
   setSample(selectedGroup.source);
   setDatasetName((datasetName||'Logs')+' · Parser Set group');
   setStep(0);setSelected(0);setMultiPass(null);setMultiPassEvent(0);
   setSelectedMultiPass(null);setMultiPassNotice('');setHoldout('');setMessage('');
 }
 function restoreParserSetSource(){
   const origin=parserSetOrigin??parserSetOriginRef.current;
   if(!origin)return;
   parserSetOriginRef.current=null;setParserSetOrigin(null);
   setSample(origin.source);setDatasetName(origin.datasetName);
   setDraft(origin.draft);setStep(0);setSelected(0);setMultiPass(null);setMultiPassEvent(0);
   setSelectedMultiPass(null);setMultiPassNotice('');setHoldout('');setMessage('');
 }
 async function previewRecipe(){
   if(!suite||busy||pending)return;
   const token=++epoch.current,expected=identity;
   setBusy(true);setRecipe(null);setRecipeCompiled(null);setRecipeCompilerError('');setNativeEvidence(null);
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
   setBusy(true);setRecipeCompiled(null);setRecipeCompilerError('');setNativeEvidence(null);
   try{
     const result=await compileReviewedRecipeV02({
       recipe:currentRecipe.recipe,legacyProject:currentRecipe.legacyProject,
     },currentPair);
     if(token===epoch.current&&currentRef.current===expected){
       setRecipeCompiled({key:expected,value:result});
       try{
         const available=await checkNativeProjectVerificationAvailability();
         if(token===epoch.current&&currentRef.current===expected)
           setNativeAvailability(available?'AVAILABLE':'UNAVAILABLE');
       }catch{
         if(token===epoch.current&&currentRef.current===expected)setNativeAvailability('ERROR');
       }
     }
   }catch{
     if(token===epoch.current&&currentRef.current===expected)
       setRecipeCompilerError('The backend could not verify the strict v0.2 stages against the current DRAFT pair. The original v0.1 files remain available.');
   }finally{if(token===epoch.current)setBusy(false);}
 }
 async function verifyCurrentNativeProject(){
   if(!currentRecipe||!currentRecipe.ok||!currentRecipeCompiled||!suite||busy||pending)return;
   const token=++epoch.current,expected=identity;
   setBusy(true);setNativeEvidence(null);
   try{
     const result=await verifyNativeProject({
       source:sample,suite,recipe:currentRecipe.recipe,
       legacyProject:currentRecipe.legacyProject,compiled:currentRecipeCompiled,
     });
     if(token===epoch.current&&currentRef.current===expected)
       setNativeEvidence({key:expected,status:'PASS',report:result,
         message:'Current source-bound Ruby/CONF passed the pinned Native parser runtime.'});
   }catch(error){
     if(token!==epoch.current||currentRef.current!==expected)return;
     if(error instanceof NativeProjectVerificationUnavailable)
       setNativeEvidence({key:expected,status:'UNAVAILABLE',
         message:'Private Native verification is not configured or access was denied. DRAFT remains Native NOT VERIFIED.'});
     else setNativeEvidence({key:expected,status:'FAILED',
       message:'Native Ruby/CONF verification did not pass. No target or sensor claim was made.'});
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
     parserSetOriginRef.current=null;setParserSetOrigin(null);setSample(value);setDatasetName(file.name);setSelected(0);setStep(0);
   }catch{setMessage('Only bounded, valid UTF-8 text files can be opened locally.');}
 }
 function restoreExistingProject(next:ParserDraft,label:string){
   parserSetOriginRef.current=null;setParserSetOrigin(null);setDraft(next);setSample('');setDatasetName(label);setSelected(0);setStep(0);
 }
 async function previewMultiPass(){
  if(!sample.trim()||multiPassBusy)return;
  if(namedLogValidation&&!namedLogValidation.ok){
    setMultiPassNotice('Every log type needs a unique name and at least one sample before analysis.');
    return;
  }
  const original=sample;setMultiPass(null);setMultiPassEvent(0);setSelectedMultiPass(null);
  setMultiPassNotice('');
  const run=analysisRun.begin(new TextEncoder().encode(original).byteLength);
  const options={signal:run.controller.signal,
    onPhase:(phase:'analyzing'|'validating')=>analysisRun.setPhase(run,phase)};
  try{
   let review:MultiPassReview;
   if(original.includes('\n')||original.includes('\r')||original.includes('\0')||
      original.startsWith('\x1e')||/^[1-9][0-9]{0,5} /.test(original)){
    const result=await requestMultiPassBatchPreview(original,fetch,options);
    review={raw:original,metadataLines:result.separators.filter(item=>item.kind==='SOURCE_METADATA').length,transportFramingParts:result.separators.filter(item=>item.kind==='SOURCE_FRAMING').length,events:result.events.map(item=>({
     startByte:item.startByte,endByte:item.endByte,preview:item.preview,
    }))};
   }else{
    const result=await requestMultiPassPreview(original,fetch,options);
    review={raw:original,events:[{
     startByte:0,endByte:new TextEncoder().encode(original).byteLength,preview:result,
    }]};
   }
   if(!analysisRun.isCurrent(run))return;
   // The bounded compiler can resolve a partial source diagnostic only when
   // its strict grammar preserves the same complete set of original records.
   const automatic=!advanced&&draft.format==='auto'&&report.unsupported>0&&
     review.events.length>0
     ?buildSourceReviewedGenericStructuralDraft(original,draft,review):null;
   // Finish before a successful automatic draft adoption changes the identity.
   analysisRun.finish(run);
   setMultiPass(review);
   if(automatic){
     setDraft(automatic.draft);
     // The main parsed-completely summary is the single beginner status.
     setMultiPassNotice('');
   }
  }catch{
   if(analysisRun.isCurrent(run))setMultiPassNotice('Deeper local analysis is unavailable right now. Your logs were not changed; continue with the normal analysis or try again later.');
  }finally{analysisRun.finish(run);}
 }
 const multiPassDerived=useMemo(()=>{
  const review=multiPass?.raw===sample?multiPass:null;
  const frame=review?.events[multiPassEvent]??review?.events[0]??null;
  const preview=frame?.preview??null;
  const bytes=new TextEncoder().encode(sample);
  const decoder=new TextDecoder('utf-8',{fatal:true});
  const decode=(startByte:number,endByte:number)=>decoder.decode(bytes.slice(startByte,endByte));
  const raw=frame?decode(frame.startByte,frame.endByte):'';
  const highlights=advanced&&preview?buildMultiPassSourceHighlights(raw,preview):null;
  const counts=review?.events.reduce((value,event)=>{
   value[event.preview.status]=(value[event.preview.status]??0)+1;return value;
  },{} as Record<string,number>)??{};
  const protectedValues=review?.events.map(event=>
   event.preview.spans.filter(span=>span.endByte>span.startByte)
    .map(span=>decode(event.startByte+span.startByte,event.startByte+span.endByte)));
  const protectedResiduals=review?.events.map(event=>
   event.preview.residuals.filter(region=>region.endByte>region.startByte)
    .map(region=>decode(event.startByte+region.startByte,event.startByte+region.endByte))
    .filter(text=>text.trim().length>0));
  return {review,frame,preview,raw,highlights,counts,protectedValues,protectedResiduals};
 },[multiPass,sample,multiPassEvent,advanced]);
 const currentMultiPassReview=multiPassDerived.review;
 const currentMultiPassFrame=multiPassDerived.frame;
 const currentMultiPass=multiPassDerived.preview;
 const currentMultiPassRaw=multiPassDerived.raw;
 const currentMultiPassHighlights=multiPassDerived.highlights;
 const currentMultiPassCounts=multiPassDerived.counts;
 const protectedSourceValuesByEvent=multiPassDerived.protectedValues;
 const protectedResidualTextByEvent=multiPassDerived.protectedResiduals;
 const parserIdentityIsDefault=draft.vendor==='Demo / local draft'&&draft.name==='Untitled parser';
 const parserArtifactName=parserIdentityIsDefault
   ?'customized_<manufacturer>_<product>'
   :'customized_'+(draft.guided?.slug??parserIdentitySlug(draft.vendor,draft.name));
 const updateParserIdentity=(field:'vendor'|'name'|'version',value:string)=>{
  setDraft(old=>{
   const vendor=field==='vendor'?value:old.vendor;
   const name=field==='name'?value:old.name;
   const version=field==='version'?value:(old.version??'');
   const opts=old.guided??defaultGuidedOptions();
   return {...old,vendor,name,version,
    guided:{...opts,slug:parserIdentitySlug(vendor,name)}};
  });
 };
 useEffect(()=>{
   if(advanced||parserSetOrigin||report.unsupported<3||!currentMultiPassReview||
      currentStructural||busy||pending||!suite)return;
   void mineUnknownShapes();
 },[advanced,parserSetOrigin,report.unsupported,currentMultiPassReview,currentStructural,
   busy,pending,suite,identity]);
 return <main className={'auto-parser-workspace '+(advanced?'advanced-mode':'beginner-mode')} aria-label="Auto Parser v2">
   <header className="auto-parser-intro">
     <span className="pane-index">AUTO PARSER · GUIDED MODE</span>
     <h1>Paste security logs. Parser Studio will guide you to a parser step by step.</h1>
     <p>You do not need to know parser formats or write code. Start with a few representative
       logs, use the main button on each screen, and Parser Studio will tell you when something needs review.</p>
     {step===0&&!namedLogTypes&&<button type="button" className="novice-log-entry-shortcut"
       onClick={()=>sourceLogRef.current?.focus()}>
       Go to log input
     </button>}
   </header>
   <nav aria-label="Auto Parser steps" className="auto-parser-steps">
     {STEPS.map((label,index)=>{
       const locked=index>furthestStep;
       return <button type="button" key={label}
         aria-current={index===step?'step':undefined}
         aria-label={locked?label+' — locked until the current step is finished':undefined}
         title={locked?'Click to see what must be completed first.':STEP_HELP[index]}
         className={(index===step?'active ':'')+(locked?'locked':'')}
         onClick={()=>navigateToStep(index as 0|1|2|3)}>
         <span>{index+1}</span><span className="step-copy">{label}
           {locked&&<small className="step-lock">Next after current step</small>}</span>
       </button>;
     })}
   </nav>
   {navigationHint&&<p className="beginner-navigation-hint" role="status">{navigationHint}</p>}
   <div className="auto-parser-body">
     {step===0&&<section aria-label="Add Logs stage">
       <div className="parser-identity-card" aria-label="Parser product identity">
         <div className="parser-identity-copy">
           <strong>Parser identity</strong>
           <span>Enter the source product before creating files. Parser Studio uses these values in the parser metadata and file name.</span>
         </div>
         <div className="parser-identity-fields">
           <label>Manufacturer
             <input aria-label="Parser manufacturer" value={draft.vendor}
               placeholder="e.g. Fortinet"
               onChange={e=>updateParserIdentity('vendor',e.target.value)}/>
           </label>
           <label>Product
             <input aria-label="Parser product" value={draft.name}
               placeholder="e.g. FortiGate"
               onChange={e=>updateParserIdentity('name',e.target.value)}/>
           </label>
           <label>Version
             <input aria-label="Parser product version" value={draft.version??''}
               placeholder="e.g. 7.4.5"
               onChange={e=>updateParserIdentity('version',e.target.value)}/>
           </label>
           <label>Listener Port
             <input aria-label="Parser listener port" type="number" min={1024} max={65535} step={1}
               value={draft.guided?.receiver.port??DEFAULT_PARSER_LISTENER_PORT}
               onChange={e=>{
                 const port=Number(e.target.value);
                 setDraft(old=>{
                   const guided=old.guided??defaultGuidedOptions();
                   return {...old,guided:{...guided,receiver:{...guided.receiver,port}}};
                 });
               }}/>
             <small>Default 6801 · Used in the generated .conf listener. Change if your source needs another port. Syslog requires 6800 or higher; live port availability is not verified.</small>
           </label>
         </div>
         <div className="parser-identity-filename">
           <span>Generated parser files</span>
           <code>{parserArtifactName}</code>
           <code>{parserArtifactName}.conf</code>
           <small>CONF listener port: <b>{draft.guided?.receiver.port??DEFAULT_PARSER_LISTENER_PORT}</b> · Draft only</small>
           <small>Stellar custom parsers use the <b>customized_&lt;vendor&gt;_&lt;product&gt;</b> naming convention. Version is stored in the parser metadata rather than appended to the file name.</small>
         </div>
       </div>
       <h2>Add Logs <HelpTip label="Add Logs"
         text="Use logs from the same product and event family when possible. Two or more examples help Parser Studio tell changing values from fixed text."/></h2>
       <StageGuide title="Start here">
         Paste or upload representative logs, then click Analyze Logs. Do not choose a format or write a parsing rule first.
       </StageGuide>
       <p>Paste or upload a few representative security events. Parser Studio will try to identify
         the structure and fields for you. Nothing changes until you press <b>Analyze Logs</b>.</p>
       <small>For exact original line endings and UTF-8 byte locations, upload the source file. Pasting into a browser text box can normalize CRLF to LF.</small>
       <NamedLogTypesPanel groups={namedLogTypes}
         onEnable={onEnableNamedLogTypes} onChange={onChangeNamedLogTypes}
         onExit={onExitNamedLogTypes} analysis={namedAnalysis??undefined}/>
       {!namedLogTypes&&<>
       <div className="auto-parser-source-toolbar">
         <label>Upload a log file <HelpTip label="Upload a log file"
           text="Optional. Use this instead of paste when you already have a small text, log, JSON, or CSV sample. The file is read into this browser session."/>
           <input type="file" aria-label="Auto Parser file upload"
             accept=".txt,.log,.json,.csv,text/plain"
             onChange={e=>{const file=e.currentTarget.files?.[0];
               e.currentTarget.value='';void upload(file);}}/>
         </label>
         <small>{datasetName} · Maximum 64 KiB / 500 events</small>
       </div>
       {parserSetOrigin&&<div className="auto-parser-note beginner-essential-note" aria-label="Separate log group context">
         <strong>Working on one matching log group · {parserSetOrigin.groupCount} events
           <HelpTip label="Why is this a separate group?"
             text="These events repeat the same basic structure. Parser Studio separated them so a parser for one shape does not accidentally break different-looking events."/></strong>
         <p>This is an exact subset of the original {parserSetOrigin.sourceCount} logs.
           Analyze this group and create its parser separately; the other log shapes remain unchanged.</p>
         <button type="button" onClick={restoreParserSetSource}>
           Return to all {parserSetOrigin.sourceCount} logs
         </button>
       </div>}
       {zeekSuggestion&&<div className="auto-parser-note beginner-essential-note" aria-label="Zeek schema preparation">
         <strong>Zeek field names found — {zeekSuggestion.recordCount} data events</strong>
         <p>{zeekSuggestion.metadataCount} lines beginning with # describe the log format, not separate security events.
           The remaining {zeekSuggestion.recordCount} tab-separated rows have consistent columns.
           You can explicitly separate them and fill the field names, then click Analyze Logs again.</p>
         <p>Dots in Zeek column names become underscores for safe CSV field names.
           All data row values remain unchanged. Original header lines stay in browser memory
           for the Restore action until you leave this page. Save a Local Version if you need a lasting copy.</p>
         <button type="button" onClick={prepareZeekRows}>Prepare Zeek data rows and field names</button>
       </div>}
       {zeekOrigin&&<div className="auto-parser-note beginner-essential-note" aria-label="Prepared Zeek source context">
         <strong>Working with Zeek data rows only</strong>
         <p>The original sample with its # header lines is preserved in this page.
           Review the TAB column names, analyze again, and confirm mappings before creating a DRAFT.
           You can restore the full original source now; closing the page clears this temporary copy.</p>
         <button type="button" onClick={restoreZeekRows}>Restore original Zeek sample</button>
       </div>}
       <textarea ref={sourceLogRef} spellCheck={false} rows={10} aria-label="Auto Parser raw logs"
         placeholder="Paste representative raw log events here. Parser Studio will detect the structure for you."
         value={sample} onChange={e=>{const value=e.target.value;
           if(parserSetOriginRef.current?.groupSource!==value){
             parserSetOriginRef.current=null;setParserSetOrigin(null);
           }
           if(zeekOrigin?.dataRows!==value)setZeekOrigin(null);
           setSample(value);setDatasetName('Pasted logs · Browser session only');setSelected(0);}}/>
       </>}
       <div className="beginner-analyze-action">
         <button type="button" className="auto-parser-primary" disabled={!sample.trim()||multiPassBusy}
           onClick={()=>void previewMultiPass()}>
           {multiPassBusy?'Analyzing Logs…':'Analyze Logs'}
         </button>
         <span>No log data is sent to an LLM. This analysis uses the local Parser Studio engine.</span>
       </div>
       <AnalysisProgressPanel progress={analysisRun.progress} interruption={analysisRun.interruption}
         onCancel={analysisRun.cancel}/>
       <ManualSourceBoundaryReview source={sample} sourceInput={sourceLogRef}/>
       <DeclaredRelayProfilePanel sample={sample} draft={draft} setDraft={setDraft}/>
       <PythonTestSenderPanel source={sample} draft={draft}/>
       {multiPassNotice&&<p className="beginner-analysis-error" role="alert">
         Parser Studio could not complete local analysis. Your source was preserved. Open troubleshooting tools only if you need more diagnostic detail.
       </p>}
       {currentMultiPassReview&&<BeginnerAnalysisPanel source={sample}
         events={currentMultiPassReview.events} onOpenAssisted={onChatGPT}
         draft={draft} suite={suite} onApplyCandidate={setDraft}
         resolvedByReviewedCandidate={reviewedCandidateComplete||neutralCsvComplete}
         compilerBlockedReason={currentReviewBlock?.reason}
         parserRuleReviewRequired={parserRuleReviewRequired}
         parserRuleReviewEventIndexes={parserRuleReviewEventIndexes}
         csvReviewRequired={csvReviewActive&&!csvApproved}
         csvConsistentShapeAvailable={csvConsistentShapeAvailable}
         neutralCsvColumnCount={neutralCsvColumnCount??undefined}
         onUseNeutralCsvColumns={suggestNeutralCsvColumns}
         protectedSourceValuesByEvent={protectedSourceValuesByEvent}
           protectedResidualTextByEvent={protectedResidualTextByEvent}/>}
       {!advanced&&!parserSetOrigin&&parserSetCandidates.length>0&&currentStructural&&
         <div className="auto-parser-warning" aria-label="Similar log groups">
           <strong>Different log shapes were found
             <HelpTip label="Why are there multiple groups?"
               text="Some products send several different-looking event types. Parser Studio keeps those shapes separate instead of forcing one rule to fit everything."/></strong>
           <p>Parser Studio found {parserSetCandidates.length} repeatable group
             {parserSetCandidates.length===1?'':'s'} covering {parserSetCovered} of {currentStructural.unknownCount}
             {' '}events that still need help. Work on one group at a time.</p>
           <div className="stellar-span-actions">
             {parserSetCandidates.map((group,index)=><button type="button"
               key={group.fingerprint} aria-label={'Analyze structural group '+(index+1)}
               onClick={()=>useParserSetGroup(group)}>
               Analyze group {index+1} · {group.count} similar events
             </button>)}
           </div>
           {currentStructural.unknownCount>parserSetCovered&&
             <small>{currentStructural.unknownCount-parserSetCovered} event
               {currentStructural.unknownCount-parserSetCovered===1?'':'s'} do not have enough similar examples yet.
               Parser Studio leaves them for separate review instead of guessing.</small>}
         </div>}
       {advanced&&<div className="beginner-tools-intro" aria-label="Troubleshooting tools guidance">
         <strong>Troubleshooting tools</strong>
         <p>Most users can ignore everything in this section. Use a tool only when the normal Analyze Logs result tells you that a log still needs help. Opening a tool does not change your parser automatically.</p>
       </div>}
       {advanced&&<div className="stellar-multipass-panel" aria-label="Deeper local log analysis">
         <div className="beginner-tool-summary">
           <strong>Deeper local log analysis</strong>
           <HelpTip label="Deeper local log analysis"
             text="Use this only when normal analysis cannot fully identify a difficult log. It tries additional local parsing paths and shows which values were recognized. It does not install or certify a parser."/>
         </div>
         <span className="beginner-tool-when">Use when: Analyze Logs says one or more events still need review.</span>
         <button type="button" disabled={!sample.trim()||multiPassBusy} onClick={()=>void previewMultiPass()}>
           {multiPassBusy?'Running deeper analysis…':'Re-analyze difficult logs'}
         </button>
         <small>This checks only the sample on this development server. It does not deploy anything or prove that final parser files work on a live Stellar system.</small>
         {multiPassNotice&&<p role="status">{multiPassNotice}</p>}
         {currentMultiPassReview&&Boolean(currentMultiPassReview.transportFramingParts)&&<p className="auto-parser-note" role="status">Parser Studio kept {currentMultiPassReview.transportFramingParts} original transport boundaries or journal-entry separators. The original event count and source bytes are preserved. This transport framing is not yet verified for downloadable parser execution.</p>}
       {currentMultiPassReview&&currentMultiPassReview.metadataLines!==undefined&&currentMultiPassReview.metadataLines>0&&<p className="auto-parser-note" role="status">Parser Studio kept {currentMultiPassReview.metadataLines} original schema/header lines as source metadata, not data events. The parsed field values are available for review; creating a downloadable parser for this exact header-dependent input is not yet verified.</p>}
       {currentMultiPassReview&&<div className="auto-parser-ledger" aria-label="Detailed event accounting">
           <strong>{currentMultiPassReview.events.length} event{currentMultiPassReview.events.length===1?'':'s'} checked without dropping source text</strong>
           <span>{currentMultiPassCounts.SOURCE_PARSED??0} fields found · {currentMultiPassCounts.PARTIAL??0} need review · {currentMultiPassCounts.RAW_ONLY??0} not yet understood · {currentMultiPassCounts.STRUCTURED_EMPTY??0} structure only</span>
           <span>Diagnostic check only · final parser files are tested later</span>
           {currentMultiPassReview.events.length>1&&<label>Choose an event to inspect
             <select aria-label="Detailed analysis event" value={multiPassEvent}
               onChange={e=>{setMultiPassEvent(Number(e.target.value));setSelectedMultiPass(null);}}>
               {currentMultiPassReview.events.map((event,index)=><option key={index} value={index}>
                 Event {index+1} · {sourceAnalysisLabel(event.preview.status)}
               </option>)}
             </select>
           </label>}
         </div>}
         {currentMultiPass&&<div role="status">
           <strong>{sourceAnalysisLabel(currentMultiPass.status)}</strong>
           <p>These are the values Parser Studio found in the selected event. Click a highlighted value only when you want to correct it.</p>
           <pre>{JSON.stringify(currentMultiPass.fields,null,2)}</pre>
           <details className="beginner-technical-details">
             <summary>Technical detection details</summary>
             <code>{currentMultiPass.status} · {currentMultiPass.syntax}</code>
             {currentMultiPassFrame&&<small>Source byte range {currentMultiPassFrame.startByte}–{currentMultiPassFrame.endByte}. Internal correction ranges use UTF-8 byte offsets.</small>}
           </details>
           {currentMultiPass.redaction&&<div className="stellar-redaction-review" aria-label="Visible masking and redaction assessment">
             <strong>Visible redaction review · {currentMultiPass.redaction.explicitMaskOccurrences} explicit marker{currentMultiPass.redaction.explicitMaskOccurrences===1?'':'s'}</strong>
             <p>{currentMultiPass.redaction.assessment==='EXPLICIT_VISIBLE_MASKS'
               ?'Exact visible masking markers were recognized in extracted source values. The visible token is preserved exactly; hidden content is never reconstructed.'
               :currentMultiPass.redaction.assessment==='NOT_ASSESSED_NO_LITERAL_MARKER'
               ?'No exact literal masking marker was recognized. This does not prove the source was never masked or anonymized.'
               :'No extracted source occurrence is available for masking assessment; the event remains excluded from this assessment.'}</p>
             {!!currentMultiPass.redaction.occurrences.length&&<div className="stellar-redaction-grid">
               {currentMultiPass.redaction.occurrences.map((item,i)=><span key={i}>
                 <b>{item.sourcePath}{item.occurrence?` #${item.occurrence+1}`:''}</b>
                 <small>{item.markerClass.replaceAll('_',' ')} · bytes {item.startByte}–{item.endByte}</small>
               </span>)}
             </div>}
             <small>{currentMultiPass.redaction.unassessedVisibleOccurrences} other visible source occurrence{currentMultiPass.redaction.unassessedVisibleOccurrences===1?'':'s'} remain unassessed · Source extraction preserved · Hidden-value reconstruction OFF</small>
           </div>}
           {currentMultiPass.dictionary&&<div className="stellar-dictionary-review" aria-label="Stellar field name suggestions">
             <strong>Suggested Stellar Cyber field names · {currentMultiPass.dictionary.mapped.length} found · {currentMultiPass.dictionary.unmappedCount} kept unchanged
               <HelpTip label="Suggested Stellar field names"
                 text="This compares field names with Stellar Cyber's published metadata list. A suggestion changes only the destination name; the original source value is preserved."/></strong>
             <p>Only documented field names or known standard aliases are shown here. Fields without a safe match stay unchanged for later review.</p>
             <div className="stellar-dictionary-grid">{currentMultiPass.dictionary.mapped.map((item,i)=><span key={i}>
               <b>{item.sourcePath}</b> → {item.targetField} <small>{item.documentedType}</small>
             </span>)}</div>
             {!!currentMultiPass.dictionary.issues.length&&<small>{currentMultiPass.dictionary.issues.join(' · ')}</small>}
             <details className="beginner-technical-details"><summary>Technical field-list evidence</summary>
               <small>{currentMultiPass.dictionary.dictionaryRevision} · source values preserved · live target not tested</small>
             </details>
           </div>}
           {currentMultiPassHighlights?.ok&&<div className="stellar-source-map" aria-label="Highlighted source values">
             {currentMultiPassHighlights.segments.map((segment,i)=>segment.kind==='plain'?
               <span key={i}>{segment.text}</span>:
               <button type="button" key={i}
                 className={'stellar-source-segment '+segment.kind+(selectedMultiPass?.startByte===segment.selection.startByte&&selectedMultiPass.endByte===segment.selection.endByte?' selected':'')}
                 aria-label={segment.kind==='field'
                   ?`Correct extracted field ${segment.selection.path}`
                   :segment.text.trim()
                     ?`Review unparsed text: ${segment.text.trim().slice(0,36)}`
                     :'Review unparsed whitespace'}
                 onClick={()=>setSelectedMultiPass(segment.selection)}>{segment.text}</button>)}</div>}
           {currentMultiPassHighlights&&!currentMultiPassHighlights.ok&&<p className="auto-parser-warning">
             Parser Studio cannot highlight the exact text safely for this event, so no correction target was selected.</p>}
           <div className="stellar-span-actions">{currentMultiPass.spans.filter(span=>span.endByte>span.startByte).map((span,i)=><button type="button" key={'f'+i} className="stellar-span-chip"
             onClick={()=>{const item=currentMultiPassHighlights?.ok?currentMultiPassHighlights.selectable.find(x=>x.kind==='field'&&x.path===span.path&&x.startByte===span.startByte&&x.endByte===span.endByte):undefined;if(item)setSelectedMultiPass(item);}}>
             Correct field: {span.path}</button>)}</div>
           <div className="stellar-span-actions">{currentMultiPass.residuals.map((span,i)=><button type="button" key={'r'+i}
             className="stellar-residual-chip" onClick={()=>{const item=currentMultiPassHighlights?.ok?currentMultiPassHighlights.selectable.find(x=>x.kind==='residual'&&x.startByte===span.startByte&&x.endByte===span.endByte):undefined;if(item)setSelectedMultiPass(item);}}>
             Review unparsed text</button>)}</div>
           {selectedMultiPass&&currentMultiPass.status!=='RAW_ONLY'&&<div className="stellar-selected-source" role="status">
             {selectedMultiPass.kind==='field'?`Selected field: ${selectedMultiPass.path}`:'Selected text that was not parsed'}
           </div>}
           {advanced&&selectedMultiPass&&currentMultiPass.status!=='RAW_ONLY'&&<AutoParserAIReview raw={currentMultiPassRaw} status="partial" onChatGPT={onChatGPT}
             initialByteRange={selectedMultiPass} selectionContext={{kind:selectedMultiPass.kind,path:selectedMultiPass.path}}
             source={sample} draft={draft} suite={suite} onApplyCandidate={setDraft}
             protectedSourceValuesByEvent={protectedSourceValuesByEvent}
           protectedResidualTextByEvent={protectedResidualTextByEvent}/>}
           {advanced&&currentMultiPass.status==='RAW_ONLY'&&<AutoParserAIReview raw={currentMultiPassRaw} status="unsupported" onChatGPT={onChatGPT}
             source={sample} draft={draft} suite={suite} onApplyCandidate={setDraft}
             protectedSourceValuesByEvent={protectedSourceValuesByEvent}
           protectedResidualTextByEvent={protectedResidualTextByEvent}/>}

         </div>}
       </div>}
       {report.status==='SOURCE_LIMIT'&&<div className="auto-parser-warning" role="alert"
         aria-label="Auto Parser sample limit">
         <ShieldAlert size={16}/>
         <div><strong>Sample limit exceeded</strong>
           <p>Use at most 500 logical events and 64 KiB in one analysis. Split this sample into smaller representative batches; Parser Studio will not silently drop the extra events.</p>
         </div>
       </div>}
       {sample.trim()&&<div className="auto-parser-ledger" aria-label="Automatic event accounting">
         <strong>{report.accounted}/{report.sourceCount} events checked</strong>
         <span className="sr-only">{report.accounted}/{report.sourceCount} events analyzed locally</span>
         <span>{report.unsupported} event{report.unsupported===1?'':'s'} {report.unsupported===1?'needs':'need'} attention · Local analysis only</span>
         {advanced&&report.families.map(x=><span key={x.envelope+'/'+x.body}>
           {x.envelope==='none'?'Standalone':x.envelope.toUpperCase()} / {x.body.toUpperCase()}
           {' · '}{x.count}</span>)}
       </div>}
       {csvReviewActive&&<div className="auto-parser-recipe" aria-label="Review CSV column names">
         <strong>{csvConsistentShapeAvailable
           ?'Values found, but this log does not include field names'
           :'These rows contain different numbers of values'}</strong>
         <p>{csvConsistentShapeAvailable
           ?'Parser Studio found each value but cannot safely guess what the columns mean. The safest choice is to keep every value with temporary names, then rename or map them after you confirm the meaning.'
           :'The rows do not all have the same number of values. One parser would shift values into the wrong fields, so Parser Studio asks you to handle matching row shapes separately.'}</p>
         {csvReviewEventNumbers.length>0&&csvReviewEventNumbers.length<report.sourceCount&&
           <p className="auto-parser-note" role="note">
             CSV column review applies only to event {formatCsvEventNumbers(csvReviewEventNumbers)}.
             The other {report.sourceCount-csvReviewEventNumbers.length} recognized event{report.sourceCount-csvReviewEventNumbers.length===1?'':'s'} keep their own detected parser families.
           </p>}
         {!csvConsistentShapeAvailable&&
           (csvSelectedShapeGroups.length>0||csvSelectedShapeInspection.invalidEventNumbers.length>0)&&
           <div className="auto-parser-note" aria-label="CSV row shape groups">
             <strong>Row groups for the selected separator</strong>
             {csvSelectedShapeGroups.length>0&&<ul>{csvSelectedShapeGroups.map(group=>
               <li key={group.columnCount}>{group.columnCount} columns · {group.eventNumbers.length} event{group.eventNumbers.length===1?'':'s'} · event {formatCsvEventNumbers(group.eventNumbers)}{group.columnCount>100?' · exceeds the 100-column parser limit':''}</li>)}</ul>}
             {csvSelectedShapeInspection.invalidEventNumbers.length>0&&
               <p><b>Not safe CSV:</b> event {formatCsvEventNumbers(csvSelectedShapeInspection.invalidEventNumbers)} could not be tokenized with this separator and needs separate review.</p>}
             <p>Use these event numbers to make one parser sample per matching row shape. No source event is discarded automatically.</p>
           </div>}
         <label>Names to give each value <HelpTip label="Names to give each value"
           text="These names describe the values from left to right. If you do not know what they mean yet, use the temporary-name button instead of guessing."/>
           <input aria-label="Reviewed CSV column names" value={draft.csvColumns}
             maxLength={4096}
             onChange={e=>setDraft(old=>({...old,csvColumns:e.target.value}))}/>
         </label>
         {neutralCsvColumnCount&&<div className="auto-parser-note" aria-label="Neutral CSV column suggestion">
           <strong>{neutralCsvColumnCount} consistent columns detected</strong>
           <p>Parser Studio can keep every value under temporary names such as field_001 and field_002
             without guessing vendor semantics. Original values remain unchanged;
             you can rename or map fields later.</p>
           <button type="button" className="auto-parser-primary" onClick={suggestNeutralCsvColumns}>
             Keep all {neutralCsvColumnCount} values with temporary names
           </button>
         </div>}
         <label>Character between the values <HelpTip label="Character between the values"
           text="Choose the character that separates one value from the next in each row. Comma is most common; some products use semicolon or tab."/>
           <select aria-label="Reviewed CSV data separator"
             value={draft.csvDelimiter??','}
             onChange={e=>setDraft(old=>({...old,
               csvDelimiter:e.target.value as ','|';'|'\t'}))}>
             <option value=",">Comma (,)</option>
             <option value=";">Semicolon (;)</option>
             <option value={'\t'}>Tab</option>
           </select>
         </label>
         {!csvApproved&&<button type="button"
           disabled={!csvNamesValid||!csvSelectedShapeMatchesNames||pending}
           onClick={confirmCsvColumns}>
           I Confirm These CSV Column Names
         </button>}
         <p role="status">{csvApproved?
           'Field names are ready. Continue to Review Fields.':
           !csvConsistentShapeAvailable?
             'These rows need to be separated into matching positional shapes before one CSV parser can be created.':
           !neutralCsvColumnCount?
             'Choose the separator that gives every row the same column count before confirming field names.':
           !csvSelectedShapeMatchesNames?
             `Enter exactly ${neutralCsvColumnCount} unique field names for the selected separator before confirming.`:
             'Field names and separator are consistent. Confirm them to continue.'}</p>
       </div>}
       {javaFramedCandidate&&<div className="auto-parser-warning"
         aria-label="Explicit Java TCP framing confirmation">
         <strong>These look like Java error stack traces</strong>
         <p>Parser Studio can handle this sample when each complete error is separated from the next one by a blank line.
           Confirm that your real log sender uses the same boundary before continuing.
           <HelpTip label="Blank-line event boundary"
             text="Technically, the sender must deliver complete events over TCP with two line-feed characters between events. Parser Studio will not guess where a partial stream should be split."/></p>
         <button type="button" aria-label="I Confirm TCP Java Events Are Separated by LF LF"
           onClick={adoptFramedJava}>
           I Confirm Each Java Error Is Separated by a Blank Line
         </button>
       </div>}
       {advanced&&sample.trim()&&report.unsupported>0&&<div className="stellar-ai-unrecognized" aria-label="Unsupported log AI fallback">
         <strong>Some source events need assistance</strong>
         <p>{report.unsupported} of {report.sourceCount} events were not fully recognized. The original input is preserved; unsupported events are not silently discarded or marked parser-ready.</p>
         <AutoParserAIReview raw={sample} status="unsupported" onChatGPT={onChatGPT} source={sample} draft={draft} suite={suite}
           protectedSourceValuesByEvent={protectedSourceValuesByEvent}
           protectedResidualTextByEvent={protectedResidualTextByEvent}/>
       </div>}
       {report.unsupported>0&&!beginnerResolved&&<p className="auto-parser-note beginner-essential-note">
         Some events could not be understood safely. Parser Studio keeps those events unchanged and will not let you continue until they are reviewed.
         <HelpTip label="Why are some events blocked?"
           text="Security logs can contain unusual headers, broken timestamps, several lines per event, or vendor-specific text. Parser Studio stops instead of guessing when that could lose data or create the wrong fields."/>
       </p>}
       <ExistingParserReviewPanel onRestore={restoreExistingProject}/>
       {advanced&&<details className="auto-parser-recipe" aria-label="Multi-line event boundary tool">
         <summary className="beginner-tool-summary">Check where multi-line events begin and end
           <HelpTip label="Multi-line event help"
             text="Use this when one security event is spread across several lines, such as a Java stack trace or formatted JSON. Skip it when each log event is already on one line."/>
         </summary>
         <span className="beginner-tool-when">Use when: Analyze Logs says event boundaries are unclear, or your sample visibly spans several lines per event.</span>
         <p>This check groups physical lines into possible events without changing your source.
           It is a review aid only; it does not create or install a parser by itself.</p>
         <button type="button" disabled={!sample.trim()||busy||pending}
           onClick={()=>setLogicalReview({
             key:identity,value:reviewLogicalBoundaries(sample)
           })}>Review Logical Event Boundaries</button>
         {currentLogicalReview&&<div role="status" aria-label="Reviewed logical boundaries">
           <strong>{currentLogicalReview.status==='NO_MULTILINE'?'No multi-line boundary review is needed':
             currentLogicalReview.status==='REVIEWABLE_MULTILINE'?'Multi-line event boundaries found':
             currentLogicalReview.status==='REVIEW_REQUIRED'?'Multi-line boundaries need review':currentLogicalReview.status} ·
             {currentLogicalReview.accountedNonEmptyLines}/{currentLogicalReview.nonEmptyLines}
             nonempty physical lines accounted</strong>
           <span>{currentLogicalReview.status==='NO_MULTILINE'
             ?'Each current event is already on one physical line. This does not change or contradict the parser result above.'
             :currentLogicalReview.multilineEventCount+' possible multi-line event'+(currentLogicalReview.multilineEventCount===1?'':'s')+' · '+currentLogicalReview.ambiguousCount+' still need review · This check does not test a live Stellar system'}</span>
           {currentLogicalReview.groups.slice(0,12).map((group,i)=><span key={i}>
             Lines {group.firstLine}–{group.lastLine} ·
             {group.kind} · {group.status}
           </span>)}
           {currentLogicalReview.groups.length>12&&<span>
             {currentLogicalReview.groups.length-12} further local groups,
             included in source accounting
           </span>}
           {currentLogicalReview.status!=='NO_MULTILINE'&&<span>
             Review the proposed event boundaries before continuing. This check only helps Parser Studio decide which lines belong to the same event.
           </span>}
         </div>}
       </details>}
       <details className="auto-parser-recipe" aria-label="Private text grouping tool">
         <summary className="beginner-tool-summary">Group similar text logs
           <HelpTip label="Group similar text logs"
             text="Use this when you have many free-form text logs that look similar but Parser Studio cannot find stable fields. The private service groups repeated text shapes so you can decide whether they should share one parser."/>
         </summary>
         <span className="beginner-tool-when">Use when: many unresolved text logs repeat the same general shape. Skip it for JSON, key/value, CEF, LEEF, or other logs that already parse cleanly.</span>
         <p>This optional tool can send only the sample you approve to your private Parser Studio analysis service.
           It does not send data to an external AI service, edit your parser automatically, or deploy anything.</p>
         <button type="button" disabled={busy||pending}
           onClick={()=>{void probeDrain3();}}>
           Check whether private grouping is available
         </button>
         {drainAvailability==='DISABLED'&&<p role="status">
           Private text grouping is not available. You can continue using the normal local analysis.
         </p>}
         {drainAvailability==='ERROR'&&<p role="status">
           Parser Studio could not verify the private grouping service. No sample was sent.
         </p>}
         {drainAvailability==='AVAILABLE'&&<>
           <label className="auto-parser-persist-label">
             <input type="checkbox" checked={drainConsent}
               onChange={e=>{
                 setDrainConsent(e.target.checked);
                 setDrainResult(null);setDrainNotice('');
               }}/>
             I approve sending this sample to my private Parser Studio service for this one grouping check.
           </label>
           <label>Optional different examples for a second check
             <HelpTip label="Different examples"
               text="Paste a few different logs from the same source. Parser Studio uses them only to see whether the discovered text groups also fit examples that were not used to form the groups."/>
             <textarea aria-label="Different example logs" rows={3}
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
             Group Similar Logs
           </button>
         </>}
         {drainNotice&&<p role="status">{drainNotice}</p>}
         {currentDrain&&<div role="status" aria-label="Private text grouping results">
           <strong>{currentDrain.accounted}/{currentDrain.sourceCount} events checked · {currentDrain.groupCount} similar-text group{currentDrain.groupCount===1?'':'s'}</strong>
           <span>{currentDrain.holdoutMatched}/{currentDrain.holdoutCount} different example{currentDrain.holdoutCount===1?'':'s'} matched the discovered groups</span>
           {currentDrain.groups.map((group,index)=><span key={group.clusterId}>
             Group {index+1}: {group.trainingCount} sample event{group.trainingCount===1?'':'s'} ·
             {group.holdoutMatches} different example match{group.holdoutMatches===1?'':'es'}
           </span>)}
           <span>This is a grouping hint only. Review the groups before using them to create parser rules.</span>
           <details><summary>Technical details</summary><span>{currentDrain.engine}</span></details>
         </div>}
       </details>
       <details className="auto-parser-recipe" aria-label="Known log shape matcher">
         <summary className="beginner-tool-summary">Find a similar known log shape
           <HelpTip label="Find a similar known log shape"
             text="Use this when you are unsure what kind of log you pasted. Parser Studio compares field names and structure with safe built-in examples. It never applies a parser automatically."/>
         </summary>
         <span className="beginner-tool-when">Use when: the log looks unfamiliar and normal analysis has not given you a clear next step.</span>
         <p>This check compares only the shape and field names with reviewed example patterns.
           It does not send log values anywhere and does not change your parser.</p>
         <button type="button" disabled={busy||pending||!suite}
           onClick={findKnownTemplates}>Find Similar Known Shapes</button>
         <button type="button" disabled={busy||pending||!suite}
           onClick={()=>{void mineUnknownShapes();}}>Group Similar Unknown Shapes</button>
         {currentStructural&&<div role="status" aria-label="Similar-shape grouping results">
           <strong>{currentStructural.unknownCount} unfamiliar event{currentStructural.unknownCount===1?'':'s'} ·
             {currentStructural.groupedCount} placed into similar-shape groups</strong>
           {currentStructural.groups.map((group,i)=><span key={i}>
             Group {i+1}: {group.count} event{group.count===1?'':'s'}
           </span>)}
           <span>These groups are suggestions only. No parser rule was created or applied automatically.</span>
           <details><summary>Technical shape identifiers</summary>
             {currentStructural.groups.map((group,i)=><span key={i}>{group.fingerprint}</span>)}
           </details>
         </div>}
         {currentFingerprints&&<div role="status" aria-label="Known shape comparison results">
           <strong>{currentFingerprints.sourceCount} event{currentFingerprints.sourceCount===1?'':'s'} compared with known examples</strong>
           {currentFingerprints.hints.length===0&&
             <span>No close known shape was found. Nothing was changed.</span>}
           {currentFingerprints.hints.map(hint=><span key={hint.id}>
             Similar to {hint.label}: {hint.matchedFieldCount}/{hint.expectedFieldCount} expected field names were present consistently
           </span>)}
           <span>Use this only as a clue about the log family; review the actual extracted fields before continuing.</span>
         </div>}
       </details>
       {!advanced&&sample.trim()&&!currentMultiPassReview&&
         <p className="beginner-next-step" role="status">Analyze the logs first. Parser Studio will not create a parser from an unreviewed sample.</p>}
       {!advanced&&currentMultiPassReview&&!beginnerResolved&&
         <p className="beginner-next-step needs-fix" role="status">Resolve the events marked above before continuing. Already-correct fields remain preserved.</p>}
       {!advanced&&currentMultiPassReview&&beginnerResolved&&pending&&
         <p className="beginner-next-step" role="status">Source extraction is complete. Preparing the browser parser draft for field review…</p>}
       {currentReviewBlock&&<div className="auto-parser-warning" role="alert" aria-label="Parser draft not ready">
         <strong>Source fields are available, but this parser draft is not ready.</strong>
         <p>{statusMessage(currentReviewBlock.reason)}</p>
         <p>No source value was discarded. This is source extraction only; a downloadable parser and Stellar Cyber mapping are not yet verified for these original events.</p>
         <details><summary>Inspect extracted source fields (read-only)</summary>
           <p>These are original-source values. Choose field names and repeated-value policies before generating parser files.</p>
           {Object.entries(currentMultiPass?.fields??{}).slice(0,40).map(([name,value])=>
             <p key={name}><strong>{name}</strong>: {JSON.stringify(value).slice(0,180)}</p>)}
         </details>
         <button type="button" onClick={onChatGPT}>Use ChatGPT Assisted Parser</button>
         <button type="button" onClick={()=>setReviewBlock(null)}>Re-check parser support</button>
       </div>}
       <button type="button" className="auto-parser-primary"
         disabled={!canReview} onClick={()=>{void review();}}>
         {busy?'Checking the parser…':!advanced&&beginnerResolved&&pending?'Preparing Parser Draft…':advanced?'Review Detected Results':'Review Fields'} <ArrowRight size={16}/>
       </button>
     </section>}
     {step===1&&<section aria-label="Review Fields stage">
       <h2>Review Fields <HelpTip label="Review Fields"
         text="A field is one value Parser Studio found in the log, such as a source IP, username, action, or port. Check that the values were separated correctly before deciding their Stellar Cyber names."/></h2>
       <StageGuide title="What to do here">
         Pick a few events and check that the important values were found correctly. If they look right, continue to Map Fields. You do not need to edit parser syntax.
       </StageGuide>
       <p>Confirm the values Parser Studio found. You can adjust a field only when the detected result is not what you expect.</p>
       <div className="auto-parser-summary">
         <span>{advanced?'Browser events':'Log events'} <strong>{report.sourceCount}</strong></span>
         <span>Need review <strong>{report.unsupported}</strong></span>
         <span>{advanced?'Mapping rules':'Fields mapped'} <strong>{draft.mappings.length}</strong></span>
       </div>
       {report.events.some(event=>event.timePolicy==='YEAR_AND_ZONE_UNKNOWN')&&
         <p className="auto-parser-warning" role="note">
           This log's header does not include a year or timezone, so Parser Studio kept the time as text instead of guessing.
           Review the original time before mapping it to an event timestamp.
           <HelpTip label="Why was the time not converted?"
             text="Some older syslog headers contain only month, day, and clock time. Without a year and timezone, converting them to an exact timestamp could be wrong."/></p>}
       {!!currentReview?.mappingCount&&<p className="auto-parser-note">
         Parser Studio prepared {currentReview.mappingCount} starting field mapping{currentReview.mappingCount===1?'':'s'}.
         Review the actual values first; the next step will suggest Stellar Cyber field names.</p>}
       {currentReview?.requiresApproval&&<p className="auto-parser-note">
         Your edited field mappings were preserved. Check them below before generating.</p>}
       {namedAnalysis&&<NamedLogTypeReview data={namedAnalysis}/>}
       <SampleUnionReview suite={suite}/>
       <ReviewedEventProfilesPanel suite={suite} draft={draft} setDraft={setDraft}
         highlightNamed={Boolean(namedLogTypes&&namedLogTypes.length>1)}
         source={sample} pending={pending}
         backendCapabilities={capability?.source===sample?capability.value:undefined}/>
       <label>Choose a source event
         <select aria-label="Auto Parser review event" value={chosen?.id??''}
           onChange={e=>setSelected(Math.max(0,records.findIndex(x=>x.id===e.target.value)))}>
           {records.map((entry)=><option key={entry.id} value={entry.id}>
             Event {entry.line} · {friendlyEventStatus(entry.status)}</option>)}
         </select></label>
       <div className="stellar-review-columns">
       {chosen&&<div className="auto-parser-preview" aria-label="Browser-only event inspector">
         <div><h3>Original log</h3><pre>{chosen.raw}</pre></div>
         <div><h3>Fields Parser Studio found</h3><pre>{JSON.stringify(chosen.fields,null,2)}</pre></div>
         <div><h3>Current output preview <HelpTip label="Current output preview"
           text="This is only a local preview using the current field names. The next step lets you choose the Stellar Cyber field names before parser files are created."/></h3><pre>{JSON.stringify(chosen.normalized,null,2)}</pre></div>
       </div>}
       <details className="auto-parser-recipe" open={advanced}
         aria-label="Optional AI field correction">
         <summary>Need a different extraction? Fix a field with ChatGPT</summary>
         {chosen&&suite&&!pending?<AutoParserAIReview raw={chosen.raw} status={chosen.status} onChatGPT={onChatGPT} source={sample} draft={draft} suite={suite} onApplyCandidate={setDraft}
           protectedSourceValuesByEvent={protectedSourceValuesByEvent}
           protectedResidualTextByEvent={protectedResidualTextByEvent}/>:
          <div className="stellar-ai-review" role="status" aria-label="Improve with AI preview status">
            <p>Preparing the optional ChatGPT correction tools for this event.</p>
          </div>}
       </details>
       </div>
       <div className="auto-parser-note beginner-essential-note" aria-label="Normalization mapping handoff">
         <strong>Next: choose where each value belongs in Stellar Cyber</strong>
         <p>Continue to Map Fields. Parser Studio will suggest Stellar field names, show example values, and warn you if a value does not fit. Changing a mapping never deletes the original extracted value.</p>
       </div>
       {!!draft.guided?.enrichment?.length&&<div className="auto-parser-map-list" aria-label="Applied normalization refinements">
         {draft.guided.enrichment.map((rule,index)=><div key={rule.id}>
           <strong>{rule.operator==='split_field'?'Split':'Merge'} #{index+1}</strong>
           <span>{rule.operator==='split_field'
             ?`${rule.source} by ${JSON.stringify(rule.delimiter)} → ${(rule.targets??[]).join(', ')}`
             :`${(rule.sources??[]).join(' + ')} with ${JSON.stringify(rule.delimiter)} → ${rule.target}`}</span>
           <small>Reviewed field adjustment · no custom code required</small>
         </div>)}
       </div>}
       {pending&&<p className="beginner-next-step" role="status">
         Parsed fields are ready. Parser Studio is refreshing the local preview before the final test.
       </p>}
       <div className="auto-parser-actions">
         <button type="button" onClick={()=>setStep(0)}><ArrowLeft size={15}/> Back to Logs</button>
         <button type="button" className="auto-parser-primary" disabled={pending||!suite}
           onClick={()=>{setNavigationHint('');setFurthestStep(2);setStep(2);}}>
           {pending?'Preparing…':'Map Fields'} <ArrowRight size={16}/>
         </button>
       </div>
     </section>}
     {step===2&&<NormalizationMappingReview
       draft={draft} setDraft={setDraft} suite={suite}
       selected={selected} setSelected={setSelected} pending={pending}
       onBack={()=>setStep(1)} onContinue={()=>{setNavigationHint('');setFurthestStep(3);setStep(3);}}/>}
     {step===3&&<section aria-label="Create Parser stage">
       <h2>Create Parser <HelpTip label="Create Parser"
         text="This is the final local step. Parser Studio tests the current sample again and, if everything still passes, creates the files you can download. It does not install them automatically."/></h2>
       <StageGuide title="Final step">
         Run the final test, then download the parser files. If Parser Studio finds a problem, go back to Review Fields or Map Fields and correct only the item it highlights.
       </StageGuide>
       <p>Parser Studio will test every sample again before it creates downloadable files.
         Nothing is installed in a live Stellar system from this screen.</p>
       <div className="auto-parser-summary">
         <span>Sample logs <strong>{report.sourceCount}</strong></span>
         <span>Parsed successfully <strong>{suite?.counts.matched??0}</strong></span>
         <span>Ready to output <strong>{suite?.counts.normalized??0}</strong></span>
         <span>Need fixing <strong>{suite?.counts.failures??0}</strong></span>
       </div>
       {!confirmed()&&<p className="auto-parser-warning" role="note">
         Not all sample events passed. Review detected fields and mappings above
         before generating your parser.</p>}
       <button type="button" className="auto-parser-primary"
         aria-label="Create Parser Files"
         disabled={!canGenerate||!confirmed()} onClick={()=>{void generate();}}>
         {busy?'Testing every sample…':'Run Final Test & Create Files'}
       </button>
       {currentEvidence&&<div className="auto-parser-result" aria-label="Auto Parser test evidence">
         <strong>{currentEvidence.status==='PASS'?'All sample logs passed the final test':'Parser creation stopped'}</strong>
         <span>{currentEvidence.status==='PASS'
           ?`${currentEvidence.total} sample event${currentEvidence.total===1?'':'s'} tested successfully. Nothing has been deployed.`
           :'One or more sample logs still need review. No parser files were released.'}</span>
         {currentEvidence.issues.map((issue,i)=><span key={i}>{issue}</span>)}
         {advanced&&<small>
           Technical evidence: SHA/schema {currentEvidence.status} ·
           {currentNativeEvidence?.status==='PASS'?' Native verified':' Native not verified'} ·
           Stellar target import not verified.
         </small>}
       </div>}
       {currentPair&&<div className="auto-parser-download" aria-label="Generated parser files">
         <strong><CheckCircle2 size={17}/> Parser files created successfully</strong>
         <span>{currentNativeEvidence?.status==='PASS'
           ?'All current samples passed, and an additional local parser-file compatibility check passed. The files have not been installed in a live Stellar system.'
           :'All current samples passed. The files have not been installed in a live Stellar system.'}</span>
         <details className="auto-parser-recipe" aria-label="Parser file verification details">
           <summary>Technical verification details</summary>
           <span>File integrity checked · {currentNativeEvidence?.status==='PASS'?'Local parser-runtime check passed':'Local parser-runtime check not run'}</span>
           {advanced&&<span>Two generated files have matching recorded SHA-256 integrity evidence. Live Stellar import remains a separate test.</span>}
         </details>
         {currentPair.files.map(file=><button key={file.name} type="button"
           aria-label={file.name} onClick={()=>download(file.name,file.content)}>
           <FileText size={15}/>
           <span>{file.name.endsWith('.conf')?'Download listener configuration':'Download parser logic'}
             <small>{file.name}</small>
           </span>
           <Download size={15}/>
         </button>)}
         <button type="button" disabled={busy}
           onClick={()=>{void zipPair();}}><FileArchive size={16}/> Download Parser Package</button>
         {advanced&&currentZip&&<details className="beginner-technical-details">
           <summary>Package checksum</summary><small>ZIP SHA-256: {currentZip.sha256} · {currentZip.filename}</small>
         </details>}
       </div>}
       {currentPair&&<AutoParserLocalReplay sample={sample} draft={draft}/>}
       <details className="auto-parser-recipe" aria-label="Manual field fix test">
         <summary className="beginner-tool-summary">Test a manual field fix against different examples
           <HelpTip label="Test a manual field fix"
             text="Use this after you manually change a field mapping and want extra confidence that the change does not break other logs. Provide different examples that were not used to make the fix."/>
         </summary>
         <span className="beginner-tool-when">Use when: you changed a field mapping yourself and have fresh logs from the same source to test it against.</span>
         <p>Parser Studio compares one proposed field change with every current sample and with the different examples you provide.
           Nothing is applied automatically or uploaded to another service.</p>
         <label>Different examples not used to make the fix
           <HelpTip label="Different examples"
             text="These are fresh log events from the same product that were not part of the original sample. They help reveal a fix that works only for the examples you already saw."/>
           <textarea aria-label="Different example logs for field fix" rows={4}
             value={holdout} onChange={e=>{setHoldout(e.target.value);setRepair(null);setRepairNotice('');}}
             placeholder="Paste a few fresh events from the same source; kept in browser memory." />
         </label>
         <button type="button" disabled={busy||pending||!suite}
           onClick={()=>{void compareRepair();}}>Test One Proposed Field Fix</button>
         {repairNotice&&<p role="status">{repairNotice}</p>}
         {currentRepair&&<div aria-label="Proposed field fix comparison" role="status">
           <strong>{currentRepair.comparison.acceptedWithoutRegression&&currentRepair.comparison.holdoutStatus==='TESTED'
             ?'This field fix passed the current and different examples'
             :'Review this field fix before applying it'}</strong>
           <span>{currentRepair.source} → {currentRepair.target}</span>
           <span>Current sample: {currentRepair.comparison.baseline.accounted}/
             {currentRepair.comparison.baseline.sourceCount} checked ·
             Passed before {currentRepair.comparison.baseline.positiveBefore} ·
             Passed after {currentRepair.comparison.baseline.positiveAfter}</span>
           <span>Problems introduced by this fix: {currentRepair.comparison.baseline.regressions}</span>
           <span>Different examples: {currentRepair.comparison.holdoutStatus==='TESTED'?'tested':'not tested yet'} ·
             {currentRepair.comparison.holdout?.sourceCount??0} events ·
             {currentRepair.comparison.holdout?.regressions??0} problems introduced</span>
           <details className="beginner-technical-details"><summary>Technical comparison details</summary>
             <span>Added field shapes: {currentRepair.comparison.baseline.fieldAdditions} · Removed: {currentRepair.comparison.baseline.fieldRemovals} · Type changes: {currentRepair.comparison.baseline.typeChanges}</span>
             <span>Holdout status: {currentRepair.comparison.holdoutStatus}</span>
           </details>
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
             <p>Add different examples before applying this fix.</p>}
           {!currentRepair.comparison.acceptedWithoutRegression&&
             <p>This fix caused a previously working sample to fail, so Parser Studio will not apply it.</p>}
         </div>}
       </details>
       <details className="auto-parser-recipe" aria-label="Reusable approved field matches">
         <summary className="beginner-tool-summary">Reuse a field match you approved earlier
           <HelpTip label="Reuse an approved field match"
             text="Use this only when the same kind of log appears again and you previously chose a field match that worked. Parser Studio retests it before allowing reuse."/>
         </summary>
         <span className="beginner-tool-when">Use when: the same log family returns and you want to try a field match you previously approved.</span>
         <p>Only field names, value types, and anonymous test counts are stored in this browser.
           No raw log values are saved. Reused matches must pass the current sample and different examples again.</p>
         <label>Previously approved field match
           <select aria-label="Approved field match" value={selectedPattern}
             onChange={e=>setSelectedPattern(e.target.value)}>
             <option value="">Choose a saved mapping</option>
             {approvedPatterns.map(item=><option key={item.id} value={item.id}>
               {item.family}: {item.mapping.source} → {item.mapping.target}
             </option>)}
           </select>
         </label>
         <button type="button" disabled={!selectedPattern||busy||pending||!suite}
           onClick={()=>{void compareStoredPattern();}}>Test Saved Match with Different Examples</button>
         <button type="button" disabled={!selectedPattern||busy}
           onClick={()=>{
             if(!window.confirm('Forget the selected saved field match? This does not change current parser rules.'))return;
             if(forgetApprovedPattern(selectedPattern)){
               setApprovedPatterns(readApprovedPatterns());setSelectedPattern('');
             }else setRepairNotice('Unable to remove the selected saved field match.');
           }}>Forget Selected Match</button>
         <span>{approvedPatterns.length} approved field match{approvedPatterns.length===1?'':'es'} saved in this browser</span>
       </details>
       <div className="auto-parser-note" aria-label="Local review session metrics">
         Session-only review counts: {reviewMetrics.compared} compared ·
         {reviewMetrics.approved} user approved · {reviewMetrics.blocked} regression blocks.
         Not a measured human usability study; no telemetry or raw samples are sent.
       </div>
       <details className="auto-parser-recipe" aria-label="Parser-building steps review">
         <summary className="beginner-tool-summary">Inspect how Parser Studio will build the parser
           <HelpTip label="Parser-building steps"
             text="This is a technical troubleshooting view. Use it only when you need to inspect the internal sequence Parser Studio plans to use before creating the parser files."/>
         </summary>
         <span className="beginner-tool-when">Use when: you are troubleshooting parser generation or need technical evidence for the exact build steps. Normal users can skip this.</span>
         <p>This view checks the planned parser-building steps locally. It does not install the parser or prove that it works in a live Stellar system.</p>
         <button type="button" aria-label="Review Staged Recipe" disabled={busy||pending||!suite}
           onClick={()=>{void previewRecipe();}}>Inspect Parser-Building Steps</button>
         {currentRecipe&&(currentRecipe.ok
           ? <div role="status" aria-label="Parser-building steps">
             <strong>Parser-building steps are ready for technical review</strong>
             <span>{currentRecipe.recipe.stages.length} planned step{currentRecipe.recipe.stages.length===1?'':'s'} ·
               {currentRecipe.recipe.sample.events} sample event{currentRecipe.recipe.sample.events===1?'':'s'}</span>
             <p>{currentRecipe.recipe.stages.map(stage=>stage.op).join(' → ')}</p>
             <details className="beginner-technical-details"><summary>Technical evidence</summary>
               <span>REVIEW_ONLY · Native and target NOT VERIFIED</span>
               <span>Source SHA-256 {currentRecipe.recipe.sample.sha256.slice(0,12)}…</span>
               <span>v0.1 snapshot: {currentRecipe.lossReport.status} · v0.2 restricted compilation needs backend capability verification</span>
             </details>
             <button type="button" aria-label="Validate and Compile Strict v0.2 DRAFT Pair"
               disabled={!currentPair||busy||pending}
               onClick={()=>{void compileReviewedRecipe();}}>
               Validate These Build Steps
             </button>
             {!currentPair&&<span>Create the parser files first so Parser Studio can compare the exact generated result.</span>}
           </div>
           : <p role="status">Review cannot be generated safely: {statusMessage(currentRecipe.reason)}</p>)}
         {recipeCompilerError&&<p role="status">{recipeCompilerError}</p>}
         {currentRecipeCompiled&&<div role="status" aria-label="Parser-building step verification result">
           <strong>Parser-building steps matched the generated files</strong>
           <span>{currentRecipeCompiled.receipt.stageCount} build step{currentRecipeCompiled.receipt.stageCount===1?'':'s'} ·
             {currentRecipeCompiled.receipt.sampleEventCount} sample event{currentRecipeCompiled.receipt.sampleEventCount===1?'':'s'}</span>
           <details className="beginner-technical-details"><summary>Technical compiler evidence</summary>
             <span>v0.2 STRICT COMPILER PASS · v0.1 pair SHA MATCHED</span>
             <span>Recipe SHA-256 {currentRecipeCompiled.receipt.recipeSha256.slice(0,16)}… · Native user parser NOT VERIFIED by compiler receipt · Stellar DP import NOT VERIFIED</span>
           </details>
           <p>You can optionally run a private local compatibility check on the generated parser files. This still does not install anything in Stellar Cyber.</p>
           {nativeAvailability==='AVAILABLE'
             ? <button type="button" aria-label="Run private parser-file compatibility check"
                 disabled={busy||pending||!suite}
                 onClick={()=>{void verifyCurrentNativeProject();}}>
                 {busy?'Checking parser files…':'Run Private Parser-File Compatibility Check'}
               </button>
             : nativeAvailability==='UNAVAILABLE'
               ? <span>The private parser-file checker is not configured. You can still download the files after the normal sample test passes.</span>
               : nativeAvailability==='ERROR'
                 ? <span>Parser Studio could not verify the private parser-file checker. No compatibility result is claimed.</span>
                 : <span>Checking whether the private parser-file checker is available…</span>}
           {currentNativeEvidence&&<div className="auto-parser-result"
             aria-label="Private parser-file compatibility result">
             <strong>{currentNativeEvidence.status==='PASS'?
               'Private parser-file compatibility check passed':
               currentNativeEvidence.status==='UNAVAILABLE'?'Private parser-file checker unavailable':
               'Private parser-file compatibility check failed'}</strong>
             <span>{currentNativeEvidence.status==='PASS'
               ?'The generated files worked in the configured private local parser runtime. This still does not mean they were installed in Stellar Cyber.'
               :currentNativeEvidence.message}</span>
             {currentNativeEvidence.report&&<details className="beginner-technical-details">
               <summary>Technical runtime evidence</summary>
               <span>NATIVE RUBY/CONF VERIFIED · TARGET NOT VERIFIED</span>
               <span>{currentNativeEvidence.report.eventsPassed}/{currentNativeEvidence.report.eventCount} events exact · Ruby {currentNativeEvidence.report.ruby} · Fluentd {currentNativeEvidence.report.fluentd}</span>
               <span>Source/event hashes verified · CONF AST verified · Parser callback verified · Stellar DP target import NOT VERIFIED</span>
             </details>}
           </div>}
         </div>}
       </details>
       <p className="auto-parser-note"><LockKeyhole size={14}/> Parser Studio does not install or activate anything on a live Stellar system from this screen.
         {currentNativeEvidence?.status==='PASS'
           ?' The optional private parser-file compatibility check passed.'
           :' The optional private parser-file compatibility check has not established live-system compatibility.'}</p>
       <div className="auto-parser-actions">
         <button type="button" onClick={()=>setStep(2)}><ArrowLeft size={14}/> Map Fields</button>
         <button type="button" onClick={onChatGPT}>Ask ChatGPT for Unfamiliar Logs</button>
       </div>
     </section>}
     {message&&<p role="alert" className="auto-parser-warning"><ShieldAlert size={16}/> {message}</p>}
   </div>
 </main>;
}
