import {useEffect,useState} from 'react';
import {toSourceByteRange,fromSourceByteRange} from './sourceByteSelection';
import type {ParserDraft,SuiteResult} from '../model';
import {importRecoveryAIRecipe,importReviewOnlyAIRecipe,proposeV01EnrichmentFromAI,
 proposeV01FieldMappingFromAI,proposeV01MappingCorrectionFromAI,proposeV01RecoveryParserFromAI} from './aiRecipeExchange';
import {compareCandidate,compareMappingCorrectionCandidate} from './autoParserRegression';
import {buildReviewableRecipe} from './parserRecipeV2';
import {MAX_EVENTS,preview,splitEvents} from '../parser';
import {defaultGuidedOptions} from './contract';
import {sha256Utf8Hex} from '../sha256';
import {requestMultiPassBatchPreview,type MultiPassBatchPreview} from './multipassPreviewClient';

type HoldoutEvidenceRequester=(source:string)=>Promise<MultiPassBatchPreview>;
interface Props {raw:string;status:string;onChatGPT:()=>void;source?:string;draft?:ParserDraft;suite?:SuiteResult;initialByteRange?:{startByte:number;endByte:number}|null;selectionContext?:{kind:'field'|'residual';path?:string};onApplyCandidate?:(draft:ParserDraft)=>void;importOnly?:boolean;protectedSourceValuesByEvent?:string[][];protectedResidualTextByEvent?:string[][];holdoutEvidenceRequester?:HoldoutEvidenceRequester}
const completeSuite=(value:SuiteResult)=>value.counts.total>0&&value.counts.matched===value.counts.total&&
 value.counts.extracted===value.counts.total&&value.counts.normalized===value.counts.total&&value.counts.failures===0;
function scalarValues(value:unknown):string[]{
 if(value===null)return ['null'];
 if(Array.isArray(value))return value.flatMap(scalarValues);
 if(typeof value==='object'&&value!==null)return Object.values(value as Record<string,unknown>).flatMap(scalarValues);
 return value===undefined?[]:[String(value)];
}
function sourceAlternatives(value:string):string[]{
 const out=[value];
 if(value.length>=2&&value[0]==='\"'&&value.at(-1)==='\"'){
  try{const parsed=JSON.parse(value);if(typeof parsed==='string')out.push(parsed);}catch{/* keep exact source */}
 }else if(value.length>=2&&value[0]==="'"&&value.at(-1)==="'")out.push(value.slice(1,-1));
 return [...new Set(out)];
}
function containsExactSourceRaw(value:unknown,raw:string,depth=0):boolean{
 if(depth>8||value===null||value===undefined)return false;
 if(Array.isArray(value))return value.some(item=>containsExactSourceRaw(item,raw,depth+1));
 if(typeof value!=='object')return false;
 const record=value as Record<string,unknown>;
 if(Object.prototype.hasOwnProperty.call(record,'source_raw')&&record.source_raw===raw)return true;
 return Object.values(record).some(item=>containsExactSourceRaw(item,raw,depth+1));
}
function hasLosslessSourceProjection(event:SuiteResult['events'][number]|undefined):boolean{
 if(!event)return false;
 const projection=event.normalized?.parserstudio_source;
 return projection!==undefined&&containsExactSourceRaw(projection,event.raw);
}
function protectedValueRegression(candidate:SuiteResult,protectedValues:string[][]|undefined,
 normalizedOnly=false):{event:number;missing:number;required:number;available:number}|null{
 if(!protectedValues?.some(values=>values.length))return null;
 for(let index=0;index<protectedValues.length;index++){
  const observed=protectedValues[index]??[];
  // The backend's reviewed normalization contract intentionally ignores an
  // explicit empty string. Do not make FULL_RECOVERY impossible by requiring
  // JSON "" / '' source spans to reappear in final normalized output.
  const required=normalizedOnly?
   observed.filter(source=>!sourceAlternatives(source).includes('')):observed;
  if(!required.length)continue;
  const event=candidate.events[index];
  if(normalizedOnly&&hasLosslessSourceProjection(event))continue;
  const pool=normalizedOnly?scalarValues(event?.normalized):
   [...scalarValues(event?.fields),...scalarValues(event?.normalized)];
  const used=new Array(pool.length).fill(false);let missing=0;
  for(const source of required){
   const choices=sourceAlternatives(source);let found=-1;
   for(let i=0;i<pool.length;i++)if(!used[i]&&choices.includes(pool[i]!)){found=i;break;}
   if(found<0)missing++;else used[found]=true;
  }
  if(missing)return {event:index+1,missing,required:required.length,available:pool.length};
 }
 return null;
}
function protectedResidualRegression(candidate:SuiteResult,protectedResiduals:string[][]|undefined):
 {event:number;missing:number;required:number}|null{
 if(!protectedResiduals?.some(values=>values.length))return null;
 for(let index=0;index<protectedResiduals.length;index++){
  const required=(protectedResiduals[index]??[]).map(value=>value.trim()).filter(Boolean);
  if(!required.length)continue;
  // Recovery residuals must survive into the final parser output, not only
  // an intermediate extraction object that normalization can discard.
  const event=candidate.events[index];
  if(hasLosslessSourceProjection(event))continue;
  const pool=scalarValues(event?.normalized);
  let missing=0;
  for(const residual of required){
   if(!pool.some(value=>value.includes(residual)))missing++;
  }
  if(missing)return {event:index+1,missing,required:required.length};
 }
 return null;
}

function multiPassProtection(source:string,batch:MultiPassBatchPreview):{
 values:string[][];residuals:string[][];
}{
 const bytes=new TextEncoder().encode(source);
 const decoder=new TextDecoder('utf-8',{fatal:true});
 const decode=(startByte:number,endByte:number)=>decoder.decode(bytes.slice(startByte,endByte));
 return {
  values:batch.events.map(event=>event.preview.spans
   .filter(span=>span.endByte>span.startByte)
   .map(span=>decode(event.startByte+span.startByte,event.startByte+span.endByte))),
  residuals:batch.events.map(event=>event.preview.residuals
   .filter(region=>region.endByte>region.startByte)
   .map(region=>decode(event.startByte+region.startByte,event.startByte+region.endByte))
   .filter(text=>text.trim().length>0)),
 };
}

export default function AutoParserAIReview({raw,status,onChatGPT,source,draft,suite,initialByteRange,selectionContext,onApplyCandidate,importOnly=false,protectedSourceValuesByEvent,protectedResidualTextByEvent,holdoutEvidenceRequester}:Props){
 const [mode,setMode]=useState<'entire'|'selection'>(status==='unsupported'?'entire':'selection');
 const [range,setRange]=useState<[number,number]>([0,0]);
 const [goal,setGoal]=useState('');
 const [reviewedExcerpt,setReviewedExcerpt]=useState('');
 const [approved,setApproved]=useState(false);
 const [notice,setNotice]=useState('');
 const [recipeText,setRecipeText]=useState('');
 const [importResult,setImportResult]=useState('');
 const [importBusy,setImportBusy]=useState(false);
 const [holdout,setHoldout]=useState('');
 const [holdoutAttested,setHoldoutAttested]=useState(false);
 const [approvedCandidate,setApprovedCandidate]=useState<{draft:ParserDraft;mode:'mapping'|'correction'|'enrichment'|'recovery';scope?:{oldTarget:string;newTarget:string};holdoutProtectedValues?:string[][];holdoutProtectedResiduals?:string[][]}|null>(null);
 const [approval,setApproval]=useState(false);
 const [validatedEvidence,setValidatedEvidence]=useState('');
 const evidenceFingerprint=()=>JSON.stringify([source??'',draft??null,holdout,recipeText]);
 useEffect(()=>{
  const initial=initialByteRange?fromSourceByteRange(raw,initialByteRange.startByte,initialByteRange.endByte):null;
  setRange(initial??[0,0]);setReviewedExcerpt('');setApproved(false);setNotice('');setRecipeText('');setImportResult('');setApprovedCandidate(null);setApproval(false);setHoldoutAttested(false);setValidatedEvidence('');
  setMode(initial?'selection':status==='unsupported'?'entire':'selection');
 },[raw,status,initialByteRange?.startByte,initialByteRange?.endByte,selectionContext?.kind,selectionContext?.path]);
 const sourceRange=toSourceByteRange(raw,range[0],range[1]);
 const excerpt=mode==='entire'?raw:(sourceRange?.text??'');
 const canCopy=approved&&!!reviewedExcerpt.trim()&&!!goal.trim()&&!!excerpt.trim();
 async function prompt(){
  const lines=[
   'Parser Studio — source extraction assistance (review-only).',
   'Return a proposed ParserRecipe v0.2 JSON object. A parse_regex stage is allowed only for a bounded named-capture pattern; do not return executable Ruby, Grok, scripting or arbitrary/unbounded Regex.',
   'Do not invent missing values, do not overwrite correct fields, and preserve the original event.',
   `Scope: ${mode==='entire'?'entire unsupported event':'only the selected source range'}.`,
   `Selection context: ${mode==='entire'?'full-log fallback':selectionContext?.kind==='field'?`currently extracted field ${selectionContext.path??'UNKNOWN'}`:selectionContext?.kind==='residual'?'unparsed residual region':'manual source selection'}.`,
   `Source UTF-8 byte range: ${mode==='entire'?`0–${new TextEncoder().encode(raw).byteLength}`:`${sourceRange?.startByte??'UNSELECTED'}–${sourceRange?.endByte??'UNSELECTED'}`}.`,
   `Requested correction: ${goal.trim()}`,
  ];
  if(source&&draft&&suite){
   const baseline=await buildReviewableRecipe(source,draft,suite);
   if(baseline.ok){
    lines.push('Preserve every unrelated stage and mapping in this canonical current recipe. Change only what the requested correction requires.',
     'BEGIN CANONICAL PARSER RECIPE',JSON.stringify(baseline.recipe,null,2),'END CANONICAL PARSER RECIPE');
   }else{
    const hash=await sha256Utf8Hex(source);
    const boundary=draft.guided?.eventBoundary??'single-line';
    const records=splitEvents(source,boundary,MAX_EVENTS+1);
    const opts=draft.guided??defaultGuidedOptions();
    lines.push('No compiler-ready baseline exists. A FULL_RECOVERY recipe is allowed only for a supported declarative grammar.',
     `Recovery identity: projectId=draft-${opts.slug}; sourceSha256=${hash}; events=${records.length}.`,
     'Supported recovery grammars are JSON, strict key/value, explicit-column CSV, CEF, LEEF, bounded RFC3164/RFC5424 bodies, allowlisted mixed families, bounded Java stack traces, and bounded named-capture Regex for otherwise unresolved one-line text.',
     'If a Regex is required, use parse_regex with a pattern no longer than 256 visible characters, at least one named capture, and no backreferences/lookbehind/unsafe nested repetition. Grok, scripting, executable Ruby and guessed semantics remain unsupported.');
   }
  }
  lines.push('User-reviewed excerpt follows (may contain sensitive source values):',
   'BEGIN REVIEWED SOURCE',reviewedExcerpt,'END REVIEWED SOURCE',
   'Explain uncertainty, candidate field names, and how to test positive/negative cases before approval.');
  return lines.join('\n');
 }
 async function copyPrompt(){
  if(!canCopy)return;
  try{await navigator.clipboard.writeText(await prompt());setNotice('Reviewed prompt copied. Paste it into ChatGPT manually.');}
  catch{setNotice('Clipboard unavailable. No log data was transferred.');}
 }
 async function reviewImport(){
  if(!source||!draft||!suite||!recipeText.trim()||importBusy)return;
  setImportBusy(true);setImportResult('');setApprovedCandidate(null);setApproval(false);
  try{
   let result=await importReviewOnlyAIRecipe(recipeText,source,draft,suite);
   if(!result.ok&&result.reason==='CURRENT_RECIPE_UNAVAILABLE')
    result=await importRecoveryAIRecipe(recipeText,source,draft,suite);
   if(!result.ok){setImportResult(`ChatGPT result rejected: ${result.reason}. No changes were made.`);return;}
   let proposal:{ok:true;candidate:ParserDraft}|{ok:false;reason:string};
   let candidateMode:'mapping'|'correction'|'enrichment'|'recovery';
   let correctionScope:{oldTarget:string;newTarget:string}|undefined;
   if(result.report.mode==='FULL_RECOVERY'){
    proposal=proposeV01RecoveryParserFromAI(result,draft);candidateMode='recovery';
   }else{
    const additive=proposeV01FieldMappingFromAI(result,source,draft,suite);
    if(additive.ok){proposal=additive;candidateMode='mapping';}
    else{
     const correction=proposeV01MappingCorrectionFromAI(result,source,draft,suite);
     if(correction.ok){proposal=correction;candidateMode='correction';
      correctionScope={oldTarget:correction.oldTarget,newTarget:correction.newTarget};}
     else{proposal=proposeV01EnrichmentFromAI(result,source,draft,suite);candidateMode='enrichment';}
    }
   }
   if(!proposal.ok){setImportResult(`This ChatGPT result cannot be safely turned into a parser fix: ${proposal.reason}. No changes were made.`);return;}
   if(!holdout.trim()){setImportResult('Add different test log examples before applying this fix. No parser rules were changed.');return;}
   if(!holdoutAttested){setImportResult('Confirm that the additional test logs are different from the examples used to create this fix. No parser rules were changed.');return;}
   let report:ReturnType<typeof compareCandidate>;
   let candidateSuite:SuiteResult,candidateHoldout:SuiteResult;
   let holdoutProtectedValues:string[][]|undefined;
   let holdoutProtectedResiduals:string[][]|undefined;
   try{
    candidateSuite=preview(source,proposal.candidate);candidateHoldout=preview(holdout,proposal.candidate);
    const protectedRegression=protectedValueRegression(candidateSuite,protectedSourceValuesByEvent,
     candidateMode==='recovery');
    if(protectedRegression){
     const location=candidateMode==='recovery'?'final parser output':'reviewed extraction';
     setImportResult(`Fix not applied: event ${protectedRegression.event} would drop ${protectedRegression.missing} of ${protectedRegression.required} source value occurrences from the ${location}. No changes were made.`);return;
    }
    const residualRegression=candidateMode==='recovery'?
     protectedResidualRegression(candidateSuite,protectedResidualTextByEvent):null;
    if(residualRegression){
     setImportResult('Fix not applied: event '+residualRegression.event+' would leave '+residualRegression.missing+' of '+residualRegression.required+' previously unparsed source regions outside the final parser output. Preserve the remaining source text before applying the fix.');return;
    }
    const requireFunnelHoldout=candidateMode==='recovery'&&
     (protectedSourceValuesByEvent!==undefined||protectedResidualTextByEvent!==undefined);
    if(requireFunnelHoldout){
     try{
      const batch=await (holdoutEvidenceRequester??requestMultiPassBatchPreview)(holdout);
      const evidence=multiPassProtection(holdout,batch);
      holdoutProtectedValues=evidence.values;holdoutProtectedResiduals=evidence.residuals;
     }catch{
      setImportResult('Fix not applied: the additional test logs could not be verified by the local Multi-Pass source engine. No changes were made.');return;
     }
     const holdoutValueRegression=protectedValueRegression(candidateHoldout,holdoutProtectedValues,true);
     if(holdoutValueRegression){
      setImportResult('Fix not applied: holdout event '+holdoutValueRegression.event+' would drop '+holdoutValueRegression.missing+' of '+holdoutValueRegression.required+' Funnel source value occurrences from the final parser output. No changes were made.');return;
     }
     const holdoutResidualRegression=protectedResidualRegression(candidateHoldout,holdoutProtectedResiduals);
     if(holdoutResidualRegression){
      setImportResult('Fix not applied: holdout event '+holdoutResidualRegression.event+' would leave '+holdoutResidualRegression.missing+' of '+holdoutResidualRegression.required+' Funnel residual source regions outside the final parser output. No changes were made.');return;
     }
    }
    const comparisonInput={source,baseline:suite,candidate:candidateSuite,
     holdout:{source:holdout,baseline:preview(holdout,draft),candidate:candidateHoldout}};
    report=candidateMode==='correction'&&correctionScope?
     compareMappingCorrectionCandidate(comparisonInput,correctionScope):compareCandidate(comparisonInput);
   }catch{
    setImportResult('The logs or ChatGPT result changed while testing. Test the fix again before applying it.');return;
   }
   if(report.holdoutStatus==='REJECTED'){
    const reason=report.holdoutIndependence?.ok===false?report.holdoutIndependence.reason:'TOO_SMALL';
    const detail=reason==='IDENTICAL_TO_TRAINING'?'the additional test logs are identical to the original examples':
      reason==='TRAINING_OVERLAP'?'the additional test logs reuse original examples':'more unique additional test logs are needed';
    setImportResult(`Fix not applied: ${detail}. No changes were made.`);return;
   }
   if(!report.acceptedWithoutRegression||report.holdoutStatus!=='TESTED'||
      !completeSuite(candidateSuite)||!completeSuite(candidateHoldout)){
    setImportResult('The proposed fix did not pass both the original logs and the additional test logs. No parser rules were changed.');return;
   }
   setApprovedCandidate({draft:proposal.candidate,mode:candidateMode,scope:correctionScope,holdoutProtectedValues,holdoutProtectedResiduals});setValidatedEvidence(evidenceFingerprint());
   const description=candidateMode==='recovery'?'full parser recovery':candidateMode==='correction'?'one corrected mapping':candidateMode==='enrichment'?'one bounded split/merge rule':'one added mapping';
   setImportResult(`Fix passed: ${description}; ${report.holdout?.sourceCount??0} additional test log${(report.holdout?.sourceCount??0)===1?'':'s'} checked with no regressions. Ready to apply.`);
  }catch{setImportResult('Parser Studio could not test the ChatGPT result. No changes were made.');}
  finally{setImportBusy(false);}
 }
 const importPanel=<><details className="stellar-ai-import" open={importOnly}>
   <summary>Paste ChatGPT Result</summary>
   <label className="stellar-ai-label" htmlFor="stellar-ai-recipe">ChatGPT JSON result</label>
   <textarea id="stellar-ai-recipe" aria-label="ChatGPT JSON result" rows={5} maxLength={32768}
    value={recipeText} onChange={e=>{setRecipeText(e.target.value);setImportResult('');setApprovedCandidate(null);setApproval(false);setHoldoutAttested(false);setValidatedEvidence('');}}/>
   <label className="stellar-ai-label" htmlFor="stellar-ai-holdout">Additional test logs (use different examples)</label>
   <textarea id="stellar-ai-holdout" aria-label="Additional test logs" rows={3} maxLength={65536}
    value={holdout} onChange={e=>{setHoldout(e.target.value);setHoldoutAttested(false);setApprovedCandidate(null);setApproval(false);setValidatedEvidence('');setImportResult('');}}/>
   <label className="stellar-ai-consent"><input type="checkbox" aria-label="Confirm different test examples"
    checked={holdoutAttested} onChange={e=>{setHoldoutAttested(e.target.checked);setApprovedCandidate(null);setApproval(false);setValidatedEvidence('');}}/>
    These are different log examples from the ones used to create this fix.</label>
   <button type="button" aria-label="Test Proposed Fix"
    disabled={!source||!draft||!suite||!recipeText.trim()||importBusy}
    onClick={()=>void reviewImport()}>Test Proposed Fix</button>
   {importResult&&<p role="status">{importResult}</p>}
   {approvedCandidate&&<div className="stellar-ai-approval">
    <label><input type="checkbox" aria-label="Approve tested fix" checked={approval} onChange={e=>setApproval(e.target.checked)}/>
      I reviewed the tested result and approve applying this fix. Existing unrelated fields and rules must remain unchanged.</label>
    <button type="button" onClick={()=>{
     setApprovedCandidate(null);setApproval(false);setValidatedEvidence('');
     setImportResult('Fix discarded. Existing parser rules remain unchanged.');
    }}>Discard Fix</button>
    <button type="button" disabled={!approval||!onApplyCandidate} onClick={()=>{
     if(!approval||!approvedCandidate||!onApplyCandidate||!source||!draft||!suite)return;
     if(!holdoutAttested||validatedEvidence!==evidenceFingerprint()){
      setApprovedCandidate(null);setApproval(false);setValidatedEvidence('');
      setImportResult('The logs or ChatGPT result changed after testing. Test the fix again before applying it.');return;
     }
     try{
      const candidateSuite=preview(source,approvedCandidate.draft),candidateHoldout=preview(holdout,approvedCandidate.draft);
      const protectedRegression=protectedValueRegression(candidateSuite,protectedSourceValuesByEvent,
       approvedCandidate.mode==='recovery');
      if(protectedRegression){
       setApprovedCandidate(null);setApproval(false);setValidatedEvidence('');
       const location=approvedCandidate.mode==='recovery'?'final parser output':'reviewed extraction';
       setImportResult(`The fix is no longer safe: event ${protectedRegression.event} would drop ${protectedRegression.missing} of ${protectedRegression.required} source value occurrences from the ${location}. No changes were made.`);return;
      }
      const residualRegression=approvedCandidate.mode==='recovery'?
       protectedResidualRegression(candidateSuite,protectedResidualTextByEvent):null;
      if(residualRegression){
       setApprovedCandidate(null);setApproval(false);setValidatedEvidence('');
       setImportResult('The fix is no longer safe: event '+residualRegression.event+' would leave '+residualRegression.missing+' of '+residualRegression.required+' previously unparsed source regions outside the candidate fields. No changes were made.');return;
      }
      const holdoutValueRegression=approvedCandidate.mode==='recovery'?
       protectedValueRegression(candidateHoldout,approvedCandidate.holdoutProtectedValues,true):null;
      if(holdoutValueRegression){
       setApprovedCandidate(null);setApproval(false);setValidatedEvidence('');
       setImportResult('The fix is no longer safe: holdout event '+holdoutValueRegression.event+' would drop '+holdoutValueRegression.missing+' of '+holdoutValueRegression.required+' Funnel source value occurrences from the final parser output. No changes were made.');return;
      }
      const holdoutResidualRegression=approvedCandidate.mode==='recovery'?
       protectedResidualRegression(candidateHoldout,approvedCandidate.holdoutProtectedResiduals):null;
      if(holdoutResidualRegression){
       setApprovedCandidate(null);setApproval(false);setValidatedEvidence('');
       setImportResult('The fix is no longer safe: holdout event '+holdoutResidualRegression.event+' would leave '+holdoutResidualRegression.missing+' of '+holdoutResidualRegression.required+' Funnel residual source regions outside the final parser output. No changes were made.');return;
      }
      const recheckInput={source,baseline:suite,candidate:candidateSuite,
       holdout:{source:holdout,baseline:preview(holdout,draft),candidate:candidateHoldout}};
      const recheck=approvedCandidate.mode==='correction'&&approvedCandidate.scope?
       compareMappingCorrectionCandidate(recheckInput,approvedCandidate.scope):compareCandidate(recheckInput);
      if(!recheck.acceptedWithoutRegression||recheck.holdoutStatus!=='TESTED'||
         !completeSuite(candidateSuite)||!completeSuite(candidateHoldout)){
       setApprovedCandidate(null);setApproval(false);setValidatedEvidence('');
       setImportResult('The fix no longer passes the final check. No changes were made.');return;
      }
     }catch{
      setApprovedCandidate(null);setApproval(false);setValidatedEvidence('');
      setImportResult('The logs changed during the final check. Test the fix again before applying it.');return;
     }
     onApplyCandidate(approvedCandidate.draft);setApprovedCandidate(null);setApproval(false);setValidatedEvidence('');
     setImportResult('Fix applied to the parser draft. Continue to Review Fields, then create the parser.');
    }} aria-label="Apply Verified Fix">
      Apply Verified Fix
    </button>
   </div>}
  </details></>;
 if(importOnly)return <aside className="stellar-ai-review beginner-ai-result-review" aria-label="AI result verification">
  <h3>Paste ChatGPT Result</h3>
  <p>Paste the JSON returned by ChatGPT. Parser Studio will test it against the current logs and additional examples before anything changes.</p>
  {importPanel}
  <small>No changes are made until the tests pass and you approve the fix.</small>
 </aside>;
 return <aside className="stellar-ai-review" aria-label="Improve with AI">
  <h3>Improve with AI</h3>
  <p>Use AI only where the automatic parser needs help. No log data is sent automatically.</p>
  <div className="stellar-ai-tabs" role="group" aria-label="AI recovery scope">
   <button type="button" aria-pressed={mode==='entire'} onClick={()=>{setMode('entire');setReviewedExcerpt('');setApproved(false);}}>Entire Log</button>
   <button type="button" aria-pressed={mode==='selection'} onClick={()=>{setMode('selection');setReviewedExcerpt('');setApproved(false);}}>Selected Area</button>
  </div>
  <label className="stellar-ai-label">{mode==='entire'?'Review the entire log before copying':'Select exact source text below'}</label>
  {mode==='selection'&&<textarea aria-label="Select source text for AI correction" readOnly spellCheck={false} rows={5} value={raw}
   onSelect={e=>{const el=e.currentTarget;setRange([el.selectionStart,el.selectionEnd]);setReviewedExcerpt('');setApproved(false);}}/>}
  {mode==='selection'&&sourceRange&&<p role="status">UTF-8 bytes {sourceRange.startByte}–{sourceRange.endByte}</p>}
  {mode==='selection'&&selectionContext&&<p className="stellar-selected-source">
    {selectionContext.kind==='field'?`Editing extracted field: ${selectionContext.path??'Unknown field'}. Accepted fields outside this exact range are preserved.`:'Editing an unparsed source region. Accepted fields outside this exact range are preserved.'}
  </p>}
  <div className="stellar-ai-excerpt" aria-live="polite">{excerpt||'Select a portion of the source log to repair.'}</div>
  <label className="stellar-ai-label" htmlFor="stellar-ai-reviewed">Redact the excerpt before sharing with AI</label>
  <textarea id="stellar-ai-reviewed" aria-label="Reviewed and redacted AI excerpt" rows={4} maxLength={65536}
   value={reviewedExcerpt} onChange={e=>{setReviewedExcerpt(e.target.value);setApproved(false);}}
   placeholder="Paste only reviewed, redacted source text here. Nothing is sent automatically."/>
  <label className="stellar-ai-label" htmlFor="stellar-ai-goal">What should be extracted or corrected?</label>
  <textarea id="stellar-ai-goal" aria-label="AI correction request" rows={3} maxLength={500} value={goal}
   onChange={e=>{setGoal(e.target.value);setApproved(false);}} placeholder="For example: split the selected source address into IP and port."/>
  <label className="stellar-ai-consent"><input type="checkbox" aria-label="Confirm reviewed AI excerpt" checked={approved} onChange={e=>setApproved(e.target.checked)}/>
   I reviewed the editable excerpt and removed sensitive information before copying.</label>
  <div className="stellar-ai-actions">
   <button type="button" className="stellar-ai-primary" disabled={!canCopy} onClick={()=>void copyPrompt()}>Copy AI Prompt</button>
   <button type="button" onClick={onChatGPT}>Open Assisted Parser</button>
  </div>
  {notice&&<p role="status">{notice}</p>}
  {importPanel}
  <small>ChatGPT suggestions cannot change the parser until the fix passes the additional test logs and you approve it.</small>
 </aside>;
}
