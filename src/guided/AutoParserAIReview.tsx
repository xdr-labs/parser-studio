import {useEffect,useState} from 'react';
import {toSourceByteRange,fromSourceByteRange} from './sourceByteSelection';
import type {ParserDraft,SuiteResult} from '../model';
import {importRecoveryAIRecipe,importReviewOnlyAIRecipe,proposeV01FieldMappingFromAI,
 proposeV01MappingCorrectionFromAI,proposeV01RecoveryParserFromAI} from './aiRecipeExchange';
import {compareCandidate} from './autoParserRegression';
import {buildReviewableRecipe} from './parserRecipeV2';
import {MAX_EVENTS,preview,splitEvents} from '../parser';
import {defaultGuidedOptions} from './contract';

interface Props {raw:string;status:string;onChatGPT:()=>void;source?:string;draft?:ParserDraft;suite?:SuiteResult;initialByteRange?:{startByte:number;endByte:number}|null;selectionContext?:{kind:'field'|'residual';path?:string};onApplyCandidate?:(draft:ParserDraft)=>void}
const completeSuite=(value:SuiteResult)=>value.counts.total>0&&value.counts.matched===value.counts.total&&
 value.counts.extracted===value.counts.total&&value.counts.normalized===value.counts.total&&value.counts.failures===0;
export default function AutoParserAIReview({raw,status,onChatGPT,source,draft,suite,initialByteRange,selectionContext,onApplyCandidate}:Props){
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
 const [approvedCandidate,setApprovedCandidate]=useState<{draft:ParserDraft;mode:'mapping'|'correction'|'recovery'}|null>(null);
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
   'Return a proposed ParserRecipe v0.2 JSON object; do not return executable Ruby, arbitrary Regex or code.',
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
   }else if(globalThis.crypto?.subtle){
    const digest=await crypto.subtle.digest('SHA-256',new TextEncoder().encode(source));
    const hash=[...new Uint8Array(digest)].map(value=>value.toString(16).padStart(2,'0')).join('');
    const boundary=draft.guided?.eventBoundary??'single-line';
    const records=splitEvents(source,boundary,MAX_EVENTS+1);
    const opts=draft.guided??defaultGuidedOptions();
    lines.push('No compiler-ready baseline exists. A FULL_RECOVERY recipe is allowed only for a supported declarative grammar.',
     `Recovery identity: projectId=draft-${opts.slug}; sourceSha256=${hash}; events=${records.length}.`,
     'Supported recovery grammars are JSON, strict key/value, explicit-column CSV, CEF, LEEF, bounded RFC3164/RFC5424 bodies, allowlisted mixed families, and bounded Java stack traces.',
     'If arbitrary Regex, Grok, scripting, or guessed semantics are required, explain that it is unsupported instead of inventing a recipe.');
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
   if(!result.ok){setImportResult(`Rejected AI proposal: ${result.reason}. No rules were applied.`);return;}
   let proposal:{ok:true;candidate:ParserDraft}|{ok:false;reason:string};
   let candidateMode:'mapping'|'correction'|'recovery';
   if(result.report.mode==='FULL_RECOVERY'){
    proposal=proposeV01RecoveryParserFromAI(result,draft);candidateMode='recovery';
   }else{
    const additive=proposeV01FieldMappingFromAI(result,source,draft,suite);
    if(additive.ok){proposal=additive;candidateMode='mapping';}
    else{proposal=proposeV01MappingCorrectionFromAI(result,source,draft,suite);candidateMode='correction';}
   }
   if(!proposal.ok){setImportResult(`REVIEW ONLY: ${result.report.changedStageCount} changes. No safely compilable parser candidate: ${proposal.reason}.`);return;}
   if(!holdout.trim()){setImportResult('Independent holdout sample required before approval. No rules were applied.');return;}
   if(!holdoutAttested){setImportResult('Confirm that the holdout events were not used to create or tune this AI proposal. No rules were applied.');return;}
   let report:ReturnType<typeof compareCandidate>;
   let candidateSuite:SuiteResult,candidateHoldout:SuiteResult;
   try{
    candidateSuite=preview(source,proposal.candidate);candidateHoldout=preview(holdout,proposal.candidate);
    report=compareCandidate({source,baseline:suite,candidate:candidateSuite,
     holdout:{source:holdout,baseline:preview(holdout,draft),candidate:candidateHoldout}});
   }catch{
    setImportResult('Candidate rejected: training or holdout evidence is stale, reordered, or mutated. Re-run validation from the current sample.');return;
   }
   if(report.holdoutStatus==='REJECTED'){
    const reason=report.holdoutIndependence?.ok===false?report.holdoutIndependence.reason:'TOO_SMALL';
    const detail=reason==='IDENTICAL_TO_TRAINING'?'holdout is identical to the training sample':
      reason==='TRAINING_OVERLAP'?'holdout contains training events':'holdout has too few unique independent events';
    setImportResult(`Candidate rejected: ${detail}. No rules were applied.`);return;
   }
   if(!report.acceptedWithoutRegression||report.holdoutStatus!=='TESTED'||
      !completeSuite(candidateSuite)||!completeSuite(candidateHoldout)){
    setImportResult('Candidate rejected: full training/holdout parsing or regression verification failed. No rules were applied.');return;
   }
   setApprovedCandidate({draft:proposal.candidate,mode:candidateMode});setValidatedEvidence(evidenceFingerprint());
   const description=candidateMode==='recovery'?'full parser recovery':candidateMode==='correction'?'one corrected mapping':'one added mapping';
   setImportResult(`Ready for explicit approval: ${description}, 0 training/holdout regressions; ${report.holdout?.sourceCount??0} independent holdout events tested. Browser-only; native verification pending.`);
  }catch{setImportResult('AI proposal validation unavailable. No rules were applied.');}
  finally{setImportBusy(false);}
 }
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
  <details className="stellar-ai-import">
   <summary>Paste AI Recipe for strict review</summary>
   <label className="stellar-ai-label" htmlFor="stellar-ai-recipe">ParserRecipe v0.2 JSON proposal</label>
   <textarea id="stellar-ai-recipe" aria-label="AI Recipe JSON" rows={5} maxLength={32768}
    value={recipeText} onChange={e=>{setRecipeText(e.target.value);setImportResult('');setApprovedCandidate(null);setApproval(false);setHoldoutAttested(false);setValidatedEvidence('');}}/>
   <label className="stellar-ai-label" htmlFor="stellar-ai-holdout">Independent holdout logs (required)</label>
   <textarea id="stellar-ai-holdout" aria-label="AI candidate holdout logs" rows={3} maxLength={65536}
    value={holdout} onChange={e=>{setHoldout(e.target.value);setHoldoutAttested(false);setApprovedCandidate(null);setApproval(false);setValidatedEvidence('');setImportResult('');}}/>
   <label className="stellar-ai-consent"><input type="checkbox" aria-label="Confirm independent AI holdout provenance"
    checked={holdoutAttested} onChange={e=>{setHoldoutAttested(e.target.checked);setApprovedCandidate(null);setApproval(false);setValidatedEvidence('');}}/>
    I confirm these holdout events were not used to create, tune, or select this AI proposal.</label>
   <button type="button" disabled={!source||!draft||!suite||!recipeText.trim()||importBusy}
    onClick={()=>void reviewImport()}>Validate Proposal (Review Only)</button>
   {importResult&&<p role="status">{importResult}</p>}
   {approvedCandidate&&<div className="stellar-ai-approval">
    <label><input type="checkbox" aria-label="Approve verified inline AI candidate" checked={approval} onChange={e=>setApproval(e.target.checked)}/>
      {approvedCandidate.mode==='recovery'?'I approve replacing the current unverified parser draft with this verified recovery parser.':
       approvedCandidate.mode==='correction'?'I approve this one verified mapping correction. All unrelated rules must remain unchanged.':
       'I approve the one verified additive mapping. Existing rules must remain unchanged.'}</label>
    <button type="button" disabled={!approval||!onApplyCandidate} onClick={()=>{
     if(!approval||!approvedCandidate||!onApplyCandidate||!source||!draft||!suite)return;
     if(!holdoutAttested||validatedEvidence!==evidenceFingerprint()){
      setApprovedCandidate(null);setApproval(false);setValidatedEvidence('');
      setImportResult('Candidate rejected: approval evidence is stale. Re-run holdout validation against the current sample and proposal.');return;
     }
     try{
      const candidateSuite=preview(source,approvedCandidate.draft),candidateHoldout=preview(holdout,approvedCandidate.draft);
      const recheck=compareCandidate({source,baseline:suite,candidate:candidateSuite,
       holdout:{source:holdout,baseline:preview(holdout,draft),candidate:candidateHoldout}});
      if(!recheck.acceptedWithoutRegression||recheck.holdoutStatus!=='TESTED'||
         !completeSuite(candidateSuite)||!completeSuite(candidateHoldout)){
       setApprovedCandidate(null);setApproval(false);setValidatedEvidence('');
       setImportResult('Candidate rejected during final holdout recheck. No rules were applied.');return;
      }
     }catch{
      setApprovedCandidate(null);setApproval(false);setValidatedEvidence('');
      setImportResult('Candidate rejected: final training or holdout evidence is stale, reordered, or mutated.');return;
     }
     const appliedMode=approvedCandidate.mode;onApplyCandidate(approvedCandidate.draft);setApprovedCandidate(null);setApproval(false);setValidatedEvidence('');
     setImportResult(appliedMode==='recovery'?'Approved recovery parser added to draft. Native parser testing and export verification remain required.':
      appliedMode==='correction'?'Approved mapping correction added to draft. Native parser testing and export verification remain required.':
      'Approved mapping added to draft. Native parser testing and export verification remain required.');
    }}>{approvedCandidate.mode==='recovery'?'Apply Approved Recovery Parser to Draft':approvedCandidate.mode==='correction'?'Apply Approved Mapping Correction':'Apply Approved Mapping to Draft'}</button>
   </div>}
  </details>
  <small>AI output is a proposal only. Import, independent validation and user approval are required before changing parser rules.</small>
 </aside>;
}
