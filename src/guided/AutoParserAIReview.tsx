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

interface Props {raw:string;status:string;onChatGPT:()=>void;source?:string;draft?:ParserDraft;suite?:SuiteResult;initialByteRange?:{startByte:number;endByte:number}|null;selectionContext?:{kind:'field'|'residual';path?:string};onApplyCandidate?:(draft:ParserDraft)=>void;importOnly?:boolean}
const completeSuite=(value:SuiteResult)=>value.counts.total>0&&value.counts.matched===value.counts.total&&
 value.counts.extracted===value.counts.total&&value.counts.normalized===value.counts.total&&value.counts.failures===0;
export default function AutoParserAIReview({raw,status,onChatGPT,source,draft,suite,initialByteRange,selectionContext,onApplyCandidate,importOnly=false}:Props){
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
 const [approvedCandidate,setApprovedCandidate]=useState<{draft:ParserDraft;mode:'mapping'|'correction'|'enrichment'|'recovery';scope?:{oldTarget:string;newTarget:string}}|null>(null);
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
   try{
    candidateSuite=preview(source,proposal.candidate);candidateHoldout=preview(holdout,proposal.candidate);
    const comparisonInput={source,baseline:suite,candidate:candidateSuite,
     holdout:{source:holdout,baseline:preview(holdout,draft),candidate:candidateHoldout}};
    report=candidateMode==='correction'&&correctionScope?
     compareMappingCorrectionCandidate(comparisonInput,correctionScope):compareCandidate(comparisonInput);
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
    setImportResult('The proposed fix did not pass both the original logs and the additional test logs. No parser rules were changed.');return;
   }
   setApprovedCandidate({draft:proposal.candidate,mode:candidateMode,scope:correctionScope});setValidatedEvidence(evidenceFingerprint());
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
   <label className="stellar-ai-consent"><input type="checkbox" aria-label="Confirm independent AI holdout provenance"
    checked={holdoutAttested} onChange={e=>{setHoldoutAttested(e.target.checked);setApprovedCandidate(null);setApproval(false);setValidatedEvidence('');}}/>
    These are different log examples from the ones used to create this fix.</label>
   <button type="button" aria-label="Validate Proposal (Review Only)"
    disabled={!source||!draft||!suite||!recipeText.trim()||importBusy}
    onClick={()=>void reviewImport()}>Test Proposed Fix</button>
   {importResult&&<p role="status">{importResult}</p>}
   {approvedCandidate&&<div className="stellar-ai-approval">
    <label><input type="checkbox" aria-label="Approve verified inline AI candidate" checked={approval} onChange={e=>setApproval(e.target.checked)}/>
      I reviewed the tested result and approve applying this fix. Existing unrelated fields and rules must remain unchanged.</label>
    <button type="button" onClick={()=>{
     setApprovedCandidate(null);setApproval(false);setValidatedEvidence('');
     setImportResult('AI candidate rejected by the user. Existing parser rules remain unchanged.');
    }}>Reject Candidate</button>
    <button type="button" disabled={!approval||!onApplyCandidate} onClick={()=>{
     if(!approval||!approvedCandidate||!onApplyCandidate||!source||!draft||!suite)return;
     if(!holdoutAttested||validatedEvidence!==evidenceFingerprint()){
      setApprovedCandidate(null);setApproval(false);setValidatedEvidence('');
      setImportResult('Candidate rejected: approval evidence is stale. Re-run holdout validation against the current sample and proposal.');return;
     }
     try{
      const candidateSuite=preview(source,approvedCandidate.draft),candidateHoldout=preview(holdout,approvedCandidate.draft);
      const recheckInput={source,baseline:suite,candidate:candidateSuite,
       holdout:{source:holdout,baseline:preview(holdout,draft),candidate:candidateHoldout}};
      const recheck=approvedCandidate.mode==='correction'&&approvedCandidate.scope?
       compareMappingCorrectionCandidate(recheckInput,approvedCandidate.scope):compareCandidate(recheckInput);
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
      appliedMode==='enrichment'?'Approved split/merge rule added to draft. Native parser testing and export verification remain required.':
      'Approved mapping added to draft. Native parser testing and export verification remain required.');
    }} aria-label={approvedCandidate.mode==='recovery'?'Apply Approved Recovery Parser to Draft':approvedCandidate.mode==='correction'?'Apply Approved Mapping Correction':approvedCandidate.mode==='enrichment'?'Apply Approved Split/Merge Rule':'Apply Approved Mapping to Draft'}>
      Apply Verified Fix
    </button>
   </div>}
  </details></>;
 if(importOnly)return <aside className="stellar-ai-review beginner-ai-result-review" aria-label="AI result verification">
  <h3>Paste ChatGPT Result</h3>
  <p>Paste the JSON returned by ChatGPT. Parser Studio will test it against the current logs and additional examples before anything changes.</p>
  {importPanel}
  <small>No rule changes until validation passes and you explicitly approve the candidate.</small>
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
  <small>AI output is a proposal only. Import, independent validation and user approval are required before changing parser rules.</small>
 </aside>;
}
