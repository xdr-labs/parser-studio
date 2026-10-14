import {useEffect,useState} from 'react';
import {toSourceByteRange,fromSourceByteRange} from './sourceByteSelection';
import type {ParserDraft,SuiteResult} from '../model';
import {importReviewOnlyAIRecipe,proposeV01FieldMappingFromAI} from './aiRecipeExchange';
import {compareCandidate} from './autoParserRegression';
import {preview} from '../parser';

interface Props {raw:string;status:string;onChatGPT:()=>void;source?:string;draft?:ParserDraft;suite?:SuiteResult;initialByteRange?:{startByte:number;endByte:number}|null;onApplyCandidate?:(draft:ParserDraft)=>void}
export default function AutoParserAIReview({raw,status,onChatGPT,source,draft,suite,initialByteRange,onApplyCandidate}:Props){
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
 const [approvedCandidate,setApprovedCandidate]=useState<ParserDraft|null>(null);
 const [approval,setApproval]=useState(false);
 useEffect(()=>{
  const initial=initialByteRange?fromSourceByteRange(raw,initialByteRange.startByte,initialByteRange.endByte):null;
  setRange(initial??[0,0]);setReviewedExcerpt('');setApproved(false);setNotice('');setRecipeText('');setImportResult('');setApprovedCandidate(null);setApproval(false);
  setMode(initial?'selection':status==='unsupported'?'entire':'selection');
 },[raw,status,initialByteRange?.startByte,initialByteRange?.endByte]);
 const sourceRange=toSourceByteRange(raw,range[0],range[1]);
 const excerpt=mode==='entire'?raw:(sourceRange?.text??'');
 const canCopy=approved&&!!reviewedExcerpt.trim()&&!!goal.trim()&&!!excerpt.trim();
 const prompt=()=>[
  'Parser Studio — source extraction assistance (review-only).',
  'Return a proposed ParserRecipe v0.2 JSON object; do not return executable Ruby, arbitrary Regex or code.',
  'Do not invent missing values, do not overwrite correct fields, and preserve the original event.',
  `Scope: ${mode==='entire'?'entire unsupported event':'only the selected source range'}.`,
  `Source UTF-8 byte range: ${mode==='entire'?`0–${new TextEncoder().encode(raw).byteLength}`:`${sourceRange?.startByte??'UNSELECTED'}–${sourceRange?.endByte??'UNSELECTED'}`}.`,
  `Requested correction: ${goal.trim()}`,
  'User-reviewed excerpt follows (may contain sensitive source values):',
  'BEGIN REVIEWED SOURCE',reviewedExcerpt,'END REVIEWED SOURCE',
  'Explain uncertainty, candidate field names, and how to test positive/negative cases before approval.'
 ].join('\n');
 async function copyPrompt(){
  if(!canCopy)return;
  try{await navigator.clipboard.writeText(prompt());setNotice('Reviewed prompt copied. Paste it into ChatGPT manually.');}
  catch{setNotice('Clipboard unavailable. No log data was transferred.');}
 }
 async function reviewImport(){
  if(!source||!draft||!suite||!recipeText.trim()||importBusy)return;
  setImportBusy(true);setImportResult('');setApprovedCandidate(null);setApproval(false);
  try{
   const result=await importReviewOnlyAIRecipe(recipeText,source,draft,suite);
   if(!result.ok){setImportResult(`Rejected AI proposal: ${result.reason}. No rules were applied.`);return;}
   const proposal=proposeV01FieldMappingFromAI(result,source,draft,suite);
   if(!proposal.ok){setImportResult(`REVIEW ONLY: ${result.report.changedStageCount} changes. No safely compilable additive mapping: ${proposal.reason}.`);return;}
   if(!holdout.trim()){setImportResult('Independent holdout sample required before approval. No rules were applied.');return;}
   const report=compareCandidate({source,baseline:suite,candidate:preview(source,proposal.candidate),
    holdout:{source:holdout,baseline:preview(holdout,draft),candidate:preview(holdout,proposal.candidate)}});
   if(!report.acceptedWithoutRegression||report.holdoutStatus!=='TESTED'){
    setImportResult('Candidate rejected: training or holdout regression. No rules were applied.');return;
   }
   setApprovedCandidate(proposal.candidate);
   setImportResult(`Ready for explicit approval: 1 added mapping, 0 training/holdout regressions; ${report.holdout?.sourceCount??0} holdout events tested. Browser-only; native verification pending.`);
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
  <div className="stellar-ai-excerpt" aria-live="polite">{excerpt||'Select a portion of the source log to repair.'}</div>
  <label className="stellar-ai-label" htmlFor="stellar-ai-reviewed">Redact the excerpt before sharing with AI</label>
  <textarea id="stellar-ai-reviewed" aria-label="Reviewed and redacted AI excerpt" rows={4} maxLength={65536}
   value={reviewedExcerpt} onChange={e=>{setReviewedExcerpt(e.target.value);setApproved(false);}}
   placeholder="Paste only reviewed, redacted source text here. Nothing is sent automatically."/>
  <label className="stellar-ai-label" htmlFor="stellar-ai-goal">What should be extracted or corrected?</label>
  <textarea id="stellar-ai-goal" aria-label="AI correction request" rows={3} maxLength={500} value={goal}
   onChange={e=>{setGoal(e.target.value);setApproved(false);}} placeholder="For example: split the selected source address into IP and port."/>
  <label className="stellar-ai-consent"><input type="checkbox" checked={approved} onChange={e=>setApproved(e.target.checked)}/>
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
    value={recipeText} onChange={e=>{setRecipeText(e.target.value);setImportResult('');setApprovedCandidate(null);setApproval(false);}}/>
   <label className="stellar-ai-label" htmlFor="stellar-ai-holdout">Independent holdout logs (required)</label>
   <textarea id="stellar-ai-holdout" aria-label="AI candidate holdout logs" rows={3} maxLength={65536}
    value={holdout} onChange={e=>{setHoldout(e.target.value);setApprovedCandidate(null);setApproval(false);setImportResult('');}}/>
   <button type="button" disabled={!source||!draft||!suite||!recipeText.trim()||importBusy}
    onClick={()=>void reviewImport()}>Validate Proposal (Review Only)</button>
   {importResult&&<p role="status">{importResult}</p>}
   {approvedCandidate&&<div className="stellar-ai-approval">
    <label><input type="checkbox" checked={approval} onChange={e=>setApproval(e.target.checked)}/>
      I approve the one verified additive mapping. Existing rules must remain unchanged.</label>
    <button type="button" disabled={!approval||!onApplyCandidate} onClick={()=>{
     if(!approval||!approvedCandidate||!onApplyCandidate)return;
     onApplyCandidate(approvedCandidate);setApprovedCandidate(null);setApproval(false);
     setImportResult('Approved mapping added to draft. Native parser testing and export verification remain required.');
    }}>Apply Approved Mapping to Draft</button>
   </div>}
  </details>
  <small>AI output is a proposal only. Import, independent validation and user approval are required before changing parser rules.</small>
 </aside>;
}
