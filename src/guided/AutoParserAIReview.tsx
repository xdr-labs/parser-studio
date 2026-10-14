import {useEffect,useState} from 'react';
import {toSourceByteRange} from './sourceByteSelection';

interface Props {raw:string;status:string;onChatGPT:()=>void}
export default function AutoParserAIReview({raw,status,onChatGPT}:Props){
 const [mode,setMode]=useState<'entire'|'selection'>(status==='unsupported'?'entire':'selection');
 const [range,setRange]=useState<[number,number]>([0,0]);
 const [goal,setGoal]=useState('');
 const [approved,setApproved]=useState(false);
 const [notice,setNotice]=useState('');
 useEffect(()=>{setRange([0,0]);setApproved(false);setNotice('');setMode(status==='unsupported'?'entire':'selection');},[raw,status]);
 const sourceRange=toSourceByteRange(raw,range[0],range[1]);
 const excerpt=mode==='entire'?raw:(sourceRange?.text??'');
 const canCopy=approved&&!!excerpt.trim()&&!!goal.trim();
 const prompt=()=>[
  'Parser Studio — source extraction assistance (review-only).',
  'Return a proposed ParserRecipe v0.2 JSON object; do not return executable Ruby, arbitrary Regex or code.',
  'Do not invent missing values, do not overwrite correct fields, and preserve the original event.',
  `Scope: ${mode==='entire'?'entire unsupported event':'only the selected source range'}.`,
  `Source UTF-8 byte range: ${mode==='entire'?`0–${new TextEncoder().encode(raw).byteLength}`:`${sourceRange?.startByte??'UNSELECTED'}–${sourceRange?.endByte??'UNSELECTED'}`}.`,
  `Requested correction: ${goal.trim()}`,
  'User-reviewed excerpt follows (may contain sensitive source values):',
  'BEGIN REVIEWED SOURCE',excerpt,'END REVIEWED SOURCE',
  'Explain uncertainty, candidate field names, and how to test positive/negative cases before approval.'
 ].join('\n');
 async function copyPrompt(){
  if(!canCopy)return;
  try{await navigator.clipboard.writeText(prompt());setNotice('Reviewed prompt copied. Paste it into ChatGPT manually.');}
  catch{setNotice('Clipboard unavailable. No log data was transferred.');}
 }
 return <aside className="stellar-ai-review" aria-label="Improve with AI">
  <h3>Improve with AI</h3>
  <p>Use AI only where the automatic parser needs help. No log data is sent automatically.</p>
  <div className="stellar-ai-tabs" role="group" aria-label="AI recovery scope">
   <button type="button" aria-pressed={mode==='entire'} onClick={()=>{setMode('entire');setApproved(false);}}>Entire Log</button>
   <button type="button" aria-pressed={mode==='selection'} onClick={()=>{setMode('selection');setApproved(false);}}>Selected Area</button>
  </div>
  <label className="stellar-ai-label">{mode==='entire'?'Review the entire log before copying':'Select exact source text below'}</label>
  {mode==='selection'&&<textarea aria-label="Select source text for AI correction" readOnly spellCheck={false} rows={5} value={raw}
   onSelect={e=>{const el=e.currentTarget;setRange([el.selectionStart,el.selectionEnd]);setApproved(false);}}/>}
  {mode==='selection'&&sourceRange&&<p role="status">UTF-8 bytes {sourceRange.startByte}–{sourceRange.endByte}</p>}
  <div className="stellar-ai-excerpt" aria-live="polite">{excerpt||'Select a portion of the source log to repair.'}</div>
  <label className="stellar-ai-label" htmlFor="stellar-ai-goal">What should be extracted or corrected?</label>
  <textarea id="stellar-ai-goal" aria-label="AI correction request" rows={3} maxLength={500} value={goal}
   onChange={e=>{setGoal(e.target.value);setApproved(false);}} placeholder="For example: split the selected source address into IP and port."/>
  <label className="stellar-ai-consent"><input type="checkbox" checked={approved} onChange={e=>setApproved(e.target.checked)}/>
   I reviewed this excerpt and removed sensitive information before copying.</label>
  <div className="stellar-ai-actions">
   <button type="button" className="stellar-ai-primary" disabled={!canCopy} onClick={()=>void copyPrompt()}>Copy AI Prompt</button>
   <button type="button" onClick={onChatGPT}>Open Assisted Parser</button>
  </div>
  {notice&&<p role="status">{notice}</p>}
  <small>AI output is a proposal only. Import, independent validation and user approval are required before changing parser rules.</small>
 </aside>;
}
