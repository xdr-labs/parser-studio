import {useMemo,useState} from 'react';
import type {RefObject} from 'react';
import {detectFormat} from '../parser';
import {boundaryLiteralError,inspectDeclaredSourceBoundaries,selectedBoundaryLiteral,
  type DeclaredSourceBoundaries} from './declaredSourceBoundaries';
import {HelpTip} from './BeginnerHelp';

/**
 * Author-defined, byte-exact prefix/postfix inspector. Never mutates
 * source input or compiler configuration; this does not certify export.
 */
export default function DeclaredSourceBoundaryReview({
  source,inputRef,
}:{
  source:string;
  inputRef:RefObject<HTMLTextAreaElement|null>;
}){
  const [literals,setLiterals]=useState<DeclaredSourceBoundaries>({prefix:'',postfix:''});
  const [hint,setHint]=useState('');
  const review=useMemo(()=>inspectDeclaredSourceBoundaries(source,literals),
    [source,literals]);
  const candidates=useMemo(()=>review.status==='EXACT_PREVIEW'?
    review.records.slice(0,3).map(record=>({
      line:record.line,
      sourceBytes:record.recordEndByte-record.recordStartByte,
      payloadBytes:record.payloadEndByte-record.payloadStartByte,
      startByte:record.payloadStartByte,
      endByte:record.payloadEndByte,
      format:detectFormat(record.payload).format,
      text:record.payload.slice(0,240),
    })):[],[review]);

  const mark=(side:'prefix'|'postfix')=>{
    const textarea=inputRef.current;
    if(!textarea){setHint('Open the log input to select exact boundary text.');return;}
    const selected=selectedBoundaryLiteral(source,textarea.selectionStart,
      textarea.selectionEnd,side);
    if(selected.error){setHint(selected.error);return;}
    setLiterals(old=>({...old,[side]:selected.value}));
    setHint('Exact '+side+' text selected from the first event. Check all examples below.');
  };
  const setLiteral=(side:'prefix'|'postfix',value:string)=>{
    setLiterals(old=>({...old,[side]:value}));
    setHint('');
  };
  const error=boundaryLiteralError(literals.prefix)||boundaryLiteralError(literals.postfix);
  return <details className="auto-parser-recipe declared-source-boundaries"
    aria-label="Review manually marked prefix and suffix">
    <summary>Optional: mark text added before or after a log event
      <HelpTip label="Mark prefix and suffix"
        text="For example, a forwarder may add fixed characters before a log or a trailer after it. Highlight those characters in the first example and mark them, or type the exact text. This is a local inspection; no parser rule is generated."/></summary>
    <p>Use this only when a forwarding system adds <strong>exactly the same text</strong>
      at the start or end of every sample event. Parser Studio will not guess timestamps,
      changing hostnames, or wildcard patterns. Your original log stays unchanged.</p>
    <div className="declared-source-boundary-inputs">
      <label>Prefix — exact starting text
        <input aria-label="Exact forwarder prefix" value={literals.prefix}
          maxLength={256} placeholder="Example: RELAY: "
          onChange={event=>setLiteral('prefix',event.target.value)}/>
      </label>
      <label>Suffix — exact ending text
        <input aria-label="Exact forwarder suffix" value={literals.postfix}
          maxLength={256} placeholder="Example: :END"
          onChange={event=>setLiteral('postfix',event.target.value)}/>
      </label>
    </div>
    <div className="stellar-span-actions">
      <button type="button" onClick={()=>mark('prefix')}>Mark highlighted prefix</button>
      <button type="button" onClick={()=>mark('postfix')}>Mark highlighted suffix</button>
      <button type="button" onClick={()=>{setLiterals({prefix:'',postfix:''});setHint('');}}>
        Clear both marks
      </button>
    </div>
    {hint&&<p role="status" aria-label="Manual boundary selection guidance">{hint}</p>}
    {error&&<p role="alert">{error}</p>}
    {review.status!=='NONE'&&<div role="status" className="declared-source-boundary-result"
      aria-label="Exact source boundary comparison">
      <strong>{review.status==='EXACT_PREVIEW'?'Exact markers match every sample.':
        review.status==='REVIEW_ONLY'?'Some log events do not match the declared markers.':
        'The marked source boundaries cannot be inspected safely.'}</strong>
      <span>{review.matched} of {review.total} events match exact selected text</span>
      <small>Read-only source review · Native not verified · Parser export not verified</small>
      {review.status==='REVIEW_ONLY'&&<span>
        Review event lines {review.records.filter(record=>!record.matched)
          .slice(0,12).map(record=>record.line).join(', ')}. The preview will not skip unmatched logs.
      </span>}
    </div>}
    {candidates.length>0&&<div aria-label="Source payload examples"
      className="declared-source-payloads">
      {candidates.map(example=><div key={example.line}>
        <strong>Event line {example.line} · Detected inner format: {example.format}</strong>
        <span>UTF-8 byte range {example.startByte}–{example.endByte}
          {' '}({example.payloadBytes} of {example.sourceBytes} record bytes)</span>
        <pre>{example.text}</pre>
        </div>)}
    </div>}
    <p role="note" className="declared-source-export-warning">
      <strong>Inspection only.</strong> These selected characters are not included in
      generated Ruby/CONF files. Parser generation still checks the original events
      without silently stripping any text. If the wrapper varies, review the remaining
      logs or use ChatGPT Assisted Parser; do not assume a successful parse.
    </p>
  </details>;
}
