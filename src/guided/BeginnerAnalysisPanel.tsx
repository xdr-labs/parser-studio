import {useState} from 'react';
import {Bot,CheckCircle2,Clipboard,TriangleAlert,Wrench} from 'lucide-react';
import type {MultiPassSourcePreview} from './multipassPreviewClient';
import type {ParserDraft,SuiteResult} from '../model';
import AutoParserAIReview from './AutoParserAIReview';
import {buildBeginnerRepairPrompt} from './beginnerAiPrompt';

export interface BeginnerAnalysisEvent {
  startByte:number;
  endByte:number;
  preview:MultiPassSourcePreview;
}

interface Props {
  source:string;
  events:BeginnerAnalysisEvent[];
  onOpenAssisted:()=>void;
  draft?:ParserDraft;
  suite?:SuiteResult;
  onApplyCandidate?:(draft:ParserDraft)=>void;
  resolvedByReviewedCandidate?:boolean;
  parserRuleReviewRequired?:boolean;
  neutralCsvColumnCount?:number;
  onUseNeutralCsvColumns?:()=>void;
}

function utf8Slice(source:string,startByte:number,endByte:number):string{
  const bytes=new TextEncoder().encode(source);
  try{return new TextDecoder('utf-8',{fatal:true}).decode(bytes.slice(startByte,endByte));}
  catch{return '';}
}
function eventRaw(source:string,event:BeginnerAnalysisEvent){
  return utf8Slice(source,event.startByte,event.endByte);
}
function plainIssue(code:string):string{
  const known:Record<string,string>={
    KV_QUOTE_UNCLOSED:'A quoted key/value field is not closed, so the rest of the event cannot be trusted as normal key/value data.',
    RFC5424_SD_UNCLOSED:'The Syslog structured-data section is not closed correctly.',
    RFC5424_DUPLICATE_SD_KEY:'The Syslog structured-data section contains a repeated field name.',
    RFC5424_SD_TRAILING_SPACE_NONSTANDARD:'The Syslog structured-data section contains non-standard spacing.',
    RFC5424_TIMESTAMP_INVALID:'The Syslog timestamp is not valid enough to use as event time.',
    UNLABELED_CSV_NEEDS_CORPUS_CONFIRMATION:'The event is positional CSV. Values were found, but the log itself does not contain reliable column names.',
    UNSUPPORTED_BSD_BODY:'The Syslog header was recognized but the message body still needs an extraction rule.',
    RFC5424_HEADER_TOKEN_INVALID:'The Syslog header contains a token outside the supported grammar.',
  };
  return known[code]??'This source region needs an additional reviewed parsing rule ('+code.replaceAll('_',' ').toLowerCase()+').';
}
function wholeEventNeedsRule(preview:MultiPassSourcePreview):boolean{
  return Object.keys(preview.fields).length===0&&
    preview.residuals.some(region=>region.startByte===0&&region.endByte>=preview.sourceBytes);
}
function friendlySyntax(preview:MultiPassSourcePreview):string{
  const syntax=preview.syntax.toUpperCase();
  if(wholeEventNeedsRule(preview))return 'custom text format';
  if(syntax.includes('CSV'))return (syntax.includes('SYSLOG')||syntax.includes('BSD')||syntax.includes('RFC'))?
    'Syslog-wrapped positional CSV':'positional CSV';
  if(syntax.includes('ASA')||syntax.includes('FTD')||syntax.includes('BSD_SYSLOG'))return 'security device message';
  if(syntax.includes('SYSLOG'))return 'Syslog with structured security fields';
  if(syntax.includes('JSON'))return 'JSON';
  if(syntax.includes('CEF'))return 'CEF';
  if(syntax.includes('LEEF'))return 'LEEF';
  if(syntax.includes('KV'))return 'key/value fields';
  return 'security log structure';
}
function recommendation(preview:MultiPassSourcePreview):{kind:'metadata'|'json'|'cef'|'leef'|'csv'|'kv'|'message'|'text'|'assisted';label:string;text:string}{
  const syntax=preview.syntax.toUpperCase();
  const issues=preview.issues.join(' ').toUpperCase();
  if(wholeEventNeedsRule(preview))return {
    kind:'text',
    label:'Create a rule for this text format',
    text:'Parser Studio could not identify a standard format. Use the repeated separators or text pattern to extract only the values that are present, then test the fix against additional examples.',
  };
  if(preview.residuals.length===0&&
    (issues.includes('RFC5424_TIMESTAMP_INVALID')||issues.includes('RFC5424_DUPLICATE_SD_KEY')||
     issues.includes('RFC5424_SD_TRAILING_SPACE_NONSTANDARD')))return {
    kind:'metadata',
    label:'Review source metadata',
    text:'The useful fields were extracted. Keep them. The source itself contains a timestamp or structured-data problem that should be corrected or intentionally preserved before creating the parser.',
  };
  if(syntax.includes('JSON'))return {
    kind:'json',
    label:'Map the remaining JSON fields',
    text:'Keep the JSON structure and map only the missing fields. Parser Studio will preserve fields that are already correct.',
  };
  if(syntax.includes('CEF'))return {
    kind:'cef',
    label:'Map the remaining CEF fields',
    text:'Keep the CEF structure and map only the remaining extension fields.',
  };
  if(syntax.includes('LEEF'))return {
    kind:'leef',
    label:'Map the remaining LEEF fields',
    text:'Keep the LEEF structure and map only the remaining extension fields.',
  };
  if(syntax.includes('CSV')||issues.includes('CSV')||issues.includes('UNLABELED'))return {
    kind:'csv',
    label:'Keep all values with temporary field names',
    text:'The log has values in fixed positions but does not contain column names. Keep every value with temporary names now; you can rename the fields later without losing source data.',
  };
  if(syntax.includes('KV')&&!syntax.includes('UNKNOWN'))return {
    kind:'kv',
    label:'Keep the key/value fields and fix the remaining section',
    text:'Parser Studio already understands the key/value fields. Create one small rule only for the part that remains unresolved.',
  };
  if(syntax.includes('SYSLOG')||syntax.includes('ASA')||syntax.includes('FTD'))return {
    kind:'message',
    label:'Create a rule for the remaining message text',
    text:'Parser Studio found the message structure and existing fields. Create one additional rule for the unresolved text, then test it against additional examples before applying it.',
  };
  if(syntax.includes('UNKNOWN'))return {
    kind:'text',
    label:'Create a rule for this text format',
    text:'Use the repeated separators or text pattern to extract only the values that are present. Parser Studio will keep unmatched events instead of silently dropping them.',
  };
  return {
    kind:'assisted',
    label:'Fix this event with ChatGPT',
    text:'Let ChatGPT propose a parser fix, then let Parser Studio test the proposal against additional logs before you apply it.',
  };
}
function metadataOnlyReview(preview:MultiPassSourcePreview):boolean{
  const issues=preview.issues.join(' ').toUpperCase();
  return preview.residuals.length===0&&
    (issues.includes('RFC5424_TIMESTAMP_INVALID')||issues.includes('RFC5424_DUPLICATE_SD_KEY')||
     issues.includes('RFC5424_SD_TRAILING_SPACE_NONSTANDARD'));
}
function problemTitle(preview:MultiPassSourcePreview):string{
  if(metadataOnlyReview(preview))return 'Fields were extracted, but source metadata needs review';
  if(preview.status==='RAW_ONLY')return 'This event could not be safely structured yet';
  if(preview.status==='STRUCTURED_EMPTY')return 'A structure was detected but no usable fields were extracted';
  return 'Part of this event still needs parsing';
}
function sourceSegments(raw:string,preview:MultiPassSourcePreview){
  if(metadataOnlyReview(preview))return [{kind:'plain' as const,text:raw}];
  if(!preview.residuals.length)return [{kind:'problem' as const,text:raw}];
  const sorted=[...preview.residuals].sort((a,b)=>a.startByte-b.startByte);
  const out:Array<{kind:'plain'|'problem';text:string}>=[];
  let cursor=0;
  for(const region of sorted){
    if(region.startByte>cursor)out.push({kind:'plain',text:utf8Slice(raw,cursor,region.startByte)});
    out.push({kind:'problem',text:utf8Slice(raw,region.startByte,region.endByte)});
    cursor=Math.max(cursor,region.endByte);
  }
  const size=new TextEncoder().encode(raw).byteLength;
  if(cursor<size)out.push({kind:'plain',text:utf8Slice(raw,cursor,size)});
  return out;
}

export default function BeginnerAnalysisPanel({source,events,onOpenAssisted,draft,suite,onApplyCandidate,
  resolvedByReviewedCandidate=false,parserRuleReviewRequired=false,
  neutralCsvColumnCount,onUseNeutralCsvColumns}:Props){
  const [selected,setSelected]=useState(0);
  const [promptOpen,setPromptOpen]=useState(false);
  const [promptText,setPromptText]=useState('');
  const [promptBusy,setPromptBusy]=useState(false);
  const [copyStatus,setCopyStatus]=useState('');
  const sourceParsed=events.filter(x=>x.preview.status==='SOURCE_PARSED').length;
  const parsed=resolvedByReviewedCandidate?events.length:parserRuleReviewRequired?0:sourceParsed;
  const problems=resolvedByReviewedCandidate?[]:parserRuleReviewRequired&&events.length
    ?[{event:events[0]!,index:0}]
    :events.map((event,index)=>({event,index})).filter(x=>x.event.preview.status!=='SOURCE_PARSED');
  const current=problems[selected]??problems[0]??null;
  const raw=current?eventRaw(source,current.event):'';
  const rec=current?recommendation(current.event.preview):null;
  const recipeImportEligible=!!rec&&rec.kind!=='metadata';
  const openPrompt=async()=>{
    if(!current||!rec||promptBusy)return;
    setPromptBusy(true);setCopyStatus('');
    try{
      const value=await buildBeginnerRepairPrompt({
        fullSource:source,eventSource:raw,preview:current.event.preview,
        draft,suite,recommendation:rec,
      });
      setPromptText(value);setPromptOpen(true);
    }catch{
      setPromptText('');setPromptOpen(false);
      setCopyStatus('Parser Studio could not build a trusted repair prompt from the current source.');
    }finally{setPromptBusy(false);}
  };
  const copyPrompt=async()=>{
    if(!promptText)return;
    try{
      await navigator.clipboard.writeText(promptText);
      setCopyStatus('ChatGPT prompt copied. Review it before pasting into ChatGPT.');
    }catch{setCopyStatus('Copy was blocked by the browser. Select the prompt text and copy it manually.');}
  };
  return <section className="beginner-analysis" aria-label="Beginner analysis summary">
    <div className={"beginner-analysis-head "+(problems.length?'needs-attention':'complete')}>
      {problems.length?<TriangleAlert size={22}/>:<CheckCircle2 size={22}/>}
      <div>
        <strong>{parserRuleReviewRequired
          ?`${sourceParsed} of ${events.length} source event${events.length===1?'':'s'} extracted`
          :`${parsed} of ${events.length} log event${events.length===1?'':'s'} parsed completely`}</strong>
        <p>{resolvedByReviewedCandidate
          ?'The reviewed parser fix passes the current sample in browser validation. Continue to review field meanings and create the parser draft.'
          :parserRuleReviewRequired
          ?'Parser Studio found the source fields, but it still needs one additional rule before it can create the parser. No extracted values will be lost.'
          :problems.length
          ?`${problems.length} event${problems.length===1?' needs':'s need'} attention. Parser Studio will show what remains and the safest next action.`
          :'No unresolved source region was found. Continue to review field meanings and create the parser draft.'}</p>
      </div>
    </div>
    {current&&<div className="beginner-problem" aria-label="Parse problem inspector">
      {problems.length>1&&<label>Problem to review
        <select aria-label="Problem event" value={selected} onChange={e=>{setSelected(Number(e.target.value));setPromptOpen(false);setPromptText('');setCopyStatus('');}}>
          {problems.map((item,i)=><option key={item.index} value={i}>Event {item.index+1} · {problemTitle(item.event.preview)}</option>)}
        </select>
      </label>}
      <h3>{parserRuleReviewRequired
        ?'Fields found — one more rule is needed'
        :problemTitle(current.event.preview)}</h3>
      <p>{parserRuleReviewRequired
        ?<>Parser Studio found the fields in this <b>{friendlySyntax(current.event.preview)}</b>, but it needs one additional rule before it can build the parser.</>
        :<>Parser Studio recognized <b>{friendlySyntax(current.event.preview)}</b>, but it will not mark this event parser-ready until the remaining review is resolved.</>}</p>
      <div className="beginner-problem-source">
        <span>Original event {current.index+1} · {parserRuleReviewRequired
          ?'parser rule needs review'
          :metadataOnlyReview(current.event.preview)
            ?'source metadata warning · no source bytes dropped'
            :'highlighted text needs attention'}</span>
        <pre>{sourceSegments(raw,current.event.preview).map((segment,index)=>
          segment.kind==='problem'?<mark key={index}>{segment.text}</mark>:<span key={index}>{segment.text}</span>)}</pre>
      </div>
      <div className="beginner-problem-details">
        <div><strong>What needs attention</strong>
          {parserRuleReviewRequired
            ?<p>The field values are already available. Only the parser rule that reproduces this message format is still missing.</p>
            :current.event.preview.issues.length
              ?<ul>{current.event.preview.issues.map(code=><li key={code}>{plainIssue(code)}</li>)}</ul>
              :<p>The engine could not produce a complete trustworthy field set for this event.</p>}
        </div>
        <div><strong>{parserRuleReviewRequired?'What Parser Studio still needs':metadataOnlyReview(current.event.preview)?'Source metadata review':'Unparsed source'}</strong>
          {parserRuleReviewRequired
            ?<p>No source text is missing. Create one rule for this message format, then test it against additional log examples.</p>
            :current.event.preview.residuals.length
              ?current.event.preview.residuals.map((region,i)=><code key={i}>{utf8Slice(raw,region.startByte,region.endByte)}</code>)
              :metadataOnlyReview(current.event.preview)
                ?<p>No source bytes were dropped. Extracted fields are retained; review only the timestamp or structured-data anomaly listed here.</p>
                :<p>No trustworthy smaller range is available, so the whole event should be reviewed.</p>}
        </div>
      </div>
      {rec&&<div className="beginner-fix">
        <Wrench size={18}/><div><strong>Recommended fix · {rec.label}</strong><p>{rec.text}</p></div>
      </div>}
      <div className="beginner-fix-actions">
        {rec?.kind==='csv'&&neutralCsvColumnCount&&onUseNeutralCsvColumns&&
          <button type="button" className="auto-parser-primary" onClick={onUseNeutralCsvColumns}>
            Keep all {neutralCsvColumnCount} values with temporary names
          </button>}
        <button type="button" className={rec?.kind==='csv'?'':'auto-parser-primary'} disabled={promptBusy}
          onClick={()=>void openPrompt()}>
          <Bot size={16}/> {promptBusy?'Preparing…':rec?.kind==='metadata'?'Review with ChatGPT':'Fix with ChatGPT'}
        </button>
      </div>
      {promptOpen&&<div className="beginner-chatgpt" aria-label="ChatGPT repair prompt">
        <strong>1. Copy this prompt to ChatGPT</strong>
        <p>Review or redact sensitive values first. Parser Studio never sends the log automatically.</p>
        <textarea aria-label="Generated ChatGPT repair prompt" value={promptText} readOnly rows={14}/>
        <button type="button" onClick={()=>void copyPrompt()}><Clipboard size={15}/> Copy Prompt</button>
        {copyStatus&&<p role="status">{copyStatus}</p>}
        {recipeImportEligible&&draft&&suite&&onApplyCandidate&&<>
          <div className="beginner-inline-step">
            <strong>2. Paste the ChatGPT result below</strong>
            <p>Parser Studio will test the proposed fix against the current logs and additional test logs before you can apply it.</p>
          </div>
          <AutoParserAIReview importOnly raw={raw}
            status={current.event.preview.status==='RAW_ONLY'?'unsupported':'partial'}
            onChatGPT={onOpenAssisted} source={source} draft={draft} suite={suite}
            onApplyCandidate={onApplyCandidate}/>
        </>}
        {recipeImportEligible&&draft&&!suite&&<div className="beginner-inline-wait" role="status">
          <strong>Preparing result review…</strong>
          <p>The local preview is still preparing the safe validation step. You can paste the ChatGPT result here as soon as it is ready.</p>
        </div>}
        {recipeImportEligible&&<button type="button" className="beginner-secondary-link" onClick={onOpenAssisted}>
          Use the full ChatGPT workflow instead
        </button>}
        {!recipeImportEligible&&<p className="beginner-manual-fix-note" role="note">
          The fields were extracted. This is a source-metadata problem, not a missing parser rule.
          Correct the source timestamp/structured-data issue upstream or intentionally preserve it after review.
        </p>}
      </div>}
    </div>}
  </section>;
}
