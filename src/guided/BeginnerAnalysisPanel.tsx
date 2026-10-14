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
function friendlySyntax(preview:MultiPassSourcePreview):string{
  const syntax=preview.syntax.toUpperCase();
  if(syntax.includes('CISCO_ASA')||syntax.includes('FTD')||syntax.includes('BSD_SYSLOG'))return 'Cisco/security Syslog message';
  if(syntax.includes('CSV_UNLABELED'))return 'Syslog-wrapped positional CSV';
  if(syntax.includes('SYSLOG'))return 'Syslog with structured security fields';
  if(syntax.includes('JSON'))return 'JSON';
  if(syntax.includes('CEF'))return 'CEF';
  if(syntax.includes('LEEF'))return 'LEEF';
  if(syntax.includes('KV'))return 'key/value fields';
  return 'security log structure';
}
function recommendation(preview:MultiPassSourcePreview):{label:string;text:string}{
  const syntax=preview.syntax.toUpperCase();
  const issues=preview.issues.join(' ').toUpperCase();
  if(preview.residuals.length===0&&
    (issues.includes('RFC5424_TIMESTAMP_INVALID')||issues.includes('RFC5424_DUPLICATE_SD_KEY')||
     issues.includes('RFC5424_SD_TRAILING_SPACE_NONSTANDARD')))return {
    label:'Review source metadata',
    text:'The useful fields were extracted. Keep them. Review the invalid timestamp or duplicate/non-standard Syslog metadata instead of adding a Regex that would hide the source anomaly.',
  };
  if(syntax.includes('JSON'))return {
    label:'JSON field mapping',
    text:'Use direct JSON field paths first. If values need reshaping, ask ChatGPT for a supported declarative split/merge mapping; Parser Studio does not execute arbitrary JSONata expressions.',
  };
  if(syntax.includes('CEF'))return {
    label:'CEF extension mapping',
    text:'Keep the CEF header parser and map the remaining extension keys. Do not replace structured CEF with a broad Regex.',
  };
  if(syntax.includes('LEEF'))return {
    label:'LEEF extension mapping',
    text:'Keep the LEEF parser and map the remaining extension keys using the detected delimiter.',
  };
  if(syntax.includes('CSV')||issues.includes('CSV')||issues.includes('UNLABELED'))return {
    label:'Column schema mapping',
    text:'The values are positional. Map the columns to reviewed field names first; for PAN-OS, a known version-specific schema is preferable to guessing.',
  };
  if(syntax.includes('KV')&&!syntax.includes('UNKNOWN'))return {
    label:'Key/value rule',
    text:'Keep key=value parsing and add a bounded rule only for the quoted or delimited section that remains unresolved.',
  };
  if(syntax.includes('SYSLOG')||syntax.includes('ASA')||syntax.includes('FTD'))return {
    label:'Message-body pattern',
    text:'Keep the detected Syslog context and target only the unresolved message body. Parser Studio accepts a bounded named-capture Regex only after safety checks, independent holdout validation and the normal DRAFT/Native verification gates.',
  };
  if(syntax.includes('UNKNOWN'))return {
    label:'Text extraction pattern',
    text:'Parser Studio could not identify a standard envelope. Use the repeated delimiters or text structure only for the unresolved event, with bounded named captures and independent holdout validation. Do not assume Syslog or discard unmatched events.',
  };
  return {
    label:'Assisted recovery',
    text:'Use ChatGPT Assisted Parser to propose a bounded ParserRecipe for this unresolved event, then test it against independent holdout logs before applying it.',
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
  const recipeImportEligible=!!rec&&rec.label!=='Review source metadata';
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
          ?'Source extraction succeeded, but Parser Studio still needs a compiler-safe parser rule for this source shape. No extracted fields are discarded.'
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
        ?'Source fields were extracted, but parser generation needs one more rule'
        :problemTitle(current.event.preview)}</h3>
      <p>{parserRuleReviewRequired
        ?<>Parser Studio extracted this <b>{friendlySyntax(current.event.preview)}</b> event, but the current DRAFT compiler cannot yet reproduce the source shape safely. Review a bounded rule before continuing.</>
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
            ?<p>Source fields were extracted, but the current parser draft has no compiler-safe rule that reproduces this exact structure yet.</p>
            :current.event.preview.issues.length
              ?<ul>{current.event.preview.issues.map(code=><li key={code}>{plainIssue(code)}</li>)}</ul>
              :<p>The engine could not produce a complete trustworthy field set for this event.</p>}
        </div>
        <div><strong>{parserRuleReviewRequired?'Parser rule gap':metadataOnlyReview(current.event.preview)?'Source metadata review':'Unparsed source'}</strong>
          {parserRuleReviewRequired
            ?<p>No source bytes are missing. The next step is to create and validate a bounded parser rule that reproduces the already-extracted structure.</p>
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
        {rec?.label==='Column schema mapping'&&neutralCsvColumnCount&&onUseNeutralCsvColumns&&
          <button type="button" className="auto-parser-primary" onClick={onUseNeutralCsvColumns}>
            Use {neutralCsvColumnCount} Neutral Column Names
          </button>}
        <button type="button" className={rec?.label==='Column schema mapping'?'':'auto-parser-primary'} disabled={promptBusy}
          onClick={()=>void openPrompt()}>
          <Bot size={16}/> {promptBusy?'Preparing Prompt…':'Ask ChatGPT'}
        </button>
        <button type="button" onClick={onOpenAssisted}>Open Assisted Parser</button>
      </div>
      {promptOpen&&<div className="beginner-chatgpt" aria-label="ChatGPT repair prompt">
        <strong>Ready-to-use ChatGPT prompt</strong>
        <p>Review or redact sensitive values, then copy. Parser Studio never sends this automatically.</p>
        <textarea aria-label="Generated ChatGPT repair prompt" value={promptText} readOnly rows={14}/>
        <button type="button" onClick={()=>void copyPrompt()}><Clipboard size={15}/> Copy Prompt</button>
        {copyStatus&&<p role="status">{copyStatus}</p>}
        {recipeImportEligible&&draft&&suite&&onApplyCandidate&&<AutoParserAIReview importOnly raw={raw}
          status={current.event.preview.status==='RAW_ONLY'?'unsupported':'partial'}
          onChatGPT={onOpenAssisted} source={source} draft={draft} suite={suite}
          onApplyCandidate={onApplyCandidate}/>}
        {!recipeImportEligible&&<p className="beginner-manual-fix-note" role="note">
          This event needs source-metadata review rather than a new extraction rule. Keep the extracted fields
          and correct the source anomaly upstream, or intentionally preserve it after review.
        </p>}
      </div>}
    </div>}
  </section>;
}
