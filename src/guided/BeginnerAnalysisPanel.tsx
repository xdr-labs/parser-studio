import {useState} from 'react';
import {Bot,CheckCircle2,Clipboard,TriangleAlert,Wrench} from 'lucide-react';
import type {MultiPassSourcePreview} from './multipassPreviewClient';
import type {ParserDraft,SuiteResult} from '../model';
import AutoParserAIReview from './AutoParserAIReview';
import {buildBeginnerRepairPrompt} from './beginnerAiPrompt';
import {extractGenericStructural} from '../genericStructural';
import {listSafeLeafPaths} from '../fieldPaths';

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
  parserRuleReviewEventIndexes?:number[];
  csvReviewRequired?:boolean;
  csvConsistentShapeAvailable?:boolean;
  neutralCsvColumnCount?:number;
  onUseNeutralCsvColumns?:()=>void;
  protectedSourceValuesByEvent?:string[][];
  protectedResidualTextByEvent?:string[][];
}

function utf8Slice(source:string,startByte:number,endByte:number):string{
  const bytes=new TextEncoder().encode(source);
  try{return new TextDecoder('utf-8',{fatal:true}).decode(bytes.slice(startByte,endByte));}
  catch{return '';}
}
function eventRaw(source:string,event:BeginnerAnalysisEvent){
  return utf8Slice(source,event.startByte,event.endByte);
}
function genericStructuralAnchor(source:string,events:BeginnerAnalysisEvent[]):string|null{
  const pathSets=events.map(event=>{
    const extracted=extractGenericStructural(eventRaw(source,event));
    if(extracted.errors.length)return null;
    return new Set(listSafeLeafPaths(extracted.fields));
  });
  if(!pathSets.length||pathSets.some(paths=>paths===null))return null;
  const [first,...rest]=pathSets as Set<string>[];
  const common=[...first].filter(path=>rest.every(paths=>paths.has(path)));
  for(const preferred of ['syslog.pri','generic.mode'])if(common.includes(preferred))return preferred;
  return common[0]??null;
}
function prefixedJson(raw:string):boolean{
  const open=raw.indexOf('{');
  if(open<1||open>64||!/^[A-Za-z0-9_.:/-]+[ \t]+$/.test(raw.slice(0,open)))return false;
  try{
    const value=JSON.parse(raw.slice(open));
    return !!value&&typeof value==='object'&&!Array.isArray(value);
  }catch{return false;}
}
function plainIssue(code:string,raw=''):string{
  if(prefixedJson(raw)&&code==='UNLABELED_CSV_NEEDS_CORPUS_CONFIRMATION')
    return 'This event contains valid JSON after a short text prefix, so its wrapper must be handled separately.';
  if(prefixedJson(raw)&&code==='SOURCE_SYNTAX_ERROR:CSV_GRAMMAR_INVALID')
    return 'The short text prefix prevents the normal JSON path from being used even though the JSON payload itself is valid.';
  const known:Record<string,string>={
    KV_QUOTE_UNCLOSED:'A quoted key/value field is not closed, so the rest of the event cannot be trusted as normal key/value data.',
    RFC5424_SD_UNCLOSED:'A structured section in the log header is not closed correctly.',
    RFC5424_DUPLICATE_SD_KEY:'A structured section in the log header repeats the same field name.',
    RFC5424_SD_TRAILING_SPACE_NONSTANDARD:'A structured section in the log header uses unusual spacing.',
    RFC5424_TIMESTAMP_INVALID:'The time in the log header is not complete or valid enough to use as an exact event time.',
    UNLABELED_CSV_NEEDS_CORPUS_CONFIRMATION:'The event contains comma-delimited text, but Parser Studio cannot confirm trustworthy column boundaries or names from this sample alone.',
    UNSUPPORTED_BSD_BODY:'The Syslog header was recognized but the message body still needs an extraction rule.',
    RFC5424_HEADER_TOKEN_INVALID:'The Syslog header contains a token outside the supported grammar.',
  };
  return known[code]??'This source region needs an additional reviewed parsing rule ('+code.replaceAll('_',' ').toLowerCase()+').';
}
function wholeEventNeedsRule(preview:MultiPassSourcePreview):boolean{
  return Object.keys(preview.fields).length===0&&
    preview.residuals.some(region=>region.startByte===0&&region.endByte>=preview.sourceBytes);
}
function friendlySyntax(preview:MultiPassSourcePreview,raw=''):string{
  const syntax=preview.syntax.toUpperCase();
  if(wholeEventNeedsRule(preview))return 'custom text format';
  if(prefixedJson(raw))return 'JSON with a text prefix';
  if(syntax.includes('CISCO_ASA')||syntax.includes('FTD')||syntax.includes('BSD_SYSLOG'))return 'security device message';
  if(syntax.includes('CSV_UNLABELED'))return 'comma-delimited text candidate';
  if(syntax.includes('SYSLOG'))return 'Syslog with structured security fields';
  if(syntax.includes('JSON'))return 'JSON';
  if(syntax.includes('CEF'))return 'standard CEF security event';
  if(syntax.includes('LEEF'))return 'standard LEEF security event';
  if(syntax.includes('KV'))return 'key/value fields';
  return 'security log structure';
}
function recommendation(preview:MultiPassSourcePreview,canUseNeutralCsvNames=false,raw=''):{kind:'metadata'|'json'|'cef'|'leef'|'csv'|'kv'|'message'|'text'|'assisted'|'split';label:string;text:string}{
  const syntax=preview.syntax.toUpperCase();
  const issues=preview.issues.join(' ').toUpperCase();
  if(wholeEventNeedsRule(preview))return {
    kind:'text',
    label:'Create a rule for this text format',
    text:'Parser Studio could not identify a standard format. Use the repeated separators or text pattern to extract only the values that are present, then test the fix against additional examples.',
  };
  if(prefixedJson(raw))return {
    kind:'split',
    label:'Separate prefixed JSON from plain JSON',
    text:'This event contains valid JSON after a short vendor prefix while other events may be plain JSON. Keep these variants in separate parser samples; Parser Studio will not silently merge the two formats.',
  };
  if(preview.residuals.length===0&&
    (issues.includes('SOURCE_TIMESTAMP_INVALID')||issues.includes('RFC5424_TIMESTAMP_INVALID')||issues.includes('RFC5424_DUPLICATE_SD_KEY')||
     issues.includes('RFC5424_SD_TRAILING_SPACE_NONSTANDARD')))return {
    kind:'metadata',
    label:'Review the log header or time',
    text:'The useful values were found and will be kept. The log header or time has a problem that should be corrected or intentionally kept as text before creating the parser.',
  };
  if(syntax.includes('JSON'))return {
    kind:'json',
    label:'Map the remaining JSON fields',
    text:'Keep the JSON structure and map only the missing fields. Parser Studio will preserve fields that are already correct.',
  };
  if(syntax.includes('CEF'))return {
    kind:'cef',
    label:'Review the remaining fields in this CEF event',
    text:'Parser Studio already understands the main CEF event. Review only the remaining vendor fields that still need names.',
  };
  if(syntax.includes('LEEF'))return {
    kind:'leef',
    label:'Review the remaining fields in this LEEF event',
    text:'Parser Studio already understands the main LEEF event. Review only the remaining vendor fields that still need names.',
  };
  if(issues.includes('CSV_GRAMMAR_INVALID'))return {
    kind:'text',
    label:'Review this irregular delimited text',
    text:'This event looks comma-delimited, but Parser Studio cannot assign columns safely yet. Keep the values already extracted and create a small reviewed rule only after testing additional examples.',
  };
  if(syntax.includes('CSV')||issues.includes('CSV')||issues.includes('UNLABELED')){
    if(!canUseNeutralCsvNames)return {
      kind:'assisted',
      label:'Create a rule for this comma-delimited text',
      text:'Parser Studio found comma-delimited structure, but this wrapped or irregular form cannot safely receive automatic temporary column names. Keep the extracted values and test a reviewed parser rule against additional examples.',
    };
    return {
      kind:'csv',
      label:'Keep all values with temporary field names',
      text:'The log has values in fixed positions but does not contain column names. Keep every value with temporary names now; you can rename the fields later without losing source data.',
    };
  }
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
    (issues.includes('SOURCE_TIMESTAMP_INVALID')||issues.includes('RFC5424_TIMESTAMP_INVALID')||issues.includes('RFC5424_DUPLICATE_SD_KEY')||
     issues.includes('RFC5424_SD_TRAILING_SPACE_NONSTANDARD'));
}
function problemTitle(preview:MultiPassSourcePreview):string{
  if(metadataOnlyReview(preview))return 'Fields were found, but the log header or time needs review';
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
  resolvedByReviewedCandidate=false,parserRuleReviewRequired=false,parserRuleReviewEventIndexes,
  csvReviewRequired=false,csvConsistentShapeAvailable=true,neutralCsvColumnCount,onUseNeutralCsvColumns,protectedSourceValuesByEvent,
  protectedResidualTextByEvent}:Props){
  const [selected,setSelected]=useState(0);
  const [promptOpen,setPromptOpen]=useState(false);
  const [promptText,setPromptText]=useState('');
  const [promptBusy,setPromptBusy]=useState(false);
  const [copyStatus,setCopyStatus]=useState('');
  const sourceParsed=events.filter(x=>x.preview.status==='SOURCE_PARSED').length;
  const csvReviewPending=Boolean(csvReviewRequired&&sourceParsed===events.length&&!resolvedByReviewedCandidate);
  const parsed=resolvedByReviewedCandidate?events.length:parserRuleReviewRequired?0:sourceParsed;
  const ruleReviewProblems=parserRuleReviewRequired&&events.length
    ?(parserRuleReviewEventIndexes?.length
      ?parserRuleReviewEventIndexes.filter(index=>index>=0&&index<events.length)
        .map(index=>({event:events[index]!,index}))
      :[{event:events[0]!,index:0}])
    :[];
  const problems=resolvedByReviewedCandidate?[]:parserRuleReviewRequired
    ?ruleReviewProblems
    :events.map((event,index)=>({event,index})).filter(x=>x.event.preview.status!=='SOURCE_PARSED');
  const current=problems[selected]??problems[0]??null;
  const raw=current?eventRaw(source,current.event):'';
  const rec=current?recommendation(current.event.preview,Boolean(neutralCsvColumnCount&&onUseNeutralCsvColumns),raw):null;
  const recipeImportEligible=!!rec&&rec.kind!=='metadata'&&rec.kind!=='split';
  const metadataPreserveEligible=Boolean(current&&rec?.kind==='metadata'&&draft&&onApplyCandidate&&
    current.event.preview.syntax.toUpperCase().includes('SECURITY_SYSLOG_BRACKET_COLON_KV'));
  const genericStructuralSourcePath=current&&draft?.guided&&onApplyCandidate?
    genericStructuralAnchor(source,events):null;
  const genericStructuralPreserveEligible=Boolean(genericStructuralSourcePath&&draft&&onApplyCandidate);
  const useExtractedGenericStructural=()=>{
    if(!genericStructuralSourcePath||!draft||!onApplyCandidate||!draft.guided)return;
    onApplyCandidate({...draft,format:'generic_structural',
      mappings:[{id:'generic-structural-source',source:genericStructuralSourcePath,
        target:'custom.source_field_001',type:'string'}],
      guided:{...draft.guided,enrichment:[],groups:{'generic-structural-source':'vendor_fields'},
        classification:{defaultIndex:'Syslog',rules:[]}}});
    setPromptOpen(false);setPromptText('');
    setCopyStatus('Parser Studio will use its built-in safe rule and preserve the extracted source fields.');
  };
  const preserveSourceMetadata=()=>{
    if(!metadataPreserveEligible||!draft||!onApplyCandidate)return;
    const opts=draft.guided;
    if(!opts)return;
    onApplyCandidate({...draft,format:'generic_structural',
      mappings:[{id:'metadata-source-pri',source:'syslog.pri',target:'custom.source_pri',type:'string'}],
      guided:{...opts,enrichment:[],groups:{'metadata-source-pri':'vendor_fields'},
        classification:{defaultIndex:'Syslog',rules:[]}}});
    setPromptOpen(false);setPromptText('');setCopyStatus('Source metadata will be preserved as text. No timestamp value was inferred.');
  };
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
    <div className={"beginner-analysis-head "+(problems.length||csvReviewPending?'needs-attention':'complete')}>
      {problems.length||csvReviewPending?<TriangleAlert size={22}/>:<CheckCircle2 size={22}/>}
      <div>
        <strong>{csvReviewPending||parserRuleReviewRequired
          ?`Values found in ${sourceParsed} of ${events.length} log event${events.length===1?'':'s'}`
          :`${parsed} of ${events.length} log event${events.length===1?'':'s'} parsed completely`}</strong>
        <p>{resolvedByReviewedCandidate
          ?'The reviewed parser fix passes the current sample in browser validation. Continue to review field meanings and create the parser draft.'
          :csvReviewPending
          ?!csvConsistentShapeAvailable
            ?'Parser Studio extracted the source values, but these positional rows do not share one consistent CSV shape. Analyze matching row shapes separately before continuing.'
            :neutralCsvColumnCount
              ?'Parser Studio extracted every source value, but this positional CSV does not contain trustworthy field names. Keep temporary names or enter your own before continuing.'
              :'Parser Studio extracted the source values, but this positional CSV still needs a matching separator plus column names before continuing.'
          :parserRuleReviewRequired
          ?'Parser Studio found the values, but it needs one more parsing step for this log shape before it can create files. The values already found will be kept.'
          :problems.length
          ?`${problems.length} event${problems.length===1?' needs':'s need'} attention. Parser Studio will show what remains and the safest next action.`
          :'No unresolved source region was found. Continue to review field meanings and create the parser draft.'}</p>
      </div>
    </div>
    {current&&<div className="beginner-problem" aria-label="Parse problem inspector">
      {problems.length>1&&<label>Problem to review
        <select aria-label="Problem event" value={selected} onChange={e=>{setSelected(Number(e.target.value));setPromptOpen(false);setPromptText('');setCopyStatus('');}}>
          {problems.map((item,i)=><option key={item.index} value={i}>Event {item.index+1} · {parserRuleReviewRequired?'One parsing step needs review':problemTitle(item.event.preview)}</option>)}
        </select>
      </label>}
      <h3>{parserRuleReviewRequired
        ?'Fields found — one more parsing step is needed'
        :problemTitle(current.event.preview)}</h3>
      <p>{parserRuleReviewRequired
        ?<>Parser Studio found the values in this <b>{friendlySyntax(current.event.preview,raw)}</b>, but it needs one more parsing step before it can create the parser files.</>
        :<>Parser Studio recognized <b>{friendlySyntax(current.event.preview,raw)}</b>, but it will not let you continue until the remaining review is resolved.</>}</p>
      <div className="beginner-problem-source">
        <span>Original event {current.index+1} · {parserRuleReviewRequired
          ?'one parsing step needs review'
          :metadataOnlyReview(current.event.preview)
            ?'time/header warning · all source text kept'
            :'highlighted text needs attention'}</span>
        <pre>{sourceSegments(raw,current.event.preview).map((segment,index)=>
          segment.kind==='problem'?<mark key={index}>{segment.text}</mark>:<span key={index}>{segment.text}</span>)}</pre>
      </div>
      <div className="beginner-problem-details">
        <div><strong>What needs attention</strong>
          {parserRuleReviewRequired
            ?<p>The field values are already available. Parser Studio needs one more parsing step for this message shape before it can create the files.</p>
            :current.event.preview.issues.length
              ?<ul>{current.event.preview.issues.map(code=><li key={code}>{plainIssue(code,raw)}</li>)}</ul>
              :<p>Parser Studio could not produce a complete trustworthy field set for this event.</p>}
        </div>
        <div><strong>{parserRuleReviewRequired?'What Parser Studio still needs':metadataOnlyReview(current.event.preview)?'Time or header review':'Text not yet assigned to fields'}</strong>
          {parserRuleReviewRequired
            ?<p>No source text is missing. Add one parsing step for this message shape, then test it against additional examples.</p>
            :current.event.preview.residuals.length
              ?current.event.preview.residuals.map((region,i)=><code key={i}>{utf8Slice(raw,region.startByte,region.endByte)}</code>)
              :metadataOnlyReview(current.event.preview)
                ?<p>All original source text was kept. The extracted fields are retained; review only the timestamp or log-header issue listed here.</p>
                :<p>No trustworthy smaller range is available, so the whole event should be reviewed.</p>}
        </div>
      </div>
      {rec&&<div className="beginner-fix">
        <Wrench size={18}/><div><strong>Recommended fix · {genericStructuralPreserveEligible?'Use the extracted fields':rec.label}</strong>
          <p>{genericStructuralPreserveEligible
            ?'Parser Studio already has a built-in safe rule for this structure. Use the extracted fields directly; no ChatGPT step is required.'
            :rec.kind==='metadata'&&!metadataPreserveEligible
              ?'Parser Studio kept the values it found, but it cannot safely create parser files while this header or time issue remains. Correct the source information or intentionally keep the affected value as text. ChatGPT can explain the problem, but Parser Studio will not guess missing time or header details.'
              :rec.text}</p></div>
      </div>}
      <div className="beginner-fix-actions">
        {rec?.kind==='csv'&&neutralCsvColumnCount&&onUseNeutralCsvColumns&&
          <button type="button" className="auto-parser-primary" onClick={onUseNeutralCsvColumns}>
            Keep all {neutralCsvColumnCount} values with temporary names
          </button>}
        {genericStructuralPreserveEligible&&<button type="button" className="auto-parser-primary"
          onClick={useExtractedGenericStructural}>
          Use extracted fields
        </button>}
        {metadataPreserveEligible&&<button type="button" className="auto-parser-primary"
          onClick={preserveSourceMetadata}>
          Keep the affected header/time value as text
        </button>}
        {rec?.kind!=='split'&&<button type="button" className={rec?.kind==='csv'||metadataPreserveEligible||genericStructuralPreserveEligible?'':'auto-parser-primary'} disabled={promptBusy}
          onClick={()=>void openPrompt()}>
          <Bot size={16}/> {promptBusy?'Preparing…':rec?.kind==='metadata'?'Review with ChatGPT':'Fix with ChatGPT'}
        </button>}
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
            onApplyCandidate={onApplyCandidate}
            protectedSourceValuesByEvent={protectedSourceValuesByEvent}
            protectedResidualTextByEvent={protectedResidualTextByEvent}/>
        </>}
        {recipeImportEligible&&draft&&!suite&&<div className="beginner-inline-wait" role="status">
          <strong>Preparing result review…</strong>
          <p>The local preview is still preparing the safe validation step. You can paste the ChatGPT result here as soon as it is ready.</p>
        </div>}
        {recipeImportEligible&&<button type="button" className="beginner-secondary-link" onClick={onOpenAssisted}>
          Use the full ChatGPT workflow instead
        </button>}
        {!recipeImportEligible&&<p className="beginner-manual-fix-note" role="note">
          The values were found. This is a log header or time problem, not a missing field-extraction step.
          Correct that source information or intentionally keep it as text after review.
        </p>}
      </div>}
    </div>}
  </section>;
}
