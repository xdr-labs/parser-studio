import {useState} from 'react';
import {Bot,CheckCircle2,Clipboard,TriangleAlert,Wrench} from 'lucide-react';
import type {MultiPassSourcePreview} from './multipassPreviewClient';
import type {ParserDraft,SuiteResult} from '../model';
import AutoParserAIReview from './AutoParserAIReview';
import {buildBeginnerRepairPrompt} from './beginnerAiPrompt';
import {buildAutomaticGenericStructuralDraft} from './genericStructuralAutoDraft';

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
  compilerBlockedReason?:string;
  resolvedByReviewedCandidate?:boolean;
  metadataLineCount?:number;
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
function prefixedJson(raw:string):boolean{
  const open=raw.indexOf('{');
  if(open<1||open>64||!/^[A-Za-z0-9_.:/-]+[ \t]+$/.test(raw.slice(0,open)))return false;
  try{
    const value=JSON.parse(raw.slice(open));
    return !!value&&typeof value==='object'&&!Array.isArray(value);
  }catch{return false;}
}
function isZeekHeader(raw:string):boolean{
  return /^#(?:separator|fields|types|path|open|close)\b/.test(raw.trimStart());
}
function isWindowsEventXml(raw:string):boolean{
  return /^<Event(?:\s|>)/.test(raw.trimStart());
}
function plainIssue(code:string,raw=''):string{
  if(isZeekHeader(raw))
    return 'This is a Zeek log header describing fields, not an event. Copy the declared column names and separator before reviewing the data rows separately.';
  if(isWindowsEventXml(raw))
    return 'Windows Event XML is not a qualified input format. Export events as JSON before using Auto Parser; do not treat the XML as parsed.';
  if(prefixedJson(raw)&&code==='UNLABELED_CSV_NEEDS_CORPUS_CONFIRMATION')
    return 'This event contains valid JSON after a short text prefix, so its wrapper must be handled separately.';
  if(prefixedJson(raw)&&code==='SOURCE_SYNTAX_ERROR:CSV_GRAMMAR_INVALID')
    return 'The short text prefix prevents the normal JSON path from being used even though the JSON payload itself is valid.';
  const known:Record<string,string>={
    FRAMING_ORIGINAL_CONTAINER_NOT_IN_DRAFT_COMPILER:'Parser Studio recognized the original stream boundaries and useful values. The downloadable parser cannot yet be verified for this exact transport or container: review the values before creating a draft.',
    FRAMING_JOURNAL_FIELD_INVALID_OR_DUPLICATE:'A system journal entry has an invalid or repeated field; it was retained for manual review.',
    FRAMING_JOURNAL_MESSAGE_MISSING:'A journal entry lacks the expected MESSAGE field, so its completeness is not verified.',
    SCHEMA_CONTEXT_NOT_IN_DRAFT_COMPILER:'Parser Studio found the column names and values using the original declared header. This structure is not yet supported by the downloadable parser compiler. Review the fields or use ChatGPT Assisted Parser; do not treat the result as ready to deploy.',
    SCHEMA_ROW_INVALID:'This data row does not match the declared column structure. Check its field count and quoting; the source was not discarded.',
    SCHEMA_ROW_WITHOUT_VALID_HEADER:'The data line has no complete valid declared field header. Keep the source and review the format.',
    FRAMING_MULTILINE_CSV_REVIEW:'Quoted CSV content crosses physical lines. Parser Studio kept the complete logical source record, but native CSV parser creation with embedded line breaks is not verified.',
    FRAMING_TRUNCATED_CSV:'A CSV quoted field did not close. Review the original exporter quotation before assigning any columns.',
    FRAMING_CSV_BOUNDARY_LIMIT:'CSV quotation exceeded the bounded record limit. Export smaller samples or split the source manually without inventing field boundaries.',
    KV_QUOTE_UNCLOSED:'A quoted key/value field is not closed, so the rest of the event cannot be trusted as normal key/value data.',
    STRUCTURED_HEADER_INCOMPLETE:'The structured event header is incomplete. Check its fields and separators against the exporter format before continuing.',
    LEEF_DELIMITER_UNSUPPORTED:'The LEEF delimiter is outside the currently supported parser subset. For TAB-delimited LEEF 2.0, review the explicit |0x09| header form.',
    LEEF_VERSION_UNSUPPORTED:'This LEEF version is outside the currently supported parser subset. Check the version in the original exporter format.',
    LEEF_VERSION_INVALID:'The LEEF version could not be validated. Check the original header before creating parser files.',
    LEEF_INVALID_EXTENSION_TOKEN:'A LEEF extension field does not match the expected key=value boundary. Keep the source and check the delimiter and field spelling.',
    RFC5424_SD_UNCLOSED:'A structured section in the log header is not closed correctly.',
    RFC5424_DUPLICATE_SD_KEY:'A structured section in the log header repeats the same field name.',
    RFC5424_SD_TRAILING_SPACE_NONSTANDARD:'A structured section in the log header uses unusual spacing.',
    RFC5424_TIMESTAMP_INVALID:'The time in the log header is not complete or valid enough to use as an exact event time.',
    UNLABELED_CSV_NEEDS_CORPUS_CONFIRMATION:'The event contains comma-delimited text, but Parser Studio cannot confirm trustworthy column boundaries or names from this sample alone.',
    UNSUPPORTED_BSD_BODY:'The Syslog header was recognized but the message body still needs an extraction rule.',
    UNSUPPORTED_PRI_BODY:'The Syslog priority header was recognized, but the message text after it still needs an extraction rule.',
    NO_SUPPORTED_GRAMMAR:'None of the built-in parsing patterns matches this part of the event yet, so it needs an extra parsing rule.',
    RFC5424_HEADER_TOKEN_INVALID:'The Syslog header contains a token outside the supported grammar.',
  };
  return known[code]??'This part of the event does not match a built-in pattern yet, so it needs an extra parsing rule ('+code.replaceAll('_',' ').toLowerCase()+').';
}
function wholeEventNeedsRule(preview:MultiPassSourcePreview):boolean{
  return Object.keys(preview.fields).length===0&&
    preview.residuals.some(region=>region.startByte===0&&region.endByte>=preview.sourceBytes);
}
function leefHeaderNeedsReview(preview:MultiPassSourcePreview,raw=''):boolean{
  return (preview.syntax.toUpperCase().includes('LEEF')||raw.startsWith('LEEF:'))&&
    preview.issues.some(issue=>[
      'STRUCTURED_HEADER_INCOMPLETE','LEEF_DELIMITER_UNSUPPORTED',
      'LEEF_VERSION_UNSUPPORTED','LEEF_VERSION_INVALID',
    ].includes(issue));
}
function friendlySyntax(preview:MultiPassSourcePreview,raw=''):string{
  if(preview.syntax==='ZEEK_TSV_DECLARED')return 'Zeek data row with declared columns';
  if(preview.syntax==='W3C_EFL_DECLARED')return 'W3C data row with declared columns';
  if(isZeekHeader(raw))return 'Zeek column/header metadata';
  if(isWindowsEventXml(raw))return 'unsupported Windows Event XML';
  if(preview.issues.some(issue=>issue.startsWith('FRAMING_')&&issue.includes('CSV')))
    return 'CSV record with quoted line breaks';
  const syntax=preview.syntax.toUpperCase();
  if(syntax.includes('LEEF_2_IMPLICIT_TAB'))return 'LEEF event with implicit TAB delimiters';
  if(leefHeaderNeedsReview(preview,raw))return 'LEEF header needing review';
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
function recommendation(preview:MultiPassSourcePreview,canUseNeutralCsvNames=false,raw='',needsReviewedParserRule=false):{kind:'metadata'|'json'|'cef'|'leef'|'csv'|'kv'|'message'|'text'|'assisted'|'split';label:string;text:string}{
  const syntax=preview.syntax.toUpperCase();
  const issues=preview.issues.join(' ').toUpperCase();
  if(syntax.includes('LEEF_2_IMPLICIT_TAB'))return {
    kind:'leef',
    label:'Review the LEEF delimiter before creating parser files',
    text:'The source values were extracted from an implicit TAB-delimited LEEF event. This exact event does not match the currently reviewed downloadable parser grammar. If your exporter can produce an explicit delimiter, edit a copy of the LEEF 2.0 input to place |0x09| before its TAB-separated key=value fields, then analyze that input again. Any parser files created from the edited sample target the explicit form; the original input was not changed automatically.',
  };
  if(leefHeaderNeedsReview(preview,raw))return {
    kind:'leef',
    label:'Check the LEEF header and delimiter',
    text:'The LEEF header could not be fully read. Compare its fields and pipe separators with the exporter format. The reviewed LEEF 2.0 parser supports an explicit delimiter field, such as |0x09| before TAB-separated key=value fields. Correct the input yourself when appropriate and analyze it again; Parser Studio keeps the original text until you edit it.',
  };
  // Extraction and parser-file readiness are independent. Never ask a
  // beginner to recover missing text when the source ledger is complete.
  if(needsReviewedParserRule&&preview.status==='SOURCE_PARSED'&&preview.residuals.length===0)return {
    kind:'assisted',
    label:'Review parser-file support for these fields',
    text:'The source fields were extracted, including any complete message body. No source text remains to recover. Review a supported parser rule and test it against additional log examples before creating files. A complete source preview does not verify native or Stellar Cyber parser compatibility.',
  };
  if(['W3C_EFL_DECLARED','ZEEK_TSV_DECLARED'].includes(preview.syntax))return {
    kind:'assisted',
    label:'Review the recognized columns before making parser files',
    text:'Parser Studio matched the original header to each data row and kept the original source positions. Downloadable parser support for this original header-dependent stream is not verified. Inspect the field values or use ChatGPT Assisted Parser after redaction; do not convert the result into a certified parser automatically.',
  };
  if(isZeekHeader(raw))return {
    kind:'split',
    label:'Separate Zeek header lines from data events',
    text:'Lines beginning #separator or #fields define the format; they are not event data. Copy field names from #fields, paste the data rows separately, choose TAB as the CSV separator, and review every column before continuing. No header line was automatically discarded.',
  };
  if(isWindowsEventXml(raw))return {
    kind:'assisted',
    label:'Export Windows Event logs as JSON',
    text:'Parser Studio does not safely extract Windows Event XML. Export the same events as JSON, then paste them into Auto Parser. ChatGPT Assisted Parser can explain the conversion after you remove private identifiers; it cannot verify XML import here.',
  };
  if(issues.includes('FRAMING_MULTILINE_CSV')||issues.includes('FRAMING_TRUNCATED_CSV')||issues.includes('FRAMING_CSV_BOUNDARY_LIMIT'))return {
    kind:'assisted',
    label:'Review the CSV record boundary and closing quotes',
    text:'The log record contains a quoted line break or unfinished quote. Its bytes were preserved but the native DRAFT compiler does not support this multi-line CSV input. Export one event per line or correct the quoting, then re-analyze before entering field names.',
  };
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
    label:'Review the LEEF extension fields',
    text:'Keep the values already found and review the highlighted extension text. Check each key=value field and its declared delimiter before creating parser files.',
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
    (issues.includes('SCHEMA_CONTEXT_NOT_IN_DRAFT_COMPILER')||issues.includes('SOURCE_TIMESTAMP_INVALID')||issues.includes('RFC5424_TIMESTAMP_INVALID')||issues.includes('RFC5424_DUPLICATE_SD_KEY')||
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
  resolvedByReviewedCandidate=false,metadataLineCount=0,compilerBlockedReason,parserRuleReviewRequired=false,parserRuleReviewEventIndexes,
  csvReviewRequired=false,csvConsistentShapeAvailable=true,neutralCsvColumnCount,onUseNeutralCsvColumns,protectedSourceValuesByEvent,
  protectedResidualTextByEvent}:Props){
  const [selected,setSelected]=useState(0);
  const [promptOpen,setPromptOpen]=useState(false);
  const [promptText,setPromptText]=useState('');
  const [promptBusy,setPromptBusy]=useState(false);
  const [copyStatus,setCopyStatus]=useState('');
  const sourceParsed=events.filter(x=>x.preview.status==='SOURCE_PARSED').length;
  const multilineCsvNeedsReview=events.some(event=>event.preview.issues.some(
    code=>code.startsWith('FRAMING_')&&code.includes('CSV')));
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
  const rec=current?recommendation(current.event.preview,Boolean(neutralCsvColumnCount&&onUseNeutralCsvColumns),raw,parserRuleReviewRequired):null;
  const preservedSpans=current?.event.preview.spans??[];
  const textRecovery=Boolean(current&&!parserRuleReviewRequired&&rec&&
    (rec.kind==='message'||rec.kind==='text'||
      (rec.kind==='assisted'&&current.event.preview.syntax.includes('GENERIC_'))));
  const recipeImportEligible=!!rec&&rec.kind!=='metadata'&&rec.kind!=='split';
  const metadataPreserveEligible=Boolean(current&&rec?.kind==='metadata'&&draft&&onApplyCandidate&&
    current.event.preview.syntax.toUpperCase().includes('SECURITY_SYSLOG_BRACKET_COLON_KV'));
  const genericStructuralCandidate=current&&draft&&onApplyCandidate?
    buildAutomaticGenericStructuralDraft(source,draft):null;
  const genericStructuralPreserveEligible=Boolean(genericStructuralCandidate&&draft&&onApplyCandidate);
  const useExtractedGenericStructural=()=>{
    if(!genericStructuralCandidate||!onApplyCandidate)return;
    onApplyCandidate(genericStructuralCandidate.draft);
    setPromptOpen(false);setPromptText('');
    setCopyStatus('Parser Studio used the complete built-in structure and prepared the extracted fields for mapping.');
  };
  const preserveSourceMetadata=()=>{
    if(!metadataPreserveEligible||!draft||!onApplyCandidate)return;
    const opts=draft.guided;
    if(!opts)return;
    onApplyCandidate({...draft,format:'generic_structural',
      mappings:[{id:'metadata-source-pri',source:'syslog.pri',target:'source_pri',type:'string'}],
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
    <div className={"beginner-analysis-head "+(problems.length||csvReviewPending||compilerBlockedReason?'needs-attention':'complete')}>
      {problems.length||csvReviewPending||compilerBlockedReason?<TriangleAlert size={22}/>:<CheckCircle2 size={22}/>}
      <div>
        <strong>{compilerBlockedReason
          ?`Source values found in ${sourceParsed} of ${events.length} events — downloadable parser not ready`
          :csvReviewPending||parserRuleReviewRequired
          ?`Values found in ${sourceParsed} of ${events.length} log event${events.length===1?'':'s'}`
          :`${parsed} of ${events.length} log event${events.length===1?'':'s'} parsed completely`}</strong>
        <p>{compilerBlockedReason
          ?'Original values were extracted, but a verified downloadable parser cannot be prepared for this shape yet. See the recovery instructions below; no source was dropped.'
          :resolvedByReviewedCandidate
          ?'The reviewed parser fix passes the current sample in browser validation. Continue to review field meanings and create the parser draft.'
          :csvReviewPending
          ?!csvConsistentShapeAvailable
            ?'Parser Studio extracted the source values, but these positional rows do not share one consistent CSV shape. Analyze matching row shapes separately before continuing.'
            :neutralCsvColumnCount
              ?'Parser Studio extracted every source value, but this positional CSV does not contain trustworthy field names. Keep temporary names or enter your own before continuing.'
              :'Parser Studio extracted the source values, but this positional CSV still needs a matching separator plus column names before continuing.'
          :parserRuleReviewRequired
          ?'All original values were extracted, but parser-file creation still needs a reviewed rule for this log shape. No source data was discarded.'
          :problems.length
          ?`${problems.length} event${problems.length===1?' needs':'s need'} attention. Parser Studio will show what remains and the safest next action.`
          :'No unresolved source region was found. Source extraction is complete; parser-file support will be checked separately when you continue.'}</p>
        {multilineCsvNeedsReview&&<p role="note" aria-label="Multiline CSV recovery">
          Quoted CSV data spans multiple physical lines. The source record was kept intact, but this input is not approved for native parser generation. Choose the affected event below to see how to export a safe one-event-per-line sample.
        </p>}
      </div>
    </div>
    {metadataLineCount>0&&<p className="beginner-source-accounting" role="note"
      aria-label="Source header versus data event explanation">
      The input contains {events.length} data event{events.length===1?'':'s'} and
      {' '}{metadataLineCount} schema/header line{metadataLineCount===1?'':'s'}.
      Header lines describe the log format, are preserved as original source,
      and are not additional data events. Parser-file support for the original
      header-dependent stream is checked separately.
    </p>}
    {current&&<div className="beginner-problem" aria-label="Parse problem inspector">
      {problems.length>1&&<label>Problem to review
        <select aria-label="Problem event" value={selected} onChange={e=>{setSelected(Number(e.target.value));setPromptOpen(false);setPromptText('');setCopyStatus('');}}>
          {problems.map((item,i)=><option key={item.index} value={i}>Event {item.index+1} · {parserRuleReviewRequired?'Parser rule needs review':problemTitle(item.event.preview)}</option>)}
        </select>
      </label>}
      <h3>{parserRuleReviewRequired
        ?'Fields extracted — parser rule needs review'
        :problemTitle(current.event.preview)}</h3>
      <p>{parserRuleReviewRequired
        ?<>Parser Studio extracted the values in this <b>{friendlySyntax(current.event.preview,raw)}</b>. A reviewed parser rule is still required to create files; source extraction alone does not verify compatibility.</>
        :<>Parser Studio recognized <b>{friendlySyntax(current.event.preview,raw)}</b>, but it will not let you continue until the remaining review is resolved.</>}</p>
      <div className="beginner-problem-source">
        <span>Original event {current.index+1} · {parserRuleReviewRequired
          ?'parser-file rule needs review'
          :metadataOnlyReview(current.event.preview)
            ?'time/header warning · all source text kept'
            :'highlighted text needs attention'}</span>
        <pre>{sourceSegments(raw,current.event.preview).map((segment,index)=>
          segment.kind==='problem'?<mark key={index}>{segment.text}</mark>:<span key={index}>{segment.text}</span>)}</pre>
      </div>
      <div className="beginner-problem-details">
        <div><strong>What needs attention</strong>
          {parserRuleReviewRequired
            ?<p>The source field values are available. Parser Studio has not yet validated a downloadable parser rule for this log shape.</p>
            :current.event.preview.issues.length
              ?<ul>{current.event.preview.issues.map(code=><li key={code}>{plainIssue(code,raw)}</li>)}</ul>
              :<p>Parser Studio could not produce a complete trustworthy field set for this event.</p>}
        </div>
        <div><strong>{parserRuleReviewRequired?'What Parser Studio still needs':metadataOnlyReview(current.event.preview)?'Time or header review':'Text not yet assigned to fields'}</strong>
          {parserRuleReviewRequired
            ?<p>No source text is missing. Review a supported parser rule and test it against additional examples before creating parser files.</p>
            :current.event.preview.residuals.length
              ?current.event.preview.residuals.map((region,i)=><code key={i}>{utf8Slice(raw,region.startByte,region.endByte)}</code>)
              :metadataOnlyReview(current.event.preview)
                ?<p>All original source text was kept. The extracted fields are retained; review only the timestamp or log-header issue listed here.</p>
                :<p>No trustworthy smaller range is available, so the whole event should be reviewed.</p>}
        </div>
      </div>
      {preservedSpans.length>0&&<details className="beginner-technical-details" aria-label="Preserved source values">
        <summary>Values already found · {preservedSpans.length}</summary>
        <p>Review these exact values from the original event while fixing the highlighted text. Field names describe the current extraction; review their meaning before mapping them.</p>
        <table>
          <thead><tr><th>Source field</th><th>Value in the original log</th></tr></thead>
          <tbody>{preservedSpans.map((span,index)=><tr key={index}>
            <td><code>{span.path}</code></td>
            <td><code>{span.startByte===span.endByte?'(empty value)':utf8Slice(raw,span.startByte,span.endByte)}</code></td>
          </tr>)}</tbody>
        </table>
      </details>}
      {rec&&<div className="beginner-fix">
        <Wrench size={18}/><div><strong>Recommended fix · {genericStructuralPreserveEligible?'Use the extracted fields':rec.label}</strong>
          <p>{genericStructuralPreserveEligible
            ?'Parser Studio already has a built-in safe rule for this structure. Use the extracted fields directly; no ChatGPT step is required.'
            :rec.kind==='metadata'&&!metadataPreserveEligible
              ?'Parser Studio kept the values it found, but it cannot safely create parser files while this header or time issue remains. Correct the header or time in your log input (for example, add the missing time zone) and click Analyze Logs again. ChatGPT can explain the problem, but Parser Studio will not guess missing time or header details.'
              :rec.text}</p></div>
      </div>}
      {textRecovery&&!genericStructuralPreserveEligible&&<div className="beginner-next-step" aria-label="Text recovery steps">
        <strong>Continue with a reviewed fix</strong>
        <ol>
          <li>Choose Fix with ChatGPT to prepare a prompt with this event, the values already found, and the highlighted text. Review or redact it before sharing.</li>
          <li>Paste the proposed result into the review below. Test it against the current logs and additional examples; check that existing values stay intact.</li>
          <li>Apply the fix only after reviewing the test results. Then continue to Review Fields, Map Fields, and Create Parser. Parser-file support is checked separately.</li>
        </ol>
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
        <p className="auto-parser-warning" role="note">
          This prompt may include your complete original log input, not just the selected
          event, and any unparsed source regions. Review the prompt and redact any
          sensitive values before sharing. Parser Studio never sends it automatically.
        </p>
        <textarea aria-label="Generated ChatGPT repair prompt" value={promptText}
          onChange={event=>setPromptText(event.target.value)} rows={14}/>
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
