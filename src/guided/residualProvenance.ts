/**
 * Byte-level provenance of previously unparsed source regions (final re-audit H-2).
 *
 * The automatic parser reports, per event, the UTF-8 byte ranges it could not read (Multi-Pass residuals). A region
 * can span several tokens (" TCP_MISS/200 5120 GET "), and a correct ChatGPT recovery may read it into several
 * fields, so a region cannot be required to reappear whole in one output value. Counting its words anywhere in the
 * output is not evidence either: that accepted recipes that read literal digits as pattern text (IIS "0 0") or
 * dropped a sign (Apache "-0500" read as "-" + digits), verification D-1 of 3f363d2.
 *
 * The evidence here is per character and per byte. For a regex candidate (a standalone expression or a Syslog body
 * expression) the same portable expression the extractor runs is executed with match indices, giving the exact UTF-8
 * span every named capture read. A value-bearing character of a region is accounted for only when it lies inside a
 * capture whose text reaches the candidate's final output unchanged. Characters the expression consumes outside
 * every capture (literal or class text) are lost. A capture inside a repetition keeps only its last iteration, so such
 * an expression is refused. Whitespace and ASCII punctuation are syntax and may be consumed, except a + or - that
 * starts a number (a sign is part of the value).
 *
 * Anything this module cannot establish (another grammar, an expression that does not match, regions that do not
 * fall on character boundaries) is reported as unavailable; the caller then keeps its strict whole-region rule, so a
 * missing proof never accepts more than before.
 *
 * Pure and synchronous: regex candidates are evaluated in the preview worker (src/preview.worker.ts).
 */
import type {ParserDraft,SuiteResult} from '../model';
import {extractEvent} from '../grammar/extractEvent';
import {getTag} from '../grammar/primitives';
import {extractionSettingsOf,preview} from '../parser';
import {parsePortableRegexAst,portableRegexJavaScriptSource,type PortableRegexNode} from '../../backend/src/portable-regex';
import {validatePreviewRegexPattern} from '../regexSafety';
import {scalarValues,sourceAlternatives} from './sourceValueForms';

export const RESIDUAL_PROVENANCE_CONTRACT='parser-studio.residual-provenance.v1';
/** One previously unparsed region of one event, UTF-8 bytes relative to the event's first byte. */
export type ResidualRegion={startByte:number;endByte:number};
export type CaptureSpan={name:string;startByte:number;endByte:number;text:string};
export type ResidualRefusal='REPEATED_CAPTURE'|'UNACCOUNTED_SOURCE'|'CAPTURE_NOT_IN_OUTPUT';
export type ResidualAccountingEvent={
 /** 0-based event index. */
 event:number;
 method:'capture_spans'|'unavailable';
 /** Non-blank regions of the event. */
 required:number;
 /** Regions with at least one value-bearing character the candidate does not carry. */
 missing:number;
 reason?:ResidualRefusal|'NOT_REGEX'|'NO_MATCH'|'INVALID_REGION'|'EVENT_MISSING'|'NOT_EVALUATED';
 /** First unaccounted character, UTF-8 bytes in the event (no source text is reported). */
 firstUnaccounted?:{startByte:number;endByte:number};
};
export type ResidualAccounting={contract:typeof RESIDUAL_PROVENANCE_CONTRACT;events:ResidualAccountingEvent[]};

const WORD=/[\p{L}\p{N}\p{M}_]/u;
const SPACE=/\p{White_Space}/u;
const DIGIT=/\p{Nd}/u;

function utf8Length(point:number):number{return point<0x80?1:point<0x800?2:point<0x10000?3:4;}

/** UTF-8 byte offset of every UTF-16 index of `text` (length+1 entries; inner surrogate halves repeat the start). */
export function utf8Offsets(text:string):number[]{
 const offsets=new Array<number>(text.length+1);let bytes=0;
 for(let index=0;index<text.length;){
  const point=text.codePointAt(index)!;const width=point>0xffff?2:1;
  offsets[index]=bytes;if(width===2)offsets[index+1]=bytes;
  bytes+=utf8Length(point);index+=width;
 }
 offsets[text.length]=bytes;
 return offsets;
}

/** Where the value after a key ending at `index` may start: after `=` with optional blanks around it, and after one
 * opening quote or bracket (`key=v`, `key = v`, `key="v"` with the quotes inside or outside the capture, `key=[v]`;
 * re-audit F-5 and N-2); empty when no `=` follows the key. */
function keyValueStarts(text:string,index:number):number[]{
 let at=index;
 while(text[at]===' '||text[at]==='\t')at++;
 if(text[at]!=='=')return [];
 at++;
 while(text[at]===' '||text[at]==='\t')at++;
 return text[at]!==undefined&&'"\'[({'.includes(text[at]!)?[at,at+1]:[at];
}
function codePointBefore(text:string,index:number):string|undefined{
 if(index<=0)return undefined;
 const before=text.codePointAt(index-1)!;
 const point=before>=0xdc00&&before<=0xdfff&&index>=2?text.codePointAt(index-2)!:before;
 return String.fromCodePoint(point);
}
function codePointAfter(text:string,index:number):string|undefined{
 const point=text.codePointAt(index);
 if(point===undefined)return undefined;
 const next=text.codePointAt(index+(point>0xffff?2:1));
 return next===undefined?undefined:String.fromCodePoint(next);
}
const isDigit=(ch:string|undefined)=>ch!==undefined&&DIGIT.test(ch);
// Punctuation that only separates values: a pattern may read it as literal text outside every capture.
const SEPARATORS=new Set(['/','|',',',';','"',"'",'[',']','(',')','{','}','@','?','&','\\']);

/**
 * Whether the character at `index` carries value, so that a pattern may not read it as literal text outside every
 * capture: letters, digits, marks, `_` and every non-ASCII non-space character; a `-` before a digit or a decimal
 * point (a sign, also inside `-05:00`, `1e-5`, `-.5`) or after a non-word character before a word or another `-`
 * (`-inf`, `"-inf"`, `opt=-la`, `--verbose`; not `src-ip`); every `+` (`GMT+9`,
 * `C++`, `5+`); a `.` next to a digit or another `.` (`.5`, `1.2.3.4`); a `:` next to another `:` (IPv6 `::1`) or
 * between two digits (`10:00`, `1.2.3.4:443`); a `%` next to a digit; an `=` next to `=`, `!`, `<` or `>` (an
 * operator: `!=`, `<=`); and any punctuation that is not a plain separator (`!`, `<`, `>`, `~`, `^`, `*`, `$`, `#`). White space, a lone `-` placeholder and the separators above are syntax. A token such as
 * `10:00:00`, `ASA-6-302013` or `1.2.3.4:443` is split losslessly by capturing it whole and nesting the part captures
 * inside it (independent audit A-1 of 240b2e6).
 */
export function isValueBearing(text:string,index:number):boolean{
 const point=text.codePointAt(index);
 if(point===undefined)return false;
 const ch=String.fromCodePoint(point);
 if(SPACE.test(ch))return false;
 if(WORD.test(ch)||point>0x7f)return true;
 const previous=codePointBefore(text,index),next=codePointAfter(text,index);
 switch(ch){
  case '-':return isDigit(next)||next==='.'||
   ((previous===undefined||!WORD.test(previous))&&next!==undefined&&(WORD.test(next)||next==='-'));
  case '.':return isDigit(previous)||isDigit(next)||previous==='.'||next==='.';
  case ':':return previous===':'||next===':'||(isDigit(previous)&&isDigit(next));
  case '%':return isDigit(previous)||isDigit(next);
  case '=':return previous==='='||next==='='||previous==='!'||previous==='<'||previous==='>';
  default:return !SEPARATORS.has(ch);
 }
}

const LETTER=/\p{L}/u;
/** One character of `text` replaced by another of the same class, from the end of the text first. */
function substitutions(text:string):{index:number;width:number;replacement:string}[]{
 const out:{index:number;width:number;replacement:string}[]=[];
 for(let index=0;index<text.length;){
  const point=text.codePointAt(index)!;const width=point>0xffff?2:1;
  let replacement:number|null=null;
  if(point>=0x30&&point<=0x39)replacement=point<0x35?point+1:point-1;
  else if((point>=0x41&&point<=0x5a)||(point>=0x61&&point<=0x7a))replacement=point===0x5a||point===0x7a?point-1:point+1;
  else if(point===0x2d)replacement=0x2b;
  else if(point===0x2b)replacement=0x2d;
  else if(point>0x7f&&LETTER.test(String.fromCodePoint(point))){
   if(LETTER.test(String.fromCodePoint(point+1)))replacement=point+1;
   else if(LETTER.test(String.fromCodePoint(point-1)))replacement=point-1;
  }
  if(replacement!==null)out.push({index,width,replacement:String.fromCodePoint(replacement)});
  index+=width;
 }
 return out.reverse();
}

function captureInsideRepetition(node:PortableRegexNode,repeated=false):boolean{
 switch(node.kind){
  case 'sequence':return node.nodes.some(item=>captureInsideRepetition(item,repeated));
  case 'alternation':return node.branches.some(item=>captureInsideRepetition(item,repeated));
  case 'group':return (node.captureName!==null&&repeated)||captureInsideRepetition(node.body,repeated);
  case 'repeat':return captureInsideRepetition(node.atom,repeated||node.max===null||node.max>1);
  default:return false;
 }
}

/** Whether a draft reads events (or their Syslog bodies) with a portable named-capture expression. */
export function usesRegexExtraction(draft:ParserDraft):boolean{
 return draft.format==='regex'||((draft.format==='syslog_rfc3164'||draft.format==='syslog_rfc5424')&&
  draft.syslogBodyFormat==='regex');
}

/** The text the candidate's expression is applied to, and its UTF-16 offset in the event. */
function regexTarget(raw:string,draft:ParserDraft):{text:string;offset:number;pattern:string}|null{
 const pattern=draft.pattern??'';
 if(draft.format==='regex')return {text:raw,offset:0,pattern};
 if(!usesRegexExtraction(draft))return null;
 const format=draft.format as 'syslog_rfc3164'|'syslog_rfc5424';
 // The text the body expression read, as the extractor reports it (also for a tagless RFC 3164 message, which has no
 // raw-body reading: independent audit A-10); else the message of a raw-body reading.
 const read=extractEvent(raw,extractionSettingsOf(draft,format));
 const bodyText=read.errors.length?undefined:getTag(read,'bodyText');
 const head=typeof bodyText==='string'?undefined:extractEvent(raw,{...extractionSettingsOf(draft,format),syslogBodyFormat:'raw'});
 const message=typeof bodyText==='string'?bodyText:head&&!head.errors.length?head.fields.message:undefined;
 if(typeof message!=='string'||!raw.endsWith(message))return null;
 return {text:message,offset:raw.length-message.length,pattern};
}

/**
 * Exact UTF-8 spans (relative to the event) of every named capture the candidate's expression reads in one event.
 * `repeated` when a capture sits inside a repetition; null when the draft is not a regex draft or nothing matched.
 */
export function regexCaptureSpans(raw:string,draft:ParserDraft):
 {captures:CaptureSpan[]}|{repeated:true}|{unavailable:'NOT_REGEX'|'NO_MATCH'}{
 const target=regexTarget(raw,draft);
 if(!target)return {unavailable:'NOT_REGEX'};
 if(validatePreviewRegexPattern(target.pattern))return {unavailable:'NO_MATCH'};
 const ast=parsePortableRegexAst(target.pattern);
 if(!ast.ok)return {unavailable:'NO_MATCH'};
 if(captureInsideRepetition(ast.ast))return {repeated:true};
 let matched:RegExpExecArray|null;
 try{matched=new RegExp(portableRegexJavaScriptSource(target.pattern),'ud').exec(target.text);}
 catch{return {unavailable:'NO_MATCH'};}
 const groups=matched?.indices?.groups;
 if(!matched?.groups||!groups)return {unavailable:'NO_MATCH'};
 const offsets=utf8Offsets(raw);
 const captures:CaptureSpan[]=[];
 for(const [name,range] of Object.entries(groups)){
  const text=matched.groups[name];
  if(!range||text===undefined)continue;
  captures.push({name,startByte:offsets[target.offset+range[0]]!,endByte:offsets[target.offset+range[1]]!,text});
 }
 return {captures};
}

/** Byte regions of residual texts located left to right in the event (evidence that carries text only). */
export function locateResidualRegions(raw:string,texts:string[]):ResidualRegion[]|null{
 const offsets=utf8Offsets(raw);const regions:ResidualRegion[]=[];let from=0;
 for(const text of texts){
  const at=raw.indexOf(text,from);
  if(at<0)return null;
  regions.push({startByte:offsets[at]!,endByte:offsets[at+text.length]!});
  from=at+text.length;
 }
 return regions;
}

/** UTF-16 index of a UTF-8 byte offset, or -1 when the offset is not a character boundary of the event. */
function indexOfByte(offsets:number[],byte:number):number{
 let low=0,high=offsets.length-1;
 while(low<=high){
  const mid=(low+high)>>1;const value=offsets[mid]!;
  if(value===byte){
   let index=mid;while(index>0&&offsets[index-1]===byte)index--;
   return index;
  }
  if(value<byte)low=mid+1;else high=mid-1;
 }
 return -1;
}

/**
 * Account for every non-blank residual region of one candidate event. `normalized` is the candidate's final output
 * for the event; a capture counts only when its exact text (or a decoded form of it) is one output value, each
 * output value standing for one capture.
 */
export function accountEventResiduals(raw:string,normalized:Record<string,unknown>|undefined,draft:ParserDraft,
 regions:ResidualRegion[],event=0):ResidualAccountingEvent{
 const offsets=utf8Offsets(raw);
 const spans:{start:number;end:number}[]=[];
 for(const region of regions){
  const start=indexOfByte(offsets,region.startByte),end=indexOfByte(offsets,region.endByte);
  if(start<0||end<start)return {event,method:'unavailable',required:regions.length,missing:0,reason:'INVALID_REGION'};
  if(raw.slice(start,end).trim())spans.push({start,end});
 }
 const required=spans.length;
 if(!required)return {event,method:'capture_spans',required:0,missing:0};
 const evidence=regexCaptureSpans(raw,draft);
 if('unavailable' in evidence)return {event,method:'unavailable',required,missing:0,reason:evidence.unavailable};
 if('repeated' in evidence)return {event,method:'capture_spans',required,missing:required,reason:'REPEATED_CAPTURE'};
 // Every capture of the event must reach the final output, each output value standing for one capture. When the
 // output holds fewer copies of a text than the captures read, none of the captures reading it is accounted for:
 // a dropped capture cannot borrow the output value of another capture with the same text.
 const touching=evidence.captures.filter(capture=>capture.endByte>capture.startByte&&spans.some(span=>
  capture.startByte<offsets[span.end]!&&capture.endByte>offsets[span.start]!));
 const pool=scalarValues(normalized);const used=new Array(pool.length).fill(false);
 const matched=new Set<CaptureSpan>();const shortForms=new Set<string>();
 for(const capture of evidence.captures.filter(item=>item.text!=='')
  .sort((a,b)=>a.startByte-b.startByte||b.endByte-a.endByte)){
  const forms=sourceAlternatives(capture.text);
  const found=pool.findIndex((value,index)=>!used[index]&&forms.includes(value));
  if(found>=0){used[found]=true;matched.add(capture);}else for(const form of forms)shortForms.add(form);
 }
 const countable=(capture:CaptureSpan)=>matched.has(capture)&&
  !sourceAlternatives(capture.text).some(form=>shortForms.has(form));
 const counted=touching.filter(countable);
 // Differential evidence (audit A-3, re-audit F-2): equal output values cannot tell which capture an output value
 // came from (a capture mapped twice could stand in for a dropped capture with the same text), so each capture must
 // show that a field holding its text depends on it (captureCarried).
 const base=scalarPaths(normalized);
 const kept=new Set<CaptureSpan>(counted.filter(capture=>captureCarried(raw,offsets,capture,base,draft)));
 // A run of value-bearing characters no kept capture covers is lost, except a key name the expression reads as literal
 // text right before `=` and a kept capture of exactly that name (`arch=(?<arch>\S+)`): the field name preserves it.
 // A key not spelled exactly like its capture name (`src-ip`, a Hangul key read as `___`) is never exempt (audit A-2).
 // The capture of a key may lie outside every residual region: the analysis already read the value, so the region ends
 // at `key=` (`...|sip=` before a recognized address). It names the key all the same, on the evidence asked of a kept
 // capture: its own output value (countable) that depends on it (captureCarried).
 const namesKey=new Map<CaptureSpan,boolean>();
 const carriedOutside=(capture:CaptureSpan)=>{
  let known=namesKey.get(capture);
  if(known===undefined){
   known=!touching.includes(capture)&&countable(capture)&&captureCarried(raw,offsets,capture,base,draft);
   namesKey.set(capture,known);
  }
  return known;
 };
 const keyCapture=(key:string,valueStart:number)=>evidence.captures.some(capture=>
  capture.startByte===valueStart&&capture.name===key&&(kept.has(capture)||carriedOutside(capture)));
 let missing=0;let firstUnaccounted:{startByte:number;endByte:number}|undefined;let reason:ResidualRefusal|undefined;
 for(const span of spans){
  let regionLost=false;let run=null as {start:number;end:number;covered:boolean}|null;
  const closeRun=()=>{
   if(!run)return;
   const current=run;run=null;
   const exempt=!current.covered&&keyValueStarts(raw,current.end)
    .some(valueStart=>keyCapture(raw.slice(current.start,current.end),offsets[valueStart]!));
   if(exempt||regionLost)return;
   regionLost=true;
   firstUnaccounted??={startByte:offsets[current.start]!,endByte:offsets[current.end]!};
   reason??=current.covered?'CAPTURE_NOT_IN_OUTPUT':'UNACCOUNTED_SOURCE';
  };
  for(let index=span.start;index<span.end;){
   const point=raw.codePointAt(index)!;const width=point>0xffff?2:1;
   if(isValueBearing(raw,index)){
    const startByte=offsets[index]!,endByte=offsets[index+width]!;
    const covering=touching.filter(capture=>capture.startByte<=startByte&&capture.endByte>=endByte);
    if(covering.some(capture=>kept.has(capture)))closeRun();
    else if(run){run.end=index+width;run.covered||=covering.length>0;}
    else run={start:index,end:index+width,covered:covering.length>0};
   }else closeRun();
   index+=width;
  }
  closeRun();
  if(regionLost)missing++;
 }
 return {event,method:'capture_spans',required,missing,
  ...(missing?{reason,firstUnaccounted}:{})};
}

/** Every scalar of a parser output by its exact path (the strings `scalarValues` compares with source text). */
function scalarPaths(value:unknown,path='',out=new Map<string,string>()):Map<string,string>{
 if(value===null)out.set(path,'null');
 else if(Array.isArray(value))value.forEach((item,index)=>scalarPaths(item,path+'['+index+']',out));
 else if(typeof value==='object')for(const [key,item] of Object.entries(value as Record<string,unknown>))
  scalarPaths(item,path+'.'+JSON.stringify(key),out);
 else if(value!==undefined)out.set(path,String(value));
 return out;
}
/** Probe positions: the last, the first and the middle changeable character first, then the others from the end. */
function probeOrder<T>(options:T[]):T[]{
 if(options.length<3)return options;
 const order=[options.length-1,0,options.length>>1];
 for(let index=options.length-2;index>0;index--)if(!order.includes(index))order.push(index);
 return order.map(index=>options[index]!);
}
const MAX_PROBES=8;
/**
 * Whether the capture's own text reaches the candidate's output (field identity; re-audits of 4c04b0b and fbcb12f).
 * The holders are the output fields that hold the capture text exactly (or a decoded form of it). One character of
 * the capture is changed in the event; a probe counts only when the changed event still matches with the capture
 * reading the changed text and still has output. A probe decides:
 * - carried, when a holder then holds the changed text (the field follows this capture);
 * - not carried, when no holder changes (the text is held by a twin, a copy mapped twice, or nothing).
 * A holder that changes in another way (a cast that fails on the changed text, another event profile) decides
 * nothing. When no probe decides (fixed words such as `(?<proto>TCP|UDP)`, punctuation, values that only a cast
 * accepts), the capture is renamed in the expression: it is carried when a holder then changes (its mapping or its
 * preserved name made the holder). With event profiles a rename can change the route, so it proves nothing.
 */
function captureCarried(raw:string,offsets:number[],capture:CaptureSpan,base:Map<string,string>,draft:ParserDraft):boolean{
 const start=indexOfByte(offsets,capture.startByte),end=indexOfByte(offsets,capture.endByte);
 if(start<0||end<start||raw.slice(start,end)!==capture.text)return false;
 const forms=sourceAlternatives(capture.text);
 const holders=[...base].filter(([,value])=>forms.includes(value)).map(([path])=>path);
 if(!holders.length)return false;
 for(const option of probeOrder(substitutions(capture.text).reverse()).slice(0,MAX_PROBES)){
  const text=capture.text.slice(0,option.index)+option.replacement+capture.text.slice(option.index+option.width);
  const changed=raw.slice(0,start)+text+raw.slice(end);
  const spans=regexCaptureSpans(changed,draft);
  if(!('captures' in spans)||!spans.captures.some(item=>item.name===capture.name&&
   item.startByte===capture.startByte&&item.text===text))continue;
  const after=outputPaths(changed,draft);
  if(!after)continue;
  const changedForms=sourceAlternatives(text);
  if(holders.some(path=>{const value=after.get(path);return value!==undefined&&changedForms.includes(value);}))return true;
  if(holders.every(path=>after.get(path)===base.get(path)))return false;
  // A holder that disappears is a value its cast refuses (`true` to `truf`) or another route: other one-character
  // changes of the same value usually fail the same way, so the field name decides at once (re-audit F-7).
  if(holders.some(path=>!after.has(path)))break;
 }
 return carriedByName(raw,capture,holders,base,draft);
}
function outputPaths(raw:string,draft:ParserDraft):Map<string,string>|null{
 try{
  const events=preview(raw,draft).events;
  const normalized=events.length===1?events[0]!.normalized:undefined;
  return normalized?scalarPaths(normalized):null;
 }catch{return null;}
}
function carriedByName(raw:string,capture:CaptureSpan,holders:string[],base:Map<string,string>,draft:ParserDraft):boolean{
 if(draft.eventProfiles)return false;
 const pattern=draft.pattern??'';const marker=`(?<${capture.name}>`;
 if(pattern.split(marker).length!==2)return false;
 let name=capture.name+'_probe';
 while(pattern.includes(`(?<${name}>`))name+='_';
 const after=outputPaths(raw,{...draft,pattern:pattern.replace(marker,`(?<${name}>`)});
 return after!==null&&holders.some(path=>after.get(path)!==base.get(path));
}

/** Account the residual regions of a candidate's batch output (for tests, the suite can be supplied). */
export function accountResidualRegionsForSuite(suite:SuiteResult,draft:ParserDraft,
 regionsByEvent:ResidualRegion[][]):ResidualAccounting{
 const events:ResidualAccountingEvent[]=[];
 for(let index=0;index<regionsByEvent.length;index++){
  const regions=regionsByEvent[index]??[];
  if(!regions.length)continue;
  const event=suite.events[index];
  if(!event){events.push({event:index,method:'unavailable',required:regions.length,missing:0,reason:'EVENT_MISSING'});continue;}
  if(events.some(item=>item.missing>0)){
   // One unaccounted region already refuses the candidate; later events are not evaluated (re-audit F-7).
   events.push({event:index,method:'unavailable',required:regions.length,missing:0,reason:'NOT_EVALUATED'});continue;
  }
  events.push(accountEventResiduals(event.raw,event.normalized,draft,regions,index));
 }
 return {contract:RESIDUAL_PROVENANCE_CONTRACT,events};
}

/** Run the candidate on the source and account every event's residual regions (worker entry point). */
export function accountResidualRegions(source:string,draft:ParserDraft,regionsByEvent:ResidualRegion[][]):ResidualAccounting{
 if(!usesRegexExtraction(draft))return {contract:RESIDUAL_PROVENANCE_CONTRACT,events:regionsByEvent
  .map((regions,event)=>({event,method:'unavailable' as const,required:regions.length,missing:0,reason:'NOT_REGEX' as const}))
  .filter(item=>item.required>0)};
 return accountResidualRegionsForSuite(preview(source,draft),draft,regionsByEvent);
}
