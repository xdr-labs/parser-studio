import {parseSyslogEnvelope} from '../syslogEnvelope';
import {scanDelimitedRow,scanKeyValues,scanPrefixedKeyValues,type LexicalCandidate,type Separator} from './losslessLexer';

/**
 * Evidence only: a candidate is never certified as source-correct and this
 * module does not replace the qualified product parser.
 */
export type GrammarDisposition=
  'candidate_only'|'partial_candidate'|'ambiguous'|'raw_only'|'invalid_envelope'|'baseline_preserved';
export interface GrammarEvidence {
  grammar:string;
  naming:'source'|'positional';
  fieldCount:number;
  mappedValueBytes:number;
  bodyBytes:number;
  fullBodyCovered:boolean;
  tokenSpansReplayed:boolean;
  sourceOracleVerified:false;
  unparsedPrefixBytes:number;
  repeatedSourceKeys:number;
}
export interface GrammarInspection {
  disposition:GrammarDisposition;
  selected:GrammarEvidence|null;
  candidates:GrammarEvidence[];
  bodyStart:number|null;
  passes:2;
  note:string;
}

const SEP:Separator[]=['space','pipe','semicolon','tab','comma'];
const MAX_RAW_BYTES=16384;
const encoder=new TextEncoder();
const bytes=(raw:string)=>encoder.encode(raw).byteLength;

function bodyStart(raw:string):number|null{
  const envelope=parseSyslogEnvelope(raw);
  if(!envelope){
    if(/^<\d{1,3}>/.test(raw))return null;
    return 0;
  }
  if(!envelope.message||!raw.endsWith(envelope.message))return null;
  return raw.length-envelope.message.length;
}

function delimiterText(separator:Separator):RegExp{
  switch(separator){
    case 'space':return /^[ \t]+$/;
    case 'pipe':return /^[ \t]*\|[ \t]*$/;
    case 'semicolon':return /^[ \t]*;[ \t]*$/;
    case 'tab':return /^[ \t]*\t[ \t]*$/;
    case 'comma':return /^[ \t]*,[ \t]*$/;
  }
}

/** Decode the original source slice, without trusting the candidate's decoded value. */
function replaySourceValue(fragment:string,separator:Separator):string|null{
  if(!fragment)return null;
  const quote=fragment[0];
  if(quote==='"'||quote==="'"){
    if(fragment.length<2||fragment[fragment.length-1]!==quote)return null;
    let decoded='';
    for(let i=1;i<fragment.length-1;i++){
      const char=fragment[i]!;
      if(char===quote)return null;
      if(char==='\\'){
        const escaped=fragment[++i];
        const allowed=separator==='space'?' ':separator==='pipe'?'|':
          separator==='semicolon'?';':separator==='tab'?'\t':',';
        if(escaped===undefined||!['"',"'",'\\',']',allowed].includes(escaped))return null;
        decoded+=escaped;
      }else{
        if(char.charCodeAt(0)<32&&char!=='\t'||char.charCodeAt(0)===127)return null;
        decoded+=char;
      }
    }
    return decoded;
  }
  if(/[\\'"\u2018-\u201d]/u.test(fragment))return null;
  const splitter=separator==='space'?/[ \t]/:separator==='pipe'?/[ \t|]/:
    separator==='semicolon'?/[ \t;]/:separator==='tab'?/[ \t]/:/[ \t,]/;
  if(splitter.test(fragment))return null;
  return fragment;
}

/** RFC4180 quoted CSV replay, including doubled quotation marks. */
function replayCsvValue(fragment:string):string|null{
  if(fragment.startsWith('"')){
    if(!fragment.endsWith('"')||fragment.length<2)return null;
    const inner=fragment.slice(1,-1);
    const decoded=inner.replace(/""/g,'');
    if(decoded.includes('"'))return null;
    return inner.replace(/""/g,'"');
  }
  return fragment.includes('"')?null:fragment;
}

/** Second pass independently replays span boundaries and separators. */
export function replayCandidate(candidate:LexicalCandidate):GrammarEvidence|null{
  const raw=candidate.sourceRaw,fields=candidate.fields;
  if(fields.length<2||fields.length>256)return null;
  const prefix=candidate.prefixSpan;
  if(prefix&&(prefix.start!==candidate.bodySpan.start||
    prefix.end>candidate.bodySpan.end||
    !/^[^=\s]{1,255}[ \t]+$/.test(raw.slice(prefix.start,prefix.end))))return null;
  let pos=prefix?.end??candidate.bodySpan.start;
  let valueBytes=0;
  for(let index=0;index<fields.length;index++){
    const field=fields[index]!;
    const gap=raw.slice(pos,field.fieldSpan.start);
    if(index===0){
      if(!/^[ \t]*$/.test(gap))return null;
    }else if(candidate.naming==='source'){
      if(!delimiterText(candidate.separator).test(gap))return null;
    }else if(gap!==(candidate.separator==='tab'?'\t':',')){
      return null;
    }
    if(field.fieldSpan.start<pos||field.fieldSpan.end>candidate.bodySpan.end||
      field.fieldSpan.start>field.fieldSpan.end)return null;
    const keySpan=field.keySpan;
    if(candidate.naming==='source'){
      if(keySpan===null||raw.slice(keySpan.start,keySpan.end)!==field.key||
        keySpan.start!==field.fieldSpan.start)return null;
    }else if(keySpan!==null)return null;
    if(field.valueSpan.start<field.fieldSpan.start||
       field.valueSpan.end>field.fieldSpan.end||
       field.rawValueSpan.start<field.fieldSpan.start||
       field.rawValueSpan.end>field.fieldSpan.end)return null;
    for(const s of [field.fieldSpan,field.valueSpan,field.rawValueSpan,...(keySpan?[keySpan]:[])]){
      if(bytes(raw.slice(0,s.start))!==s.startByte||
         bytes(raw.slice(0,s.end))!==s.endByte)return null;
    }
    if(candidate.naming==='source'){
      if(!keySpan||raw.slice(field.fieldSpan.start,field.fieldSpan.end)
        .startsWith(field.key+'=')===false)return null;
      if(field.rawValueSpan.start!==keySpan.end+1||
        raw.slice(keySpan.end,field.rawValueSpan.start)!=='='||
        field.rawValueSpan.end!==field.fieldSpan.end)return null;
      const lexicalRaw=raw.slice(field.rawValueSpan.start,field.rawValueSpan.end);
      const decoded=replaySourceValue(lexicalRaw,candidate.separator);
      if(decoded===null||decoded!==field.value)return null;
      if(lexicalRaw.startsWith('"')||lexicalRaw.startsWith("'")){
        if(field.valueSpan.start!==field.rawValueSpan.start+1||
          field.valueSpan.end!==field.rawValueSpan.end-1)return null;
      }else if(field.valueSpan.start!==field.rawValueSpan.start||
         field.valueSpan.end!==field.rawValueSpan.end)return null;
    }else{
      if(field.rawValueSpan.start!==field.fieldSpan.start||
        field.rawValueSpan.end!==field.fieldSpan.end)return null;
      const lexicalRaw=raw.slice(field.rawValueSpan.start,field.rawValueSpan.end);
      if(replayCsvValue(lexicalRaw)!==field.value)return null;
      if(lexicalRaw.startsWith('"')){
        if(field.valueSpan.start!==field.fieldSpan.start+1||
          field.valueSpan.end!==field.fieldSpan.end-1)return null;
      }else if(field.valueSpan.start!==field.fieldSpan.start||
        field.valueSpan.end!==field.fieldSpan.end)return null;
    }
    valueBytes+=field.valueSpan.endByte-field.valueSpan.startByte;
    pos=field.fieldSpan.end;
  }
  const tail=raw.slice(pos,candidate.bodySpan.end);
  if(candidate.naming==='source'){
    if(!/^[ \t]*$/.test(tail))return null;
  }else if(tail!=='')return null;
  if(candidate.bodySpan.end!==raw.length||candidate.bodySpan.startByte!==bytes(raw.slice(0,candidate.bodySpan.start))||
    candidate.bodySpan.endByte!==bytes(raw))return null;
  return {grammar:candidate.grammar,naming:candidate.naming,
    fieldCount:fields.length,mappedValueBytes:valueBytes,
    bodyBytes:candidate.bodySpan.endByte-candidate.bodySpan.startByte,
    fullBodyCovered:prefix===null&&candidate.repeatedKeys.length===0,
    tokenSpansReplayed:true,sourceOracleVerified:false,
    unparsedPrefixBytes:prefix?prefix.endByte-prefix.startByte:0,
    repeatedSourceKeys:candidate.repeatedKeys.length};
}

function fingerprint(candidate:LexicalCandidate):string{
  return JSON.stringify(candidate.fields.map(f=>[f.key,f.value]));
}

/**
 * Pass 1: try eight bounded grammars without vendor guesses.
 * Pass 2: independently replay byte spans, enforce full consumption,
 * and abstain on incompatible candidate interpretations.
 */
export function inspectGrammarFunnel(raw:string,baselineOk=false):GrammarInspection{
  const none=(disposition:GrammarDisposition,note:string):GrammarInspection=>({
    disposition,selected:null,candidates:[],bodyStart:null,passes:2,note,
  });
  if(!raw||bytes(raw)>MAX_RAW_BYTES||/[\0\r\n]/.test(raw))
    return none('raw_only','Bounded single-record input required');
  if((raw.trimStart().startsWith('{')||raw.trimStart().startsWith('['))||raw.startsWith('CEF:')||raw.startsWith('LEEF:'))
    return none(baselineOk?'baseline_preserved':'raw_only','Existing structured format owns this record');
  const start=bodyStart(raw);
  if(start===null)return none('invalid_envelope','Malformed or unsupported Syslog envelope');
  const lexical:LexicalCandidate[]=[];
  for(const separator of SEP){
    const possible=scanKeyValues(raw,start,separator,{preserveRepeated:true});
    if(possible)lexical.push(possible);
  }
  const prefixed=scanPrefixedKeyValues(raw,start);
  if(prefixed)lexical.push(prefixed);
  for(const separator of ['comma','tab'] as const){
    const possible=scanDelimitedRow(raw,start,separator);
    if(possible)lexical.push(possible);
  }
  const checked=lexical.map(candidate=>({candidate,evidence:replayCandidate(candidate)}))
    .filter((item):item is {candidate:LexicalCandidate;evidence:GrammarEvidence}=>item.evidence!==null);
  const evidence=checked.map(item=>item.evidence);
  if(baselineOk)return {disposition:'baseline_preserved',selected:null,candidates:evidence,
    bodyStart:start,passes:2,note:'Qualified baseline preserved; suggestions cannot replace it'};
  if(checked.length===0)return {disposition:'raw_only',selected:null,candidates:[],
    bodyStart:start,passes:2,note:'No fully consumed bounded grammar'};
  // Explicit named source keys are stronger evidence than anonymous CSV columns.
  const mostSpecific=checked.some(item=>item.evidence.naming==='source')?
    checked.filter(item=>item.evidence.naming==='source'):checked;
  const meanings=new Set(mostSpecific.map(item=>fingerprint(item.candidate)));
  if(meanings.size!==1)return {disposition:'ambiguous',selected:null,candidates:evidence,
    bodyStart:start,passes:2,note:'Competing interpretations disagree on exact field values'};
  const winner=mostSpecific[0]!.evidence;
  const partial=winner.unparsedPrefixBytes>0||winner.repeatedSourceKeys>0;
  return {disposition:partial?'partial_candidate':'candidate_only',
    selected:winner,candidates:evidence,
    bodyStart:start,passes:2,
    note:partial?'Preserved unparsed prefix or repeated source keys; manual review required':
      'Lexically bounded, not independently source-certified or normalized'};
}
