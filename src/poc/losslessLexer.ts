/**
 * A source-only, bounded, lossless tokenizer. It recognizes explicit syntax,
 * not vendor semantics or an approved target parser.
 */
export type Separator='space'|'pipe'|'semicolon'|'tab'|'comma';
export interface SourceSpan {
  start:number;
  end:number;
  startByte:number;
  endByte:number;
}
export interface SourceField {
  key:string;
  value:string;
  fieldSpan:SourceSpan;
  keySpan:SourceSpan|null;
  valueSpan:SourceSpan;
  rawValueSpan:SourceSpan;
}
export interface LexicalCandidate {
  grammar:string;
  naming:'source'|'positional';
  separator:Separator;
  fields:SourceField[];
  sourceRaw:string;
  bodyRaw:string;
  bodySpan:SourceSpan;
  prefixSpan:SourceSpan|null;
  repeatedKeys:string[];
  roundTrip:true;
}

const MAX_BYTES=16*1024;
const MAX_FIELDS=256;
const KEY=/^[A-Za-z_][A-Za-z0-9_.-]{0,127}/;
const UNSAFE=new Set(['__proto__','constructor','prototype']);
const encoder=new TextEncoder();
const UTF8=(value:string)=>encoder.encode(value).length;
const white=(char:string|undefined)=>char===' '||char==='\t';
const mark=(char:string)=>char==='\u2018'||char==='\u2019'||char==='\u201c'||char==='\u201d';

function safeSource(raw:string):boolean{
  if(!raw||raw.includes('\0')||/[\r\n]/.test(raw)||UTF8(raw)>MAX_BYTES)return false;
  for(let pos=0;pos<raw.length;pos++){
    const char=raw.charCodeAt(pos);
    if(char>=0xd800&&char<=0xdbff){
      if(pos+1>=raw.length||raw.charCodeAt(pos+1)<0xdc00||
        raw.charCodeAt(pos+1)>0xdfff)return false;
      pos++;continue;
    }
    if(char>=0xdc00&&char<=0xdfff)return false;
    if(char<32&&char!==9||char===127)return false;
  }
  return true;
}
function span(raw:string,start:number,end:number):SourceSpan{
  return {start,end,startByte:UTF8(raw.slice(0,start)),endByte:UTF8(raw.slice(0,end))};
}
function delimiter(char:string|undefined,separator:Separator):boolean{
  if(separator==='space')return white(char);
  return char===({pipe:'|',semicolon:';',tab:'\t',comma:','} as Record<string,string>)[separator];
}
function decodeQuoted(text:string,opening:number,separator:Separator):
  {value:string;contentStart:number;contentEnd:number;end:number}|null{
  const quote=text[opening];
  if(quote!=='"'&&quote!=="'")return null;
  let value='',pos=opening+1;
  while(pos<text.length){
    const char=text[pos]!;
    if(char===quote)return {value,contentStart:opening+1,contentEnd:pos,end:pos+1};
    if(char==='\\'){
      const next=text[pos+1];
      if(next===undefined||!['"',"'",'\\',']',
        separator==='space'?' ':separator==='pipe'?'|':separator==='semicolon'?';':
        separator==='tab'?'\t':','].includes(next))return null;
      value+=next;pos+=2;continue;
    }
    if(char.charCodeAt(0)<32&&char!=='\t'||char.charCodeAt(0)===127)return null;
    value+=char;pos++;
  }
  return null;
}
function validKey(
  key:string,seen:Map<string,string>,allowRepeat:boolean,repeated:string[],
):boolean{
  if(UNSAFE.has(key)||UNSAFE.has(key.replaceAll('-','_')))return false;
  const normalized=key.replaceAll('-','_');
  const previous=seen.get(normalized);
  if(previous!==undefined){
    if(previous!==key||!allowRepeat)return false;
    repeated.push(key);
    return true;
  }
  seen.set(normalized,key);
  return true;
}

/** Entire body must be accounted for by complete, uniquely named KV pairs. */
export function scanKeyValues(
  sourceRaw:string,bodyStart:number,separator:Separator,
  options?:{preserveRepeated?:boolean},
):LexicalCandidate|null{
  if(!safeSource(sourceRaw)||bodyStart<0||bodyStart>=sourceRaw.length)return null;
  const text=sourceRaw.slice(bodyStart);
  let pos=0;
  while(white(text[pos]))pos++;
  if(pos===text.length)return null;
  const fields:SourceField[]=[];
  const seen=new Map<string,string>();
  const repeatedKeys:string[]=[];
  while(pos<text.length){
    if(fields.length===MAX_FIELDS)return null;
    const start=pos;
    const found=KEY.exec(text.slice(pos));
    if(!found)return null;
    const key=found[0]!;
    if(!validKey(key,seen,options?.preserveRepeated===true,repeatedKeys))return null;
    const keyStart=pos;pos+=key.length;
    if(text[pos]!=='=')return null;
    pos++;
    const fullValueStart=pos;
    let value:string,contentStart:number,contentEnd:number;
    if(text[pos]==='"'||text[pos]==="'"){
      const token=decodeQuoted(text,pos,separator);
      if(!token)return null;
      value=token.value;
      contentStart=token.contentStart;
      contentEnd=token.contentEnd;
      pos=token.end;
    }else{
      contentStart=pos;
      while(pos<text.length&&!white(text[pos])&&!delimiter(text[pos],separator)){
        if(text[pos]==='"'||text[pos]==="'"||mark(text[pos]!))return null;
        if(text[pos]==='\\')return null;
        pos++;
      }
      contentEnd=pos;
      if(contentEnd===contentStart)return null;
      value=text.slice(contentStart,contentEnd);
    }
    const end=pos;
    const absolute=(x:number)=>bodyStart+x;
    const valueSpan=span(sourceRaw,absolute(contentStart),absolute(contentEnd));
    const rawValueSpan=span(sourceRaw,absolute(fullValueStart),absolute(end));
    const fieldSpan=span(sourceRaw,absolute(start),absolute(end));
    if(sourceRaw.slice(rawValueSpan.start,rawValueSpan.end).length===0)return null;
    fields.push({key,value,fieldSpan,keySpan:span(sourceRaw,absolute(keyStart),absolute(keyStart+key.length)),
      valueSpan,rawValueSpan});
    const beforeSeparator=pos;
    while(separator==='tab'?text[pos]===' ':white(text[pos]))pos++;
    if(pos===text.length)break;
    if(separator==='space'){
      if(beforeSeparator===pos)return null;
      continue;
    }
    if(!delimiter(text[pos],separator))return null;
    pos++;
    while(white(text[pos]))pos++;
    if(pos===text.length)return null;
  }
  if(fields.length<2)return null;
  return {grammar:'kv_'+separator,naming:'source',separator,fields,
    sourceRaw,bodyRaw:text,bodySpan:span(sourceRaw,bodyStart,sourceRaw.length),
    prefixSpan:null,repeatedKeys,roundTrip:true};
}

/** Positional CSV/TSV: labels are temporary indexes, not source column names. */
export function scanDelimitedRow(
  sourceRaw:string,bodyStart:number,separator:'comma'|'tab',
):LexicalCandidate|null{
  if(!safeSource(sourceRaw)||bodyStart<0||bodyStart>=sourceRaw.length)return null;
  const raw=sourceRaw.slice(bodyStart);
  const delim=separator==='comma'?',':'\t';
  if(!raw.includes(delim))return null;
  let pos=0;
  const fields:SourceField[]=[];
  while(pos<raw.length){
    if(fields.length===MAX_FIELDS)return null;
    const start=pos;
    let value='',contentStart=pos,contentEnd=pos,end=pos;
    if(raw[pos]==='"'){
      pos++;
      contentStart=pos;
      let closed=false;
      while(pos<raw.length){
        if(raw[pos]==='"'){
          if(raw[pos+1]==='"'){value+='"';pos+=2;continue;}
          contentEnd=pos;
          pos++;
          closed=true;
          break;
        }
        if(raw[pos]!==undefined&&(raw.charCodeAt(pos)<32&&raw[pos]!=='\t'||
          raw.charCodeAt(pos)===127))return null;
        value+=raw[pos]!;
        pos++;
      }
      if(!closed)return null;
    }else{
      while(pos<raw.length&&raw[pos]!==delim){
        if(raw[pos]==='"'||mark(raw[pos]!))return null;
        pos++;
      }
      contentEnd=pos;value=raw.slice(start,pos);
    }
    end=pos;
    if(pos<raw.length&&raw[pos]!==delim)return null;
    const toAbsolute=(n:number)=>bodyStart+n;
    fields.push({key:'column_'+String(fields.length+1),value,
      keySpan:null,fieldSpan:span(sourceRaw,toAbsolute(start),toAbsolute(end)),
      valueSpan:span(sourceRaw,toAbsolute(contentStart),toAbsolute(contentEnd)),
      rawValueSpan:span(sourceRaw,toAbsolute(start),toAbsolute(end))});
    if(pos===raw.length)break;
    pos++;
    if(pos===raw.length){
      fields.push({key:'column_'+String(fields.length+1),value:'',keySpan:null,
        fieldSpan:span(sourceRaw,toAbsolute(pos),toAbsolute(pos)),
        valueSpan:span(sourceRaw,toAbsolute(pos),toAbsolute(pos)),
        rawValueSpan:span(sourceRaw,toAbsolute(pos),toAbsolute(pos))});
      break;
    }
  }
  if(fields.length<3||fields.every(f=>f.value===''))return null;
  return {grammar:'csv_'+separator,naming:'positional',separator,fields,
    sourceRaw,bodyRaw:raw,bodySpan:span(sourceRaw,bodyStart,sourceRaw.length),
    prefixSpan:null,repeatedKeys:[],roundTrip:true};
}

/**
 * Vendor-neutral prefix recovery: retain, but never interpret, a single
 * leading metadata token. All following source fields use the same KV lexer.
 */
export function scanPrefixedKeyValues(
  sourceRaw:string,bodyStart:number,
):LexicalCandidate|null{
  if(!safeSource(sourceRaw)||bodyStart<0||bodyStart>=sourceRaw.length)return null;
  const text=sourceRaw.slice(bodyStart);
  const prefix=/^([^=\s]{1,255})[ \t]+(?=[A-Za-z_][A-Za-z0-9_.-]{0,127}=)/.exec(text);
  if(!prefix)return null;
  const valueStart=bodyStart+prefix[0].length;
  const suffix=scanKeyValues(sourceRaw,valueStart,'space',{preserveRepeated:true});
  if(!suffix)return null;
  return {...suffix,grammar:'prefixed_kv_space',
    bodyRaw:text,bodySpan:span(sourceRaw,bodyStart,sourceRaw.length),
    prefixSpan:span(sourceRaw,bodyStart,valueStart)};
}
