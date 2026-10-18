/**
 * Review-only exact boundary literals, explicitly supplied by the author.
 * A match is source evidence, NOT an exportable Ruby compiler rule.
 * No implicit heuristics, variable-length guessing or source rewriting.
 */
export type DeclaredSourceBoundaries={prefix:string;postfix:string};
export type BoundaryRecord={
  line:number; raw:string; payload:string;
  recordStartByte:number; payloadStartByte:number; payloadEndByte:number; recordEndByte:number;
  matched:boolean;
};
export type BoundaryReview={
  status:'NONE'|'EXACT_PREVIEW'|'REVIEW_ONLY'|'INVALID';
  code:'NO_MARKERS'|'MATCHED_ALL'|'INCONSISTENT_MARKERS'|'INVALID_MARKERS'|'UNSAFE_SOURCE';
  total:number;matched:number;records:BoundaryRecord[];
  nativeVerified:false;targetVerified:false;exportable:false;
};
const enc=new TextEncoder();
const MAX_DATASET_BYTES=65536,MAX_EVENTS=500,MAX_LITERAL_BYTES=256;
const unacceptable=/[\u0000-\u0008\u000B-\u001F\u007F]/u;
const utf8=(s:string)=>enc.encode(s).length;
function validUtf8(value:string):boolean{
  try{return new TextDecoder('utf-8',{fatal:true}).decode(enc.encode(value))===value;}
  catch{return false;}
}
export function boundaryLiteralError(value:string):string|null{
  if(!value)return null;
  if(!validUtf8(value)||unacceptable.test(value)||/[\r\n]/u.test(value))
    return 'Choose exact printable text from one event; line breaks and invalid Unicode cannot be markers.';
  if(utf8(value)>MAX_LITERAL_BYTES)
    return 'A selected prefix or suffix must be 256 UTF-8 bytes or fewer.';
  return null;
}
function linesWithOffsets(source:string):Array<{line:number;raw:string;startByte:number}>{
  const result:Array<{line:number;raw:string;startByte:number}>=[];
  let cursor=0,line=1,byteCursor=0;
  while(cursor<source.length){
    let end=cursor;
    while(end<source.length&&source[end]!=='\r'&&source[end]!=='\n')end++;
    const raw=source.slice(cursor,end);
    if(raw.trim())result.push({line,raw,startByte:byteCursor});
    let next=end;
    if(source[next]==='\r')next++;
    if(source[next]==='\n')next++;
    byteCursor+=utf8(source.slice(cursor,next));
    cursor=next;line++;
  }
  return result;
}
/**
 * Return exact UTF-8 byte offsets into original source (never into a trimmed
 * or reserialized copy). Reject mixed/unrecognized marks for the entire set.
 */
export function inspectDeclaredSourceBoundaries(
  source:string,profile:DeclaredSourceBoundaries,
):BoundaryReview{
  const base={nativeVerified:false as const,targetVerified:false as const,
    exportable:false as const};
  const response=(status:BoundaryReview['status'],code:BoundaryReview['code'],
    records:BoundaryRecord[]=[]):BoundaryReview=>({
    ...base,status,code,total:records.length,
    matched:records.filter(record=>record.matched).length,records,
  });
  if(!profile.prefix&&!profile.postfix)return response('NONE','NO_MARKERS');
  if(boundaryLiteralError(profile.prefix)||boundaryLiteralError(profile.postfix))
    return response('INVALID','INVALID_MARKERS');
  if(!source||!validUtf8(source)||utf8(source)>MAX_DATASET_BYTES||
     source.includes('\0'))return response('INVALID','UNSAFE_SOURCE');
  const lines=linesWithOffsets(source);
  if(!lines.length||lines.length>MAX_EVENTS)
    return response('INVALID','UNSAFE_SOURCE');
  const records=lines.map(({line,raw,startByte})=>{
    const prefix=profile.prefix,postfix=profile.postfix;
    const matched=raw.startsWith(prefix)&&raw.endsWith(postfix)&&
      raw.length>prefix.length+postfix.length;
    const payload=matched?raw.slice(prefix.length,raw.length-postfix.length):'';
    const prefixBytes=matched?utf8(prefix):0;
    const payloadBytes=matched?utf8(payload):0;
    return {line,raw,payload,recordStartByte:startByte,
      payloadStartByte:startByte+prefixBytes,
      payloadEndByte:startByte+prefixBytes+payloadBytes,
      recordEndByte:startByte+utf8(raw),matched};
  });
  return records.every(item=>item.matched)?
    response('EXACT_PREVIEW','MATCHED_ALL',records):
    response('REVIEW_ONLY','INCONSISTENT_MARKERS',records);
}
/** Mark the exact beginning or end of the first nonblank physical event. */
export function selectedBoundaryLiteral(
  source:string,start:number,end:number,side:'prefix'|'postfix',
):{value:string;error:null}|{value:null;error:string}{
  const first=linesWithOffsets(source)[0];
  if(!first)return {value:null,error:'Paste a sample log first.'};
  const rawStart=source.indexOf(first.raw);
  const selected=source.slice(start,end);
  const from=start-rawStart,to=end-rawStart;
  if(start<0||end<=start||end>source.length||from<0||to>first.raw.length||
     (side==='prefix'&&from!==0)||(side==='postfix'&&to!==first.raw.length))
    return {value:null,error:side==='prefix'?
      'Select text from the very beginning of the first log event.':
      'Select text ending at the end of the first log event.'};
  const issue=boundaryLiteralError(selected);
  if(issue)return {value:null,error:issue};
  return {value:selected,error:null};
}
