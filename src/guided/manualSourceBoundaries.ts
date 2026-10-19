/**
 * Explicit literal prefix/postfix inspection only. This is NOT a generated
 * Fluentd rule, an adaptive parser, a log transformer or a source rewriter.
 * The original UTF-8 record always remains the source of truth.
 */
export interface ManualBoundaryMarks {
  prefix:string;
  postfix:string;
}
export type BoundaryRecord={
  number:number;
  originalStartByte:number;
  payloadStartByte:number;
  payloadEndByte:number;
  originalEndByte:number;
  payload:string;
};
export type BoundaryInspection={
  status:'NO_MARKS'|'REVIEW_READY'|'ABSTAIN_UNSAFE';
  reason:'NO_SELECTION'|'LITERAL_BOUNDARIES_REVIEWED'|
    'INVALID_INPUT_OR_BOUNDARY'|'INCONSISTENT_EVENT_BOUNDARIES';
  count:number;
  records:BoundaryRecord[];
  compilerVerified:false;
  originalSourcePreserved:true;
};
const enc=new TextEncoder();
const bytes=(text:string)=>enc.encode(text).byteLength;
const LIMIT=64*1024;
const LIMIT_EVENTS=500;
const LIMIT_MARK=512;
const fail=(reason:BoundaryInspection['reason']):BoundaryInspection=>({
  status:'ABSTAIN_UNSAFE',reason,count:0,records:[],
  compilerVerified:false,originalSourcePreserved:true,
});
export function inspectManualBoundaries(
  source:string,marks:ManualBoundaryMarks,
):BoundaryInspection{
  if(!marks.prefix&&!marks.postfix)return {
    status:'NO_MARKS',reason:'NO_SELECTION',count:0,records:[],
    compilerVerified:false,originalSourcePreserved:true,
  };
  if(!source||bytes(source)>LIMIT||source.includes('\0')||source.includes('\r')||
     bytes(marks.prefix)>LIMIT_MARK||bytes(marks.postfix)>LIMIT_MARK||
     marks.prefix.includes('\n')||marks.postfix.includes('\n')||
     marks.prefix.includes('\0')||marks.postfix.includes('\0'))return fail('INVALID_INPUT_OR_BOUNDARY');
  const physical=source.split('\n');
  const events:BoundaryRecord[]=[];
  let start=0;
  for(const line of physical){
    const size=bytes(line);
    if(line.trim()){
      if(events.length>=LIMIT_EVENTS)return fail('INVALID_INPUT_OR_BOUNDARY');
      if(!line.startsWith(marks.prefix)||!line.endsWith(marks.postfix)||
         marks.prefix.length+marks.postfix.length>=line.length)
        return fail('INCONSISTENT_EVENT_BOUNDARIES');
      const payload=line.slice(marks.prefix.length,line.length-marks.postfix.length);
      if(!payload.trim())return fail('INCONSISTENT_EVENT_BOUNDARIES');
      const prefixBytes=bytes(marks.prefix);
      const suffixBytes=bytes(marks.postfix);
      events.push({
        number:events.length+1,originalStartByte:start,
        payloadStartByte:start+prefixBytes,payloadEndByte:start+size-suffixBytes,
        originalEndByte:start+size,payload,
      });
    }
    start+=size+1; // Physical LF; no normalization or rewriting.
  }
  if(!events.length)return fail('INVALID_INPUT_OR_BOUNDARY');
  return {
    status:'REVIEW_READY',reason:'LITERAL_BOUNDARIES_REVIEWED',
    count:events.length,records:events,
    compilerVerified:false,originalSourcePreserved:true,
  };
}

export function selectedBoundary(
  source:string,selectionStart:number,selectionEnd:number,kind:'prefix'|'postfix',
):{ok:true;literal:string}|{ok:false;reason:string}{
  if(!Number.isSafeInteger(selectionStart)||!Number.isSafeInteger(selectionEnd)||
     selectionStart<0||selectionEnd>source.length||selectionStart>=selectionEnd)
    return {ok:false,reason:'Select the exact wrapper characters in the first log line.'};
  const firstEnd=source.indexOf('\n')<0?source.length:source.indexOf('\n');
  if(selectionEnd>firstEnd||source.slice(selectionStart,selectionEnd).includes('\n'))
    return {ok:false,reason:'Select a wrapper within the first log line only.'};
  if(kind==='prefix'&&selectionStart!==0)
    return {ok:false,reason:'A prefix selection must start at the first character.'};
  if(kind==='postfix'&&selectionEnd!==firstEnd)
    return {ok:false,reason:'A postfix selection must end at the last character of the first line.'};
  const literal=source.slice(selectionStart,selectionEnd);
  if(bytes(literal)>LIMIT_MARK||literal.includes('\0'))
    return {ok:false,reason:'The selected wrapper must be at most 512 UTF-8 bytes.'};
  return {ok:true,literal};
}
