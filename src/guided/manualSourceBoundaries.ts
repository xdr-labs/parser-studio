import {MAX_DATASET_BYTES,MAX_EVENTS} from '../parser';

export type BoundaryKind='prefix'|'suffix';
export type MarkedBoundaries={prefix:string;suffix:string};
export type BoundaryPreview={
  status:'NO_MARKERS'|'READY'|'PARTIAL'|'UNSAFE';
  reason:string;
  total:number;matched:number;unmatched:number;
  events:Array<{
    line:number;
    status:'MATCHED'|'UNMATCHED';
    // Source and payload remain browser-local. The user can inspect them.
    original:string;body:string;
    sourceStartByte:number;payloadStartByte:number;payloadEndByte:number;sourceEndByte:number;
  }>;
  nativeVerified:false;targetVerified:false;
};
const encoder=new TextEncoder();
const bytes=(s:string)=>encoder.encode(s).length;
const MAX_MARKER_BYTES=512;
const safe=(marker:string)=>!marker||(
  bytes(marker)<=MAX_MARKER_BYTES&&!/[\x00-\x1f\x7f]/.test(marker) &&
  !marker.includes('\uFFFD')
);
const FIRST_LINE_LIMIT=MAX_DATASET_BYTES;

/**
 * User must select a literal contiguous span on the FIRST nonblank record,
 * starting at its left edge for a prefix or ending at its right edge for a
 * suffix. The original source is never edited.
 */
export function markBoundarySelection(
  input:string,start:number,end:number,kind:BoundaryKind
):{ok:true;value:string}|{ok:false;reason:string}{
  if(!Number.isSafeInteger(start)||!Number.isSafeInteger(end)||start<0||
     end<=start||end>input.length)
    return {ok:false,reason:'Select nonempty text in the first sample log.'};
  if(bytes(input)>MAX_DATASET_BYTES)
    return {ok:false,reason:'The source exceeds the 64 KiB local review limit.'};
  const lines=/[^\r\n]+/g;
  let match:RegExpExecArray|null=null;
  while((match=lines.exec(input))!==null){
    if(match[0].trim())break;
  }
  if(!match||!match[0].trim())
    return {ok:false,reason:'Add a complete log record before marking a wrapper.'};
  const first=match[0],offset=match.index;
  if(first.length>FIRST_LINE_LIMIT||start<offset||end>offset+first.length)
    return {ok:false,reason:'Mark within the first sample log only.'};
  if(kind==='prefix'&&start!==offset)
    return {ok:false,reason:'A prefix must begin at the start of the sample log.'};
  if(kind==='suffix'&&end!==offset+first.length)
    return {ok:false,reason:'A suffix must end at the end of the sample log.'};
  const value=input.slice(start,end);
  if(!safe(value))return {ok:false,reason:'Keep the marked text short and free of control characters.'};
  if(!first.slice(kind==='prefix'?end-offset:0,kind==='prefix'?undefined:start-offset).trim())
    return {ok:false,reason:'Leave a nonempty body after the marked wrapper.'};
  return {ok:true,value};
}

/**
 * Compare literal user-declared boundary fragments to every record. No
 * heuristic auto-detection and no compiler claim. All offsets are UTF-8
 * byte offsets into the ORIGINAL source string (not a translated copy).
 */
export function inspectMarkedBoundaries(input:string,marks:MarkedBoundaries):BoundaryPreview{
  const empty=(status:BoundaryPreview['status'],reason:string):BoundaryPreview=>({
    status,reason,total:0,matched:0,unmatched:0,events:[],
    nativeVerified:false,targetVerified:false,
  });
  if(!marks.prefix&&!marks.suffix)
    return empty('NO_MARKERS','Mark a literal prefix or suffix, or enter it manually.');
  if(!safe(marks.prefix)||!safe(marks.suffix)||bytes(input)>MAX_DATASET_BYTES||
      input.includes('\0'))
    return empty('UNSAFE','Only bounded, single-line literal wrappers can be reviewed.');
  const chunks=input.split(/(\r\n|\n|\r)/);
  const events:BoundaryPreview['events']=[];
  let absoluteByte=0,line=1;
  for(let i=0;i<chunks.length;i+=2){
    const raw=chunks[i]??'',sep=chunks[i+1]??'';
    const start=absoluteByte;absoluteByte+=bytes(raw)+bytes(sep);
    if(raw.trim()){
      if(events.length>=MAX_EVENTS)return empty('UNSAFE','More than 500 source records require separate review.');
      const prefix=marks.prefix,suffix=marks.suffix;
      const good=raw.startsWith(prefix)&&raw.endsWith(suffix)&&
        raw.length>prefix.length+suffix.length&&
        raw.slice(prefix.length,raw.length-suffix.length).trim().length>0;
      const body=good?raw.slice(prefix.length,raw.length-suffix.length):raw;
      events.push({
        line,status:good?'MATCHED':'UNMATCHED',
        original:raw,body,
        sourceStartByte:start,payloadStartByte:start+(good?bytes(prefix):0),
        payloadEndByte:start+(good?bytes(raw)-bytes(suffix):bytes(raw)),
        sourceEndByte:start+bytes(raw),
      });
    }
    if(sep)line++;
  }
  if(!events.length)return empty('UNSAFE','No complete single-line records were found.');
  const matched=events.filter(row=>row.status==='MATCHED').length;
  return {
    status:matched===events.length?'READY':'PARTIAL',
    reason:matched===events.length?
      'Every event matched the marked literal wrapper; compiler support is still unverified.':
      'Some events have a different wrapper. Nothing was discarded or silently stripped.',
    total:events.length,matched,unmatched:events.length-matched,events,
    nativeVerified:false,targetVerified:false,
  };
}
