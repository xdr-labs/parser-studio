import {parseZeekTsvBlock} from '../zeekTabular';

/**
 * Bounded original-wire Zeek ASCII file-rotation grammar.
 * A new declared schema is allowed only after a complete #close block.
 * It is a source-only observer and NEVER verifies target-native semantics.
 */
export interface ZeekRotationClaim {
  row:number;name:string;rawLexeme:string;startByte:number;endByte:number;
}
export interface ZeekRotationBlock {
  blockIndex:number;path:string;fields:string[];
  sourceStartByte:number;sourceEndByte:number;
  physicalLines:number;rowCount:number;claims:ZeekRotationClaim[];
}
export type ZeekRotationResult=
  | {ok:true;sourceBytes:number;eventCount:number;blocks:ZeekRotationBlock[];
     autoPromoted:false;nativeVerified:false;producerProfileQualified:false}
  | {ok:false;sourceBytes:number;reason:string;blocks:[];
     autoPromoted:false;nativeVerified:false;producerProfileQualified:false};

const MAX_SOURCE_BYTES=1024*1024;
const MAX_BLOCKS=32;
const MAX_TOTAL_ROWS=1000;
const encoder=new TextEncoder();
const decoder=new TextDecoder('utf-8',{fatal:true});

export function inspectStandardZeekRotationSource(raw:string):ZeekRotationResult {
  const rawBytes=encoder.encode(raw);
  const sourceBytes=rawBytes.length;
  const invalid=(reason:string):ZeekRotationResult=>({
    ok:false,sourceBytes,reason,blocks:[],
    autoPromoted:false,nativeVerified:false,producerProfileQualified:false,
  });
  if(!raw||sourceBytes>MAX_SOURCE_BYTES||raw.includes('\0'))
    return invalid('ZEEK_ROTATION_SOURCE_BOUNDS_OR_BINARY');
  // TextEncoder replaces lone surrogate code units. Such transformed
  // source bytes cannot support original value/offset evidence.
  let roundTrip:string;
  try{roundTrip=decoder.decode(rawBytes);}
  catch{return invalid('ZEEK_ROTATION_INVALID_UTF8');}
  if(roundTrip!==raw)return invalid('ZEEK_ROTATION_INVALID_UNICODE_SOURCE');

  const hasCrlf=raw.includes('\r\n');
  const nonCrlf=raw.replace(/\r\n/g,'');
  if(nonCrlf.includes('\r')||(hasCrlf&&nonCrlf.includes('\n')))
    return invalid('ZEEK_ROTATION_MIXED_SOURCE_LINE_ENDINGS');
  const eol=hasCrlf?'\r\n':'\n';
  if(!raw.endsWith(eol))return invalid('ZEEK_ROTATION_UNTERMINATED_LAST_PHYSICAL_LINE');
  const lines=raw.slice(0,-eol.length).split(eol);
  if(!lines.length||lines.some(line=>line===''))
    return invalid('ZEEK_ROTATION_BLANK_OR_MISSING_PHYSICAL_RECORD');

  let totalRecords=0,consumedBytes=0;
  let current:string[]=[];
  let blockStartByte=0,blockIndex=0;
  const blocks:ZeekRotationBlock[]=[];
  for(const line of lines){
    if(current.length===0){
      if(!line.startsWith('#separator ')){
        return invalid('ZEEK_ROTATION_MISSING_BLOCK_SEPARATOR');
      }
      blockStartByte=consumedBytes;
    }
    current.push(line);
    consumedBytes+=encoder.encode(line).length+encoder.encode(eol).length;
    if(!line.startsWith('#close'))continue;
    if(!line.startsWith('#close\t')||blockIndex>=MAX_BLOCKS)
      return invalid('ZEEK_ROTATION_MALFORMED_CLOSE_OR_BLOCK_BUDGET');
    const blockRaw=current.join(eol)+eol;
    const blockBytes=encoder.encode(blockRaw);
    if(blockStartByte+blockBytes.length!==consumedBytes ||
       decoder.decode(rawBytes.subarray(blockStartByte,consumedBytes))!==blockRaw)
      return invalid('ZEEK_ROTATION_PHYSICAL_SOURCE_BYTE_DRIFT');

    // Reuse the already-qualified single-block Zeek source parser.
    // The lower-level parser insists on schema cardinality, directive
    // order, terminal close, and exact per-row UTF-8 intervals.
    const parsed=parseZeekTsvBlock(blockRaw);
    if(!parsed.ok||!parsed.block.closed)
      return invalid('ZEEK_ROTATION_BLOCK_UNQUALIFIED');
    if(!parsed.block.path)
      return invalid('ZEEK_ROTATION_SOURCE_PATH_NOT_DECLARED');

    totalRecords+=parsed.block.rows.length;
    if(totalRecords>MAX_TOTAL_ROWS)
      return invalid('ZEEK_ROTATION_ROW_BUDGET');

    const claims:ZeekRotationClaim[]=[];
    for(const [rowIndex,fields] of parsed.block.rowFieldSpans.entries()){
      for(const field of fields){
        const startByte=blockStartByte+field.startByte;
        const endByte=blockStartByte+field.endByte;
        if(startByte<blockStartByte||endByte>consumedBytes||startByte>endByte ||
           decoder.decode(rawBytes.subarray(startByte,endByte))!==field.rawLexeme)
          return invalid('ZEEK_ROTATION_FIELD_UTF8_SOURCE_BYTE_DRIFT');
        claims.push({
          row:rowIndex,name:field.name,rawLexeme:field.rawLexeme,
          startByte,endByte,
        });
      }
    }

    blocks.push({
      blockIndex,path:parsed.block.path,fields:parsed.block.fields,
      sourceStartByte:blockStartByte,sourceEndByte:consumedBytes,
      physicalLines:parsed.block.physicalLines,
      rowCount:parsed.block.rows.length,claims,
    });
    blockIndex++;
    current=[];
  }
  if(current.length!==0)return invalid('ZEEK_ROTATION_DANGLING_UNCLOSED_BLOCK');
  if(blocks.length===0||consumedBytes!==sourceBytes)
    return invalid('ZEEK_ROTATION_UNCONSUMED_SOURCE_BYTES');
  return {
    ok:true,sourceBytes,eventCount:totalRecords,blocks,
    autoPromoted:false,nativeVerified:false,producerProfileQualified:false,
  };
}
