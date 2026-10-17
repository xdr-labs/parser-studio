const UNSAFE_ZEEK_FIELDS=new Set(['__proto__','constructor','prototype']);

export interface ZeekTsvSchema{
  fields:string[];
  separator:'\t';
}

function safeField(value:string):boolean{
  return /^[A-Za-z_][A-Za-z0-9_.-]{0,127}$/.test(value)&&!UNSAFE_ZEEK_FIELDS.has(value);
}

export function parseZeekFieldsHeader(raw:string):ZeekTsvSchema|null{
  if(!raw.startsWith('#fields\t')||raw.includes('\0')||/[\r\n]/.test(raw))return null;
  if(new TextEncoder().encode(raw).byteLength>8192)return null;
  const fields=raw.split('\t').slice(1);
  if(fields.length<2||fields.length>128||fields.some(field=>!safeField(field)))return null;
  if(new Set(fields).size!==fields.length)return null;
  return {fields,separator:'\t'};
}

export function mapZeekTsvRow(raw:string,schema:ZeekTsvSchema):Record<string,string>|null{
  if(raw.includes('\0')||/[\r\n]/.test(raw)||new TextEncoder().encode(raw).byteLength>8192)return null;
  if(schema.separator!=='\t'||schema.fields.length<2||schema.fields.length>128||
     schema.fields.some(field=>!safeField(field))||new Set(schema.fields).size!==schema.fields.length)return null;
  const values=raw.split('\t');
  if(values.length!==schema.fields.length)return null;
  const fields:Record<string,string>=Object.create(null);
  for(let index=0;index<schema.fields.length;index++){
    const key=schema.fields[index]!,value=values[index]!;
    if(new TextEncoder().encode(value).byteLength>2048)return null;
    fields[key]=value;
  }
  return fields;
}

export interface ZeekTsvBlock{
  path?:string;
  fields:string[];
  types:string[];
  unsetField:string;
  emptyField:string;
  rows:Array<Record<string,string>>;
  rowFieldSpans:Array<Array<{
    name:string;rawLexeme:string;startByte:number;endByte:number;
  }>>;
  /** Lexical #close seen; does not certify native/event completeness. */
  closed:boolean;
  sourceBytes:number;
  physicalLines:number;
}

export type ZeekTsvBlockResult=
  |{ok:true;block:ZeekTsvBlock}
  |{ok:false;error:string};

const MAX_ZEEK_BLOCK_BYTES=1024*1024;
const MAX_ZEEK_ROWS=1000;
function safeType(value:string):boolean{
  return /^[A-Za-z][A-Za-z0-9_\[\],.-]{0,127}$/.test(value);
}

export function parseZeekTsvBlock(raw:string):ZeekTsvBlockResult{
  const enc=new TextEncoder();
  const bytes=enc.encode(raw), sourceBytes=bytes.length;
  const fail=(error:string):ZeekTsvBlockResult=>({ok:false,error});
  if(!raw||raw.includes('\0')||sourceBytes>MAX_ZEEK_BLOCK_BYTES)
    return fail('Invalid or oversized Zeek TSV block');
  const hasCrlf=raw.includes('\r\n'), withoutCrlf=raw.replace(/\r\n/g,'');
  if(withoutCrlf.includes('\r')||(hasCrlf&&withoutCrlf.includes('\n')))
    return fail('Unsupported or mixed Zeek physical record endings');
  const eol=hasCrlf?'\r\n':'\n', lines=raw.split(eol);
  const ended=raw.endsWith(eol);
  if(ended)lines.pop();
  if(!lines.length||lines.some(x=>x===''))
    return fail('Zeek blank physical record cannot be discarded');
  let cursor=0;
  const physical=lines.map((line,index)=>{
    const startByte=cursor;
    cursor+=enc.encode(line).length+(index<lines.length-1||ended?eol.length:0);
    return {line,startByte};
  });
  if(cursor!==sourceBytes)return fail('Zeek physical source bytes not accounted');

  let path:string|undefined,unsetField='-',emptyField='(empty)';
  let schema:ZeekTsvSchema|null=null,types:string[]|null=null;
  const data:Array<{line:string;startByte:number}>=[];
  let seenSeparator=false,seenSet=false,seenPath=false,seenUnset=false,
    seenEmpty=false,seenOpen=false,closed=false;
  for(const entry of physical){
    const {line}=entry, beforeData=data.length===0;
    if(closed)return fail('Zeek content after #close physical boundary');
    if(line.startsWith('#separator')){
      if(seenSeparator||!beforeData||schema||types)
        return fail('Repeated or late Zeek separator');
      const sep=line.slice('#separator'.length).trim();
      if(sep!=='\\x09'&&sep!=='\\x 09')
        return fail('Only tab-separated Zeek blocks are supported');
      seenSeparator=true;continue;
    }
    if(line.startsWith('#set_separator')){
      if(seenSet||!beforeData||schema||types)
        return fail('Repeated or late Zeek set_separator');
      const token=line.slice('#set_separator'.length).trim();
      if(!token||enc.encode(token).length>8||/[\r\n\0]/.test(token))
        return fail('Unsupported Zeek set separator');
      seenSet=true;continue;
    }
    if(line.startsWith('#path')){
      if(seenPath||!beforeData||schema||types)
        return fail('Zeek source path rotation requires a separate block');
      const value=line.slice('#path'.length).trim();
      if(!/^[A-Za-z0-9_.-]{1,128}$/.test(value))
        return fail('Invalid Zeek path');
      seenPath=true;path=value;continue;
    }
    if(line.startsWith('#unset_field')){
      if(seenUnset||!beforeData)return fail('Late/duplicated Zeek unset field');
      const value=line.slice('#unset_field'.length).trim();
      if(!value||enc.encode(value).length>64)return fail('Invalid Zeek unset marker');
      seenUnset=true;unsetField=value;continue;
    }
    if(line.startsWith('#empty_field')){
      if(seenEmpty||!beforeData)return fail('Late/duplicated Zeek empty field');
      const value=line.slice('#empty_field'.length).trim();
      if(!value||enc.encode(value).length>64)return fail('Invalid Zeek empty marker');
      seenEmpty=true;emptyField=value;continue;
    }
    if(line.startsWith('#open')){
      if(seenOpen||!beforeData||schema||types||
         !/^#open\t[!-~]{1,128}$/.test(line))
        return fail('Invalid Zeek open boundary');
      seenOpen=true;continue;
    }
    if(line.startsWith('#fields')){
      if(schema||!beforeData)return fail('Duplicate/late Zeek fields header');
      schema=parseZeekFieldsHeader(line);
      if(!schema)return fail('Invalid Zeek fields header');
      continue;
    }
    if(line.startsWith('#types')){
      if(types||!beforeData)return fail('Duplicate/late Zeek types header');
      const declared=line.split('\t').slice(1);
      if(declared.length<2||declared.length>128||
         declared.some(x=>!safeType(x)))
        return fail('Invalid Zeek types header');
      types=declared;continue;
    }
    if(line.startsWith('#close')){
      if(!schema||!types||!data.length||!/^#close\t[!-~]{1,128}$/.test(line))
        return fail('Zeek close before complete data');
      closed=true;continue;
    }
    if(line.startsWith('#'))return fail('Unknown/unqualified Zeek directive');
    if(!schema||!types||schema.fields.length!==types.length)
      return fail('Zeek physical data before declared schema');
    data.push(entry);
    if(data.length>MAX_ZEEK_ROWS)return fail('Zeek row limit exceeded');
  }
  if(!schema||!types||schema.fields.length!==types.length)
    return fail('Zeek fields/types schema incomplete');
  if(!data.length)return fail('Zeek block contains no data rows');

  const rows:Array<Record<string,string>>=[];
  const rowFieldSpans:ZeekTsvBlock['rowFieldSpans']=[];
  const decode=new TextDecoder('utf-8',{fatal:true});
  for(const {line,startByte} of data){
    const mapped=mapZeekTsvRow(line,schema);
    if(!mapped)return fail('Zeek row does not match declared schema');
    rows.push(mapped);
    let fieldStartByte=startByte;
    const spans:ZeekTsvBlock['rowFieldSpans'][number]=[];
    const values=line.split('\t');
    for(let index=0;index<values.length;index++){
      const rawLexeme=values[index]!;
      const endByte=fieldStartByte+enc.encode(rawLexeme).length;
      if(decode.decode(bytes.subarray(fieldStartByte,endByte))!==rawLexeme)
        return fail('Zeek original UTF-8 field byte span drift');
      spans.push({name:schema.fields[index]!,rawLexeme,
        startByte:fieldStartByte,endByte});
      fieldStartByte=endByte+1;
    }
    rowFieldSpans.push(spans);
  }
  return {ok:true,block:{
    path,fields:schema.fields,types,unsetField,emptyField,
    rows,rowFieldSpans,closed,sourceBytes,physicalLines:physical.length,
  }};
}
