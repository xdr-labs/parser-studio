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
  if(!raw||raw.includes('\0')||new TextEncoder().encode(raw).byteLength>MAX_ZEEK_BLOCK_BYTES)
    return {ok:false,error:'Invalid or oversized Zeek TSV block'};
  const normalized=raw.replace(/\r\n/g,'\n');
  if(normalized.includes('\r'))return {ok:false,error:'Unsupported Zeek line ending'};
  const lines=normalized.split('\n').filter((line,index,array)=>line!==''||index<array.length-1);
  let path:string|undefined,unsetField='-',emptyField='(empty)';
  let schema:ZeekTsvSchema|null=null,types:string[]|null=null;
  const dataLines:string[]=[];
  for(const line of lines){
    if(line.startsWith('#separator')){
      const value=line.slice('#separator'.length).trim();
      if(value!=='\\x09'&&value!=='\\x 09')return {ok:false,error:'Only tab-separated Zeek blocks are supported'};
      continue;
    }
    if(line.startsWith('#path')){
      const value=line.slice('#path'.length).trim();
      if(!/^[A-Za-z0-9_.-]{1,128}$/.test(value))return {ok:false,error:'Invalid Zeek path'};
      path=value;continue;
    }
    if(line.startsWith('#unset_field')){
      const value=line.slice('#unset_field'.length).trim();
      if(!value||new TextEncoder().encode(value).byteLength>64)return {ok:false,error:'Invalid Zeek unset marker'};
      unsetField=value;continue;
    }
    if(line.startsWith('#empty_field')){
      const value=line.slice('#empty_field'.length).trim();
      if(!value||new TextEncoder().encode(value).byteLength>64)return {ok:false,error:'Invalid Zeek empty marker'};
      emptyField=value;continue;
    }
    if(line.startsWith('#fields')){
      if(schema)return {ok:false,error:'Duplicate Zeek fields header'};
      schema=parseZeekFieldsHeader(line);
      if(!schema)return {ok:false,error:'Invalid Zeek fields header'};
      continue;
    }
    if(line.startsWith('#types')){
      if(types)return {ok:false,error:'Duplicate Zeek types header'};
      const values=line.split('\t').slice(1);
      if(values.length<2||values.length>128||values.some(value=>!safeType(value)))
        return {ok:false,error:'Invalid Zeek types header'};
      types=values;continue;
    }
    if(line.startsWith('#'))continue;
    if(line==='')continue;
    dataLines.push(line);
    if(dataLines.length>MAX_ZEEK_ROWS)return {ok:false,error:'Zeek row limit exceeded'};
  }
  if(!schema||!types||schema.fields.length!==types.length)
    return {ok:false,error:'Zeek fields/types schema is incomplete'};
  if(!dataLines.length)return {ok:false,error:'Zeek block contains no data rows'};
  const rows:Array<Record<string,string>>=[];
  for(const line of dataLines){
    const row=mapZeekTsvRow(line,schema);
    if(!row)return {ok:false,error:'Zeek row does not match schema'};
    rows.push(row);
  }
  return {ok:true,block:{path,fields:schema.fields,types,unsetField,emptyField,rows}};
}
