export interface JournalTextEntry{
  fields:Record<string,string|string[]>;
  raw:string;
}

export type JournalTextExportResult=
  |{ok:true;entries:JournalTextEntry[];lineEnding:'lf'|'crlf'}
  |{ok:false;error:string};

const MAX_STREAM_BYTES=1024*1024;
const MAX_ENTRY_BYTES=128*1024;
const MAX_ENTRIES=1000;
const MAX_FIELDS=512;
const MAX_FIELD_BYTES=64*1024;
const UNSAFE_KEYS=new Set(['__proto__','constructor','prototype']);

function bytes(value:string):number{return new TextEncoder().encode(value).byteLength;}

function validFieldName(value:string):boolean{
  return /^_{0,2}[A-Z][A-Z0-9_]{0,63}$/.test(value)&&!UNSAFE_KEYS.has(value);
}

function addField(fields:Record<string,string|string[]>,key:string,value:string):boolean{
  const previous=fields[key];
  fields[key]=previous===undefined?value:Array.isArray(previous)?[...previous,value]:[previous,value];
  return Object.keys(fields).length<=MAX_FIELDS;
}

export function parseJournalTextExport(raw:string):JournalTextExportResult{
  if(!raw||raw.includes('\0')||bytes(raw)>MAX_STREAM_BYTES)
    return {ok:false,error:'Invalid or oversized journal export'};
  const hasCrlf=raw.includes('\r\n');
  const withoutCrlf=raw.replace(/\r\n/g,'');
  if(withoutCrlf.includes('\r'))return {ok:false,error:'Unsupported journal line ending'};
  if(hasCrlf&&withoutCrlf.includes('\n'))return {ok:false,error:'Mixed journal line endings are unsupported'};
  const lineEnding:'lf'|'crlf'=hasCrlf?'crlf':'lf';
  const normalized=hasCrlf?raw.replace(/\r\n/g,'\n'):raw;
  if(!normalized.endsWith('\n\n'))return {ok:false,error:'Journal export must end at an entry boundary'};
  const blocks=normalized.slice(0,-2).split('\n\n');
  if(!blocks.length||blocks.length>MAX_ENTRIES||blocks.some(block=>!block))
    return {ok:false,error:'Journal export contains an empty entry or exceeds the entry limit'};

  const entries:JournalTextEntry[]=[];
  for(const block of blocks){
    if(bytes(block)>MAX_ENTRY_BYTES)return {ok:false,error:'Journal entry exceeds parser limit'};
    const fields:Record<string,string|string[]>=Object.create(null);
    const lines=block.split('\n');
    for(const line of lines){
      if(!line)return {ok:false,error:'Journal entry contains an empty field line'};
      const eq=line.indexOf('=');
      if(eq<=0){
        // Binary-safe journal export fields use a field-name-only line followed
        // by a binary little-endian length/data payload. This text-only PoC
        // rejects that form rather than corrupting or guessing binary data.
        return {ok:false,error:'Binary journal export field requires a binary-safe parser'};
      }
      const key=line.slice(0,eq),value=line.slice(eq+1);
      if(!validFieldName(key)||bytes(value)>MAX_FIELD_BYTES||/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(value))
        return {ok:false,error:'Journal field is unsafe or exceeds parser limits'};
      if(!addField(fields,key,value))return {ok:false,error:'Journal field limit exceeded'};
    }
    if(!Object.keys(fields).length)return {ok:false,error:'Journal entry contains no fields'};
    entries.push({fields,raw:block});
  }
  return {ok:true,entries,lineEnding};
}
