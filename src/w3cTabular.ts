const UNSAFE_W3C_FIELDS=new Set(['__proto__','constructor','prototype']);

export interface W3cSchema{
  fields:string[];
  delimiter:'space'|'tab';
}

function safeField(value:string):boolean{
  return /^[A-Za-z][A-Za-z0-9_.()\/-]{0,127}$/.test(value)&&!UNSAFE_W3C_FIELDS.has(value);
}

export function parseW3cFieldsHeader(raw:string,delimiter:W3cSchema['delimiter']='space'):W3cSchema|null{
  if(!raw.startsWith('#Fields: ')||raw.includes('\0')||/[\r\n]/.test(raw))return null;
  if(new TextEncoder().encode(raw).byteLength>8192)return null;
  const fields=raw.slice(9).trim().split(/ +/);
  if(fields.length<1||fields.length>128||fields.some(field=>!safeField(field)))return null;
  if(new Set(fields).size!==fields.length)return null;
  if(delimiter!=='space'&&delimiter!=='tab')return null;
  return {fields,delimiter};
}

function splitQuotedSpaceRow(raw:string):string[]|null{
  const values:string[]=[];let token='',quote='',escaped=false;
  for(let index=0;index<raw.length;index++){
    const ch=raw[index]!;
    if(quote){
      if(escaped){token+=ch;escaped=false;continue;}
      if(ch==='\\'){escaped=true;continue;}
      if(ch===quote){quote='';continue;}
      token+=ch;continue;
    }
    if(ch==='"'||ch==="'"){quote=ch;continue;}
    if(ch===' '||ch==='\t'){
      if(token){values.push(token);token='';}
      continue;
    }
    token+=ch;
  }
  if(quote||escaped)return null;
  if(token)values.push(token);
  return values;
}

export function mapW3cRow(raw:string,schema:W3cSchema):Record<string,string>|null{
  if(raw.startsWith('#')||raw.includes('\0')||/[\r\n]/.test(raw)||new TextEncoder().encode(raw).byteLength>8192)return null;
  if(!['space','tab'].includes(schema.delimiter)||schema.fields.length<1||schema.fields.length>128||
     schema.fields.some(field=>!safeField(field))||new Set(schema.fields).size!==schema.fields.length)return null;
  const values=schema.delimiter==='tab'?raw.split('\t'):splitQuotedSpaceRow(raw);
  if(!values||values.length!==schema.fields.length)return null;
  const fields:Record<string,string>=Object.create(null);
  for(let index=0;index<schema.fields.length;index++){
    const key=schema.fields[index]!,value=values[index]!;
    if(new TextEncoder().encode(value).byteLength>2048)return null;
    fields[key]=value;
  }
  return fields;
}

export interface W3cLogBlock{
  schema:W3cSchema;
  rows:Array<Record<string,string>>;
  directives:Record<string,string|string[]>;
  lineEnding:'lf'|'crlf';
}

export type W3cLogBlockResult=
  |{ok:true;block:W3cLogBlock}
  |{ok:false;error:string};

const MAX_W3C_BLOCK_BYTES=1024*1024;
const MAX_W3C_ROWS=2000;

function addDirective(target:Record<string,string|string[]>,key:string,value:string):boolean{
  if(!/^[A-Za-z][A-Za-z0-9_-]{0,63}$/.test(key)||UNSAFE_W3C_FIELDS.has(key)||
     new TextEncoder().encode(value).byteLength>8192)return false;
  const previous=target[key];
  target[key]=previous===undefined?value:Array.isArray(previous)?[...previous,value]:[previous,value];
  return Object.keys(target).length<=128;
}

export function parseW3cLogBlock(raw:string):W3cLogBlockResult{
  if(!raw||raw.includes('\0')||new TextEncoder().encode(raw).byteLength>MAX_W3C_BLOCK_BYTES)
    return {ok:false,error:'Invalid or oversized W3C log block'};
  const hasCrlf=raw.includes('\r\n');
  const withoutCrlf=raw.replace(/\r\n/g,'');
  if(withoutCrlf.includes('\r'))return {ok:false,error:'Unsupported W3C line ending'};
  if(hasCrlf&&withoutCrlf.includes('\n'))return {ok:false,error:'Mixed W3C line endings are unsupported'};
  const lineEnding:'lf'|'crlf'=hasCrlf?'crlf':'lf';
  const normalized=hasCrlf?raw.replace(/\r\n/g,'\n'):raw;
  const lines=normalized.endsWith('\n')?normalized.slice(0,-1).split('\n'):normalized.split('\n');
  if(!lines.length||lines.some(line=>line===''))return {ok:false,error:'W3C block contains an empty line'};

  let fieldsHeader:string|undefined;
  const directives:Record<string,string|string[]> = Object.create(null);
  const dataLines:string[]=[];
  for(const line of lines){
    if(line.startsWith('#Fields:')){
      if(fieldsHeader)return {ok:false,error:'Duplicate W3C Fields header'};
      fieldsHeader=line;continue;
    }
    if(line.startsWith('#')){
      const match=/^#([A-Za-z][A-Za-z0-9_-]{0,63}):(?: +(.*))?$/.exec(line);
      if(!match)return {ok:false,error:'Malformed W3C directive'};
      if(!addDirective(directives,match[1]!,match[2]??''))return {ok:false,error:'Unsafe W3C directive'};
      continue;
    }
    if(!fieldsHeader)return {ok:false,error:'W3C data row appeared before Fields header'};
    dataLines.push(line);
    if(dataLines.length>MAX_W3C_ROWS)return {ok:false,error:'W3C row limit exceeded'};
  }
  if(!fieldsHeader||!dataLines.length)return {ok:false,error:'W3C block requires a Fields header and data rows'};

  const headerFields=fieldsHeader.slice(9).trim().split(/ +/);
  const tabMode=dataLines.every(line=>line.includes('\t'));
  const spaceMode=dataLines.every(line=>!line.includes('\t'));
  if(!tabMode&&!spaceMode)return {ok:false,error:'Mixed W3C row delimiters are unsupported'};
  const schema=parseW3cFieldsHeader(fieldsHeader,tabMode?'tab':'space');
  if(!schema||schema.fields.length!==headerFields.length)return {ok:false,error:'Invalid W3C Fields header'};
  const rows:Array<Record<string,string>>=[];
  for(const line of dataLines){
    const row=mapW3cRow(line,schema);
    if(!row)return {ok:false,error:'W3C row does not match Fields schema'};
    rows.push(row);
  }
  return {ok:true,block:{schema,rows,directives,lineEnding}};
}
