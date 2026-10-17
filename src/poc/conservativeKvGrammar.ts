/** Isolated lexical candidate. Never used by the product parser or native adapter. */
export type ConservativeKvCandidate={
  envelope:'pri_kv'|'yearless_rfc3164_kv'|'bare_kv';
  fields:Record<string,string>;
};
const unsafe=new Set(['__proto__','prototype','constructor']);
const sourceKey=/^[A-Za-z_][A-Za-z0-9_.-]{0,127}$/;
const startsKey=/^[A-Za-z_][A-Za-z0-9_.-]{0,127}=/;
const months='Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec'.split(' ');
const rfc3164=/^(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) +([0-3]?[0-9]) +([0-2][0-9]):([0-5][0-9]):([0-5][0-9]) +([^\s=]{1,253}) +(?=[A-Za-z_][A-Za-z0-9_.-]{0,127}=)/;
const token=/[ \t]*([A-Za-z_][A-Za-z0-9_.-]{0,127})=(?:"((?:\\.|[^"\\])*)"|'((?:\\.|[^'\\])*)'|((?:\\.|[^\s"'\\])*))/y;
const te=new TextEncoder();

export function conservativeKvBody(raw:string):{envelope:ConservativeKvCandidate['envelope'];body:string}|null{
  if(!raw||te.encode(raw).length>16384||/[\u0000-\u0008\u000a-\u001f\u007f]/.test(raw))return null;
  if(raw.startsWith('<')){
    const pri=/^<([0-9]{1,3})>[ \t]*/.exec(raw);
    if(!pri||Number(pri[1])>191)return null;
    const body=raw.slice(pri[0].length);
    return startsKey.test(body)?{envelope:'pri_kv',body}:null;
  }
  const header=rfc3164.exec(raw);
  if(header){
    if(!months.includes(header[1]!)||Number(header[2])<1||
       Number(header[2])>31||Number(header[3])>23)return null;
    const hostname=header[6]!;
    if(!hostname.split('.').every(label=>/^[A-Za-z0-9][A-Za-z0-9-]{0,61}$/.test(label)))
      return null;
    const body=raw.slice(header[0].length);
    return startsKey.test(body)?{envelope:'yearless_rfc3164_kv',body}:null;
  }
  return startsKey.test(raw)?{envelope:'bare_kv',body:raw}:null;
}

/** Double-quotes: decode only quoted \" and \\, keep unknown backslash sequences. */
function decodeDouble(value:string):string{
  return value.replace(/\\(["\\])/g,'$1');
}
/** In unquoted tokens a slash escapes the following character in the independent lexical grammar. */
function decodeBare(value:string):string{
  return value.replace(/\\(.)/gs,'$1');
}

export function conservativeKvFields(raw:string):ConservativeKvCandidate|null{
  const qualified=conservativeKvBody(raw);
  if(!qualified)return null;
  const fields:Record<string,string>=Object.create(null);
  const canonical=new Set<string>();
  let offset=0,count=0;
  const body=qualified.body;
  while(offset<body.length){
    if(!body.slice(offset).trim())break;
    token.lastIndex=offset;
    const match=token.exec(body);
    if(!match||match.index!==offset)return null;
    const end=token.lastIndex;
    if(end<body.length&&body[end]!==' '&&body[end]!=='\t')
      return null; // Fused quote and unquoted segments are ambiguous.
    const name=match[1]!;
    const normalized=name.replaceAll('-','_');
    if(!sourceKey.test(name)||unsafe.has(name)||canonical.has(normalized))
      return null;
    canonical.add(normalized);
    if(++count>256)return null;
    const quotedDouble=match[2];
    const quotedSingle=match[3];
    const bare=match[4];
    // Conservative: shell-like single quotes are literals; \ escapes must not
    // be guessed without a supported vendor-specific source contract.
    if(quotedSingle!==undefined&&quotedSingle.includes('\\'))return null;
    const value=quotedDouble!==undefined?decodeDouble(quotedDouble):
      quotedSingle!==undefined?quotedSingle:decodeBare(bare??'');
    if(te.encode(value).length>8192||/[\u0000-\u001f\u007f]/.test(value))return null;
    fields[name]=value;
    offset=end;
  }
  return count>=2&&count<=256?{envelope:qualified.envelope,fields}:null;
}
