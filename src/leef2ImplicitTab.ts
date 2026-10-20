/** Explicit additional compiler profile; the existing LEEF grammar is unchanged. */
export function extractLeef2ImplicitTab(raw:string):Record<string,unknown>|null{
  const bytes=new TextEncoder().encode(raw);
  if(bytes.byteLength>8192||/[\u0000-\u0008\u000a-\u001f\u007f]/.test(raw)||
     !raw.startsWith('LEEF:2.0|'))return null;
  // An unpaired UTF-16 surrogate must not become an invented replacement byte.
  if(new TextDecoder('utf-8',{ignoreBOM:true}).decode(bytes)!==raw)return null;
  const names=['vendor','product','product_version','event_id'] as const;
  const header:Record<string,string>={version:raw.slice(5,8)};
  let cursor='LEEF:2.0|'.length;
  for(const name of names){
    const end=raw.indexOf('|',cursor);
    if(end<0)return null;
    const value=raw.slice(cursor,end);
    if(!value||!value.replaceAll(' ','')||/[\\\t]/.test(value)||
       new TextEncoder().encode(value).byteLength>256)return null;
    header[name]=value;
    cursor=end+1;
  }
  let extension=raw.slice(cursor);
  if(extension.startsWith('\t'))extension=extension.slice(1);
  // Pipes belong to the header in this narrow profile. An explicit delimiter
  // slot, even a malformed one, cannot fall back to the implicit interpretation.
  if(!extension||extension.includes('|'))return null;
  const tokens=extension.split('\t');
  // Five header fields plus these fields fit the explicit mapping limit.
  if(tokens.length<2||tokens.length>55)return null;
  const fields:Record<string,string>={};
  for(const token of tokens){
    const equal=token.indexOf('=');
    if(equal<1)return null;
    const key=token.slice(0,equal),value=token.slice(equal+1);
    if(!/^[A-Za-z_][A-Za-z0-9_-]{0,63}$/.test(key)||
       ['__proto__','prototype','constructor'].includes(key)||
       Object.prototype.hasOwnProperty.call(fields,key)||!value||
       new TextEncoder().encode(value).byteLength>512)return null;
    fields[key]=value;
  }
  return {
    leef_header:header,
    leef_extension:fields,
    generic:{mode:'leef2_implicit_tab',source_raw:raw},
  };
}
