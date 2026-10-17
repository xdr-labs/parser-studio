/**
 * Bounded, browser-safe CEF v26 header grammar. Shared by the browser
 * and isolated source-review evidence; never asserts CEF extension or
 * native Stellar completeness. No vendor-specific grammar branching.
 */
export type CefHeaderField = {
  name:string; decoded:string; sourceLexeme:string; startByte:number; endByte:number;
};
export type CefHeaderScan =
  | {ok:true;fields:CefHeaderField[];extensionStart:number}
  | {ok:false;reason:string};

const HEADERS=['cefVersion','deviceVendor','deviceProduct','deviceVersion',
  'deviceEventClassId','name','severity'] as const;
const BOUNDS=[3,63,63,31,1023,512,32] as const;
const NAMED_SEVERITY=new Set(['Unknown','Low','Medium','High','Very-High']);
const encoder=new TextEncoder();

function validUtf16(raw:string):boolean {
  for(let i=0;i<raw.length;i++){
    const a=raw.charCodeAt(i);
    if(a>=0xd800&&a<=0xdbff){
      if(i+1>=raw.length||raw.charCodeAt(++i)<0xdc00||raw.charCodeAt(i)>0xdfff)
        return false;
    }else if(a>=0xdc00&&a<=0xdfff)return false;
  }
  return true;
}
const fail=(reason:string):CefHeaderScan=>({ok:false,reason});
export function scanCefStandardHeaderGrammar(raw:string,start=0):CefHeaderScan{
  if(!raw||start<0||!raw.startsWith('CEF:',start)||
     encoder.encode(raw).length>8192||!validUtf16(raw)||
     /[\r\n\0]/.test(raw))
    return fail('CEF_UNSUPPORTED_OR_UNSAFE_SOURCE');
  const fields:CefHeaderField[]=[];
  let cursor=start+4;
  for(let i=0;i<HEADERS.length;i++){
    const begin=cursor;
    let decoded='',terminated=false;
    while(cursor<raw.length){
      const c=raw[cursor]!;
      if(c==='|'){terminated=true;break;}
      if(c==='\\'){
        const next=raw[cursor+1];
        if(next!=='|'&&next!=='\\')
          return fail('CEF_UNKNOWN_HEADER_ESCAPE');
        decoded+=next;cursor+=2;continue;
      }
      if(c.charCodeAt(0)<32||c.charCodeAt(0)===127)
        return fail('CEF_HEADER_CONTROL');
      decoded+=c;
      cursor++;
      if(cursor-begin>2048)return fail('CEF_HEADER_OVERSIZED');
    }
    if(!terminated)return fail('CEF_REQUIRED_SEPARATOR_MISSING');
    const lexical=raw.slice(begin,cursor);
    if(!decoded||!lexical||encoder.encode(decoded).length>BOUNDS[i]!)
      return fail('CEF_MISSING_OR_OVERSIZED_REQUIRED_HEADER');
    if(i===0&&decoded!=='0'&&decoded!=='1')
      return fail('CEF_UNSUPPORTED_VERSION');
    if(i===6&&!NAMED_SEVERITY.has(decoded)&&!/^(?:0|[1-9]|10)$/.test(decoded))
      return fail('CEF_SEVERITY_OUT_OF_RANGE');
    const startByte=encoder.encode(raw.slice(0,begin)).length;
    const endByte=encoder.encode(raw.slice(0,cursor)).length;
    if(new TextDecoder('utf-8',{fatal:true}).decode(
      encoder.encode(raw).subarray(startByte,endByte))!==lexical)
      return fail('CEF_SOURCE_BYTE_DRIFT');
    fields.push({name:HEADERS[i]!,decoded,sourceLexeme:lexical,startByte,endByte});
    cursor++;
  }
  return {ok:true,fields,extensionStart:cursor};
}
