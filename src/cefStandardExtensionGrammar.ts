/**
 * Generic ArcSight CEF v26 extension lexical grammar, shared by browser
 * and source-byte observer. No manufacturer/firmware-specific branches.
 * A lexically decoded value is never publisher-semantic/native certified.
 */
export interface CefExtensionField{
  name:string;
  occurrence:number;
  decodedValue:string;
  rawValueLexeme:string;
  nameStartByte:number;nameEndByte:number;
  valueStartByte:number;valueEndByte:number;
}
export type CefExtensionScan=
  |{ok:true;fields:CefExtensionField[]}
  |{ok:false;reason:string};

const KEY=/[A-Za-z_][A-Za-z0-9_.-]{0,127}=/y;
const UNSAFE_KEYS=new Set(['__proto__','constructor','prototype']);
const encoder=new TextEncoder();
const fail=(reason:string):CefExtensionScan=>({ok:false,reason});
const white=(c:string|undefined)=>c===' '||c==='\t';
const bytePos=(source:string,cursor:number)=>encoder.encode(source.slice(0,cursor)).length;

function wellFormedUnicode(source:string):boolean{
  for(let i=0;i<source.length;i++){
    const c=source.charCodeAt(i);
    if(c>=0xd800&&c<=0xdbff){
      if(++i>=source.length||source.charCodeAt(i)<0xdc00||
         source.charCodeAt(i)>0xdfff)return false;
    }else if(c>=0xdc00&&c<=0xdfff)return false;
  }
  return true;
}

/**
 * The last space before a following valid key= is the separator.
 * All earlier spaces belong to the preceding raw/decoded value. A final
 * field's trailing source spaces are retained in raw lexeme, but omitted
 * from decoded value as defined by the CEF extension convention.
 *
 * Quotes are not a generic CEF escape mechanism. When a candidate key=
 * marker appears inside quote-looking text, do NOT treat it as a trusted
 * source boundary: abstain rather than invent a producer-specific quote rule.
 */
export function scanCefStandardExtensions(
  source:string,start=0,options?:{preserveRepeatedForReview?:boolean},
):CefExtensionScan{
  const size=encoder.encode(source).length;
  if(start<0||start>source.length||size>65536||!wellFormedUnicode(source)||
     /[\r\n\0]/.test(source))
    return fail('CEF_EXTENSION_OUTSIDE_BOUNDED_ORIGINAL_SOURCE');
  let cursor=start,tokenCount=0;
  const fields:CefExtensionField[]=[];
  const seen=new Map<string,number>();

  while(cursor<source.length){
    while(white(source[cursor]))cursor++;
    if(cursor===source.length)break;
    if(++tokenCount>1024)return fail('CEF_EXTENSION_FIELD_BUDGET_EXCEEDED');
    KEY.lastIndex=cursor;
    const match=KEY.exec(source);
    if(!match||match.index!==cursor)return fail('UNCONSUMED_CEF_EXTENSION_SOURCE');
    const name=match[0].slice(0,-1);
    if(UNSAFE_KEYS.has(name)||UNSAFE_KEYS.has(name.replaceAll('-','_')))
      return fail('UNSAFE_CEF_EXTENSION_FIELD_NAME');
    const occurrence=seen.get(name)??0;
    if(occurrence>0&&!options?.preserveRepeatedForReview)
      return fail('DUPLICATE_CEF_EXTENSION_FIELD');
    seen.set(name,occurrence+1);
    const nameStart=cursor;
    const valueStart=KEY.lastIndex;
    let pos=valueStart,decoded='',rawEnd=source.length;
    let hasDelimiter=false;
    let insideDouble=false,insideSingle=false;
    while(pos<source.length){
      const ch=source[pos]!;
      if(ch==='\\'){
        const next=source[pos+1];
        if(next===undefined)return fail('TRUNCATED_CEF_EXTENSION_ESCAPE');
        decoded+=next==='n'?'\n':next==='r'?'\r':
          next==='='?'=':next==='\\'?'\\':'\\'+next;
        pos+=2;
        continue;
      }
      if(ch==='"'&&!insideSingle){insideDouble=!insideDouble;decoded+=ch;pos++;continue;}
      if(ch==="'"&&!insideDouble){insideSingle=!insideSingle;decoded+=ch;pos++;continue;}
      if(white(ch)){
        let runEnd=pos;
        while(white(source[runEnd]))runEnd++;
        KEY.lastIndex=runEnd;
        const next=KEY.exec(source);
        if(next&&next.index===runEnd){
          if(insideDouble||insideSingle)
            return fail('UNQUALIFIED_QUOTED_CEF_FIELD_BOUNDARY');
          rawEnd=runEnd-1;
          if(rawEnd>pos)decoded+=source.slice(pos,rawEnd);
          pos=runEnd;
          hasDelimiter=true;
          break;
        }
        decoded+=source.slice(pos,runEnd);
        pos=runEnd;
        continue;
      }
      if(ch.charCodeAt(0)<32||ch.charCodeAt(0)===127)
        return fail('UNESCAPED_CEF_EXTENSION_CONTROL');
      decoded+=ch;pos++;
    }
    if(!hasDelimiter){
      // The final field's trailing source whitespace is not a decoded CEF value.
      decoded=decoded.replace(/[ \t]+$/,'');
      rawEnd=source.length;
      cursor=source.length;
    }else{
      cursor=pos;
    }
    const original=source.slice(valueStart,rawEnd);
    const sourceStart=bytePos(source,valueStart);
    const sourceEnd=bytePos(source,rawEnd);
    if(new TextDecoder('utf8',{fatal:true}).decode(
      encoder.encode(source).subarray(sourceStart,sourceEnd))!==original)
      return fail('CEF_EXTENSION_SOURCE_BYTE_REPLAY_FAILED');
    fields.push({
      name,occurrence,decodedValue:decoded,rawValueLexeme:original,
      nameStartByte:bytePos(source,nameStart),
      nameEndByte:bytePos(source,nameStart+name.length),
      valueStartByte:sourceStart,valueEndByte:sourceEnd,
    });
  }
  if(!fields.length)return fail('EMPTY_CEF_EXTENSION');
  return {ok:true,fields};
}
