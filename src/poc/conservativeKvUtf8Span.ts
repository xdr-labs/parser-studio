/** PoC-only byte locations for existing conservative KV lexical candidates.
 * Half-open UTF-8 offsets refer to the full unchanged input, including envelopes.
 * The independent authority is scripts/poc/createSourceKvUtf8SpanOracle.py.
 */
import {conservativeKvBody,conservativeKvFields,type ConservativeKvCandidate}
  from './conservativeKvGrammar';

export type LocatedKvField={
  name:string;
  value:string;
  rawStart:number;
  rawEnd:number;
  nameStart:number;
  nameEnd:number;
  valueStart:number;
  valueEnd:number;
};
export type LocatedKvCandidate=ConservativeKvCandidate&{spans:LocatedKvField[]};
const token=/[ \t]*([A-Za-z_][A-Za-z0-9_.-]{0,127})=(?:"((?:\\.|[^"\\])*)"|'((?:\\.|[^'\\])*)'|((?:\\.|[^\s"'\\])*))/y;
const utf8=new TextEncoder();
const loneSurrogate=/(?:[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF])/;

export function conservativeKvLocatedFields(raw:string):LocatedKvCandidate|null{
  if(loneSurrogate.test(raw))return null;
  const candidate=conservativeKvFields(raw);
  const envelope=conservativeKvBody(raw);
  if(!candidate||!envelope)return null;
  const body=envelope.body;
  const prefixCharCount=raw.length-body.length;
  const toByte=(pos:number)=>utf8.encode(raw.slice(0,prefixCharCount+pos)).length;
  const spans:LocatedKvField[]=[];
  let cursor=0;
  while(cursor<body.length){
    if(!body.slice(cursor).trim())break;
    token.lastIndex=cursor;
    const match=token.exec(body);
    if(!match||match.index!==cursor)return null;
    const name=match[1]!;
    if(!Object.hasOwn(candidate.fields,name))return null;
    const leading=/^[ \t]*/.exec(match[0])![0].length;
    const nameStart=cursor+leading;
    const nameEnd=nameStart+name.length;
    const valueStart=nameEnd+1;
    const valueEnd=token.lastIndex;
    const located:LocatedKvField={
      name,value:candidate.fields[name]!,
      rawStart:toByte(nameStart),rawEnd:toByte(valueEnd),
      nameStart:toByte(nameStart),nameEnd:toByte(nameEnd),
      valueStart:toByte(valueStart),valueEnd:toByte(valueEnd),
    };
    if(!(located.rawStart===located.nameStart&&
       located.nameStart<located.nameEnd&&
       located.nameEnd+1===located.valueStart&&
       located.valueStart<=located.valueEnd&&
       located.valueEnd===located.rawEnd))return null;
    const encoded=utf8.encode(raw);
    if(new TextDecoder('utf-8',{fatal:true}).decode(
       encoded.subarray(located.nameStart,located.nameEnd))!==name)return null;
    if(encoded[located.nameEnd]!==61)return null; // ASCII '='
    spans.push(located);
    cursor=token.lastIndex;
  }
  return spans.length===Object.keys(candidate.fields).length?
    {...candidate,spans}:null;
}
