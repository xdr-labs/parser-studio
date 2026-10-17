import {parseSyslogEnvelope} from '../syslogEnvelope';

/**
 * General, vendor-agnostic JSON source-span proposal.
 *
 * This PoC is intentionally separate from parseSecurityInput; none of these
 * results can be promoted to product/native success without an independent
 * source oracle and product integration approval.
 */
export type StructuralDisposition='REVIEW_ONLY'|'ABSTAIN_UNSAFE'|'RAW_ONLY';
export interface StructuralSourceField{
  path:string;
  type:'null'|'boolean'|'integer'|'number'|'string';
  value:unknown;
  startByte:number;
  endByte:number;
}
export interface StructuralSourceObservation{
  disposition:StructuralDisposition;
  cause:string;
  syntax:'json_object'|'syslog_json_object'|'none';
  fields:StructuralSourceField[];
  sourceBytes:number;
  bodyStartByte:number|null;
  residualPrefixBytes:number;
  passes:2;
  autoPromoted:false;
  nativeVerified:false;
  maxDepthObserved:number;
}

const encoder=new TextEncoder();
const utf8=(text:string)=>encoder.encode(text).length;
const MAX_BYTES=64*1024;
const MAX_FIELDS=2000;
const MAX_DEPTH=20;
const MAX_NODES=50000;
const INT=/^-?(?:0|[1-9][0-9]*)$/;
const NUM=/-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/y;
const DANGEROUS=new Set(['__proto__','constructor','prototype']);
const JS_SAFE=BigInt(Number.MAX_SAFE_INTEGER);
const WS=new Set([' ','\t','\r','\n']);
const ZONE_RE=/^[A-Za-z_][A-Za-z0-9_.-]{0,63}(?:\[[0-9]{1,12}\])?:[ \t]+/;

class StructureUnsafe extends Error{
  constructor(readonly cause:string){super(cause);}
}
function ensureUnicode(text:string):void{
  for(let i=0;i<text.length;i++){
    const point=text.charCodeAt(i);
    if(point>=0xd800&&point<=0xdbff){
      const low=text.charCodeAt(++i);
      if(!Number.isFinite(low)||low<0xdc00||low>0xdfff)
        throw new StructureUnsafe('INVALID_UNICODE_SURROGATE');
    }else if(point>=0xdc00&&point<=0xdfff)
      throw new StructureUnsafe('INVALID_UNICODE_SURROGATE');
  }
}
function jsonEqual(a:unknown,b:unknown):boolean{
  return JSON.stringify(a)===JSON.stringify(b);
}
class SpanScanner{
  pos=0;
  nodes=0;
  peak=0;
  fields:StructuralSourceField[]=[];
  constructor(readonly body:string,readonly source:string,readonly absoluteStart:number){}
  skip(){while(WS.has(this.body[this.pos]??''))this.pos++;}
  take(char:string){
    if(this.body[this.pos]!==char)throw new StructureUnsafe('MALFORMED_JSON_BOUNDARY');
    this.pos++;
  }
  readString():string{
    const begin=this.pos;
    this.take('"');
    let completed=false;
    while(this.pos<this.body.length){
      const ch=this.body[this.pos]!;
      if(ch==='"'){this.pos++;completed=true;break;}
      if(ch==='\\'){this.pos+=2;continue;}
      if(ch.charCodeAt(0)<32)throw new StructureUnsafe('RAW_JSON_CONTROL');
      this.pos++;
    }
    if(!completed)throw new StructureUnsafe('UNTERMINATED_JSON_STRING');
    let result:unknown;
    try{result=JSON.parse(this.body.slice(begin,this.pos));}
    catch{throw new StructureUnsafe('INVALID_JSON_STRING_ESCAPE');}
    if(typeof result!=='string')throw new StructureUnsafe('INVALID_JSON_STRING_TYPE');
    ensureUnicode(result);
    return result;
  }
  leaf(path:string[],type:StructuralSourceField['type'],value:unknown,start:number){
    if(path.length<1)throw new StructureUnsafe('UNNAMED_ROOT_SCALAR');
    if(this.fields.length>=MAX_FIELDS)throw new StructureUnsafe('FIELD_BOUND_EXCEEDED');
    const originalStart=this.absoluteStart+start;
    const originalEnd=this.absoluteStart+this.pos;
    this.fields.push({
      path:'/'+path.join('/'),
      type,value,
      startByte:utf8(this.source.slice(0,originalStart)),
      endByte:utf8(this.source.slice(0,originalEnd)),
    });
  }
  parse(path:string[]=[],depth=0):unknown{
    if(depth>MAX_DEPTH||++this.nodes>MAX_NODES)
      throw new StructureUnsafe('BOUNDED_PARSE_EXHAUSTED');
    this.peak=Math.max(this.peak,depth);
    this.skip();
    const begin=this.pos;
    const next=this.body[begin];
    if(next==='{'){
      this.pos++;
      const result:Record<string,unknown>=Object.create(null);
      const seen=new Set<string>();
      this.skip();
      if(this.body[this.pos]==='}'){this.pos++;return result;}
      while(true){
        this.skip();
        if(this.body[this.pos]!=='"')throw new StructureUnsafe('MISSING_JSON_KEY');
        const key=this.readString();
        if(!key||DANGEROUS.has(key)||seen.has(key))
          throw new StructureUnsafe('DUPLICATE_OR_UNSAFE_JSON_KEY');
        seen.add(key);
        this.skip();this.take(':');
        const pointer=key.replaceAll('~','~0').replaceAll('/','~1');
        result[key]=this.parse([...path,pointer],depth+1);
        this.skip();
        if(this.body[this.pos]==='}'){this.pos++;return result;}
        this.take(',');
      }
    }
    if(next==='['){
      this.pos++;
      const result:unknown[]=[];
      this.skip();
      if(this.body[this.pos]===']'){this.pos++;return result;}
      while(true){
        result.push(this.parse([...path,String(result.length)],depth+1));
        this.skip();
        if(this.body[this.pos]===']'){this.pos++;return result;}
        this.take(',');
      }
    }
    if(next==='"'){
      const value=this.readString();
      this.leaf(path,'string',value,begin);
      return value;
    }
    let value:unknown,kind:StructuralSourceField['type'];
    if(this.body.startsWith('true',this.pos)){
      this.pos+=4;value=true;kind='boolean';
    }else if(this.body.startsWith('false',this.pos)){
      this.pos+=5;value=false;kind='boolean';
    }else if(this.body.startsWith('null',this.pos)){
      this.pos+=4;value=null;kind='null';
    }else{
      NUM.lastIndex=this.pos;
      const number=NUM.exec(this.body);
      if(!number||number.index!==this.pos)throw new StructureUnsafe('INVALID_JSON_SCALAR');
      this.pos=NUM.lastIndex;
      const literal=number[0]!;
      if(INT.test(literal)){
        const exact=BigInt(literal);
        if(exact>JS_SAFE||exact< -JS_SAFE||literal==='-0')
          throw new StructureUnsafe('LOSSY_JSON_INTEGER_NEEDS_REVIEW');
        kind='integer';
      }else kind='number';
      value=Number(literal);
      if(!Number.isFinite(value))throw new StructureUnsafe('LOSSY_JSON_FLOAT_NEEDS_REVIEW');
    }
    this.leaf(path,kind,value,begin);
    return value;
  }
  walk():{fields:StructuralSourceField[];peak:number}{
    const ours=this.parse();
    this.skip();
    if(this.pos!==this.body.length)throw new StructureUnsafe('TRAILING_JSON_DATA');
    let canonical:unknown;
    try{canonical=JSON.parse(this.body);}
    catch{throw new StructureUnsafe('INVALID_JSON_OBJECT');}
    if(!canonical||Array.isArray(canonical)||typeof canonical!=='object')
      throw new StructureUnsafe('NOT_NAMED_JSON_OBJECT');
    if(!jsonEqual(ours,canonical))throw new StructureUnsafe('INCOMPATIBLE_JSON_INTERPRETATIONS');
    if(!this.fields.length)throw new StructureUnsafe('NO_SCORABLE_SOURCE_LEAVES');
    for(const field of this.fields){
      const slice=encoder.encode(this.source).slice(field.startByte,field.endByte);
      let decoded:unknown;
      try{decoded=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(slice));}
      catch{throw new StructureUnsafe('SPAN_BYTE_REPLAY_FAILED');}
      if(!jsonEqual(decoded,field.value))
        throw new StructureUnsafe('SPAN_VALUE_REPLAY_FAILED');
    }
    return {fields:this.fields,peak:this.peak};
  }
}

function chooseBody(raw:string):{start:number;kind:'json_object'|'syslog_json_object';skipped:number}|null{
  const trimmed=raw.trimStart();
  if(trimmed.startsWith('{'))
    return {start:raw.length-trimmed.length,kind:'json_object',skipped:0};
  if(!/^<\d{1,3}>/.test(raw)&&
    !/^(?:[A-Z][a-z]{2} +\d{1,2} +\d\d:\d\d:\d\d|\d{4}-\d\d-\d\dT)/.test(raw))
    return null;
  const envelope=parseSyslogEnvelope(raw);
  if(!envelope||envelope.confidence==='partial'||!envelope.message||!raw.endsWith(envelope.message))
    return null;
  const start=raw.length-envelope.message.length;
  const body=envelope.message;
  const whitespace=body.length-body.trimStart().length;
  if(body.trimStart().startsWith('{'))
    return {start:start+whitespace,kind:'syslog_json_object',skipped:whitespace};
  const prefix=ZONE_RE.exec(body);
  if(!prefix)return null;
  const suffix=body.slice(prefix[0].length);
  const padding=suffix.length-suffix.trimStart().length;
  if(!suffix.trimStart().startsWith('{'))return null;
  return {start:start+prefix[0].length+padding,
    kind:'syslog_json_object',skipped:prefix[0].length+padding};
}
export function inspectBoundedSourceSpans(raw:string):StructuralSourceObservation{
  const size=utf8(raw);
  const empty=(cause:string,disposition:StructuralDisposition='RAW_ONLY'):
    StructuralSourceObservation=>({disposition,cause,syntax:'none',fields:[],
      sourceBytes:size,bodyStartByte:null,residualPrefixBytes:0,passes:2,
      autoPromoted:false,nativeVerified:false,maxDepthObserved:0});
  if(!raw||size>MAX_BYTES||raw.includes('\0'))
    return empty('UNSUPPORTED_OR_OVERSIZED_SOURCE');
  try{ensureUnicode(raw);}catch{return empty('INVALID_UNICODE_SURROGATE','ABSTAIN_UNSAFE');}
  const selected=chooseBody(raw);
  if(!selected)return empty('NO_UNAMBIGUOUS_STRUCTURED_BODY');
  const body=raw.slice(selected.start);
  const startByte=utf8(raw.slice(0,selected.start));
  const scanner=new SpanScanner(body,raw,selected.start);
  try{
    const parsed=scanner.walk();
    return {disposition:'REVIEW_ONLY',cause:'BYTE_REPLAYED_SOURCE_SYNTAX_ONLY',
      syntax:selected.kind,fields:parsed.fields,sourceBytes:size,
      bodyStartByte:startByte,residualPrefixBytes:utf8(raw.slice(0,selected.skipped)),
      passes:2,autoPromoted:false,nativeVerified:false,maxDepthObserved:parsed.peak};
  }catch(error){
    const reason=error instanceof StructureUnsafe?error.cause:'INVALID_OR_UNVERIFIABLE_STRUCTURE';
    return {disposition:'ABSTAIN_UNSAFE',cause:reason,syntax:selected.kind,
      fields:[],sourceBytes:size,bodyStartByte:startByte,
      residualPrefixBytes:utf8(raw.slice(0,selected.skipped)),passes:2,
      autoPromoted:false,nativeVerified:false,maxDepthObserved:scanner.peak};
  }
}
