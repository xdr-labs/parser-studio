/** Shared bounded lossless source-completeness lexical audit.
 * The same scanner serves browser extraction and isolated PoC source review.
 *
 * A lexical JSON.parse or a few matching key=value tokens must never
 * establish complete source extraction or certified producer semantics.
 * This bounded scanner reports ambiguous source that browser preview can
 * otherwise silently overwrite or ignore.
 */
export type SourceCompletenessFamily='json'|'kv';
export type SourceCompletenessIssue=
  'DUPLICATE_MEMBER_SILENT_OVERWRITE'|
  'NONFINITE_NUMBER_OR_LOSS_OF_PRECISION'|
  'UNPAIRED_UNICODE_SURROGATE'|
  'UNCONSUMED_TRAILING_RAW'|
  'UNKNOWN_PRODUCER_ESCAPE'|
  'EMPTY_ASSIGNMENT_UNQUALIFIED'|
  'DUPLICATE_SOURCE_KEY'|
  'INVALID_SOURCE_LEXICAL_GRAMMAR'|
  'RESOURCE_BOUNDS';
export type SourceCompletenessInspection={
  family:SourceCompletenessFamily;
  disposition:'REVIEW_ONLY_LEXICAL'|'REVIEW_ONLY_UNCERTAIN'|'ABSTAIN_UNSAFE';
  raw:string;sourceBytes:number;
  issues:SourceCompletenessIssue[];
  namedRawFields:Array<{name:string;rawLexeme:string;nameStartByte:number;
    nameEndByte:number;valueStartByte:number;valueEndByte:number}>;
  branchAttempts:1;maxDepth:number;
  sourceFieldValuesDecoded:false;nativeStellar:'NOT_VERIFIED';
  autoPromoted:false;completeSourceClaim:false;
};
const utf8=new TextEncoder();
const keyRx=/^[A-Za-z_][A-Za-z0-9_.-]{0,127}/;
const space=(ch:string|undefined)=>ch===' '||ch==='\t';
function unicodeValid(input:string):boolean{
  for(let i=0;i<input.length;i++){
    const x=input.charCodeAt(i);
    if(x>=0xd800&&x<=0xdbff){
      if(i+1>=input.length||input.charCodeAt(++i)<0xdc00||
         input.charCodeAt(i)>0xdfff)return false;
    }else if(x>=0xdc00&&x<=0xdfff)return false;
  }
  return true;
}
class JsonBoundedAudit{
  pos=0;nodes=0;maxDepth=0;issues=new Set<SourceCompletenessIssue>();
  constructor(readonly raw:string){}
  skip(){while(/[ \t\r\n]/.test(this.raw[this.pos]??'\0'))this.pos++;}
  bad(message:SourceCompletenessIssue='INVALID_SOURCE_LEXICAL_GRAMMAR'):never{
    this.issues.add(message);throw Error('SOURCE_LEXICAL_NOT_CERTIFIED');
  }
  visit(depth:number):void{
    if(++this.nodes>10000||depth>32)
      this.bad('RESOURCE_BOUNDS');
    this.maxDepth=Math.max(depth,this.maxDepth);
    this.skip();
    const c=this.raw[this.pos];
    if(c==='"'){this.string();return;}
    if(c==='{'){this.object(depth);return;}
    if(c==='['){this.array(depth);return;}
    for(const word of ['null','true','false']){
      if(this.raw.startsWith(word,this.pos)){
        this.pos+=word.length;return;
      }
    }
    const m=/^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/.exec(this.raw.slice(this.pos));
    if(m){
      this.pos+=m[0].length;
      const n=Number(m[0]);
      if(!Number.isFinite(n)||
        (!/[.eE]/.test(m[0])&&!Number.isSafeInteger(n))||
        m[0].replace(/[^\d]/g,'').length>18)
        this.issues.add('NONFINITE_NUMBER_OR_LOSS_OF_PRECISION');
      return;
    }
    this.bad();
  }
  string():string{
    const start=this.pos++;
    let finished=false;
    while(this.pos<this.raw.length){
      const c=this.raw[this.pos++]!;
      if(c==='"'){finished=true;break;}
      if(c.charCodeAt(0)<32)this.bad();
      if(c==='\\'){
        const escaped=this.raw[this.pos++];
        if(!escaped)this.bad();
        if(escaped==='u'){
          if(!/^[0-9a-fA-F]{4}$/.test(this.raw.slice(this.pos,this.pos+4)))this.bad();
          this.pos+=4;
        }else if(!'"\\/bfnrt'.includes(escaped))this.bad();
      }
    }
    if(!finished)this.bad();
    const token=this.raw.slice(start,this.pos);
    let decoded:string;
    try{decoded=JSON.parse(token) as string;}catch{this.bad();}
    if(!unicodeValid(decoded))this.issues.add('UNPAIRED_UNICODE_SURROGATE');
    return decoded;
  }
  object(depth:number):void{
    this.pos++;this.skip();
    const keys=new Set<string>();
    if(this.raw[this.pos]==='}'){this.pos++;return;}
    for(let i=0;i<4096;i++){
      this.skip();
      if(this.raw[this.pos]!=='"')this.bad();
      const key=this.string();
      if(keys.has(key))this.issues.add('DUPLICATE_MEMBER_SILENT_OVERWRITE');
      keys.add(key);
      this.skip();
      if(this.raw[this.pos++]!==':')this.bad();
      this.visit(depth+1);this.skip();
      const next=this.raw[this.pos++];
      if(next==='}')return;
      if(next!==',')this.bad();
    }
    this.bad('RESOURCE_BOUNDS');
  }
  array(depth:number):void{
    this.pos++;this.skip();
    if(this.raw[this.pos]===']'){this.pos++;return;}
    for(let i=0;i<4096;i++){
      this.visit(depth+1);this.skip();
      const next=this.raw[this.pos++];
      if(next===']')return;
      if(next!==',')this.bad();
    }
    this.bad('RESOURCE_BOUNDS');
  }
  run():void{
    this.visit(0);
    this.skip();
    if(this.pos!==this.raw.length)this.bad();
  }
}
function parseKV(raw:string):{
  issues:SourceCompletenessIssue[];
  fields:SourceCompletenessInspection['namedRawFields'];
}|null{
  const issues=new Set<SourceCompletenessIssue>();
  const fields:SourceCompletenessInspection['namedRawFields']=[];
  const seen=new Set<string>();let cursor=0;
  for(let count=0;cursor<raw.length&&count<256;count++){
    while(space(raw[cursor]))cursor++;
    if(cursor>=raw.length)break;
    const nameStart=cursor;
    const m=keyRx.exec(raw.slice(cursor));
    if(!m||raw[cursor+m[0].length]!=='='){
      issues.add('UNCONSUMED_TRAILING_RAW');break;
    }
    const key=m[0]!;
    cursor+=key.length+1;
    if(seen.has(key))issues.add('DUPLICATE_SOURCE_KEY');
    seen.add(key);
    const valueStart=cursor;
    if(raw[cursor]==='"'||raw[cursor]==="'"){
      const quote=raw[cursor++]!;
      let closed=false;
      while(cursor<raw.length){
        const ch=raw[cursor++]!;
        if(ch==='\\'){
          issues.add('UNKNOWN_PRODUCER_ESCAPE');
          if(cursor>=raw.length)break;
          cursor++;continue;
        }
        if(ch===quote){closed=true;break;}
        if(ch.charCodeAt(0)<32&&ch!=='\t'){
          issues.add('INVALID_SOURCE_LEXICAL_GRAMMAR');break;
        }
      }
      if(!closed)issues.add('INVALID_SOURCE_LEXICAL_GRAMMAR');
      if(cursor<raw.length&&!space(raw[cursor]))
        issues.add('UNCONSUMED_TRAILING_RAW');
    }else{
      while(cursor<raw.length&&!space(raw[cursor])){
        if(raw[cursor]==='\\')issues.add('UNKNOWN_PRODUCER_ESCAPE');
        if(raw[cursor]==='"'||raw[cursor]==="'")
          issues.add('INVALID_SOURCE_LEXICAL_GRAMMAR');
        cursor++;
      }
      if(valueStart===cursor)issues.add('EMPTY_ASSIGNMENT_UNQUALIFIED');
    }
    const valEnd=cursor;
    const toByte=(n:number)=>utf8.encode(raw.slice(0,n)).length;
    fields.push({name:key,rawLexeme:raw.slice(valueStart,valEnd),
      nameStartByte:toByte(nameStart),nameEndByte:toByte(nameStart+key.length),
      valueStartByte:toByte(valueStart),valueEndByte:toByte(valEnd)});
    if(cursor<raw.length&&!space(raw[cursor])){
      issues.add('UNCONSUMED_TRAILING_RAW');break;
    }
  }
  if(!fields.length&&issues.size===0)issues.add('INVALID_SOURCE_LEXICAL_GRAMMAR');
  if(fields.length>=256)issues.add('RESOURCE_BOUNDS');
  return {issues:[...issues],fields};
}
export function inspectSourceCompleteness(raw:string,
  family:SourceCompletenessFamily,
  options?:{maxBytes?:number}):SourceCompletenessInspection{
  const sourceBytes=utf8.encode(raw).length;
  const base:SourceCompletenessInspection={
    family,disposition:'ABSTAIN_UNSAFE',raw,sourceBytes,issues:[],
    namedRawFields:[],branchAttempts:1,maxDepth:0,
    sourceFieldValuesDecoded:false,nativeStellar:'NOT_VERIFIED',
    autoPromoted:false,completeSourceClaim:false,
  };
  const maxBytes=Math.min(1048576,Math.max(1,options?.maxBytes??65536));
  if(!raw||sourceBytes>maxBytes||!unicodeValid(raw)||raw.includes('\0'))
    return {...base,issues:['RESOURCE_BOUNDS']};
  if(family==='json'){
    const parsed=new JsonBoundedAudit(raw);
    try{parsed.run();}catch{
      const issues:SourceCompletenessIssue[]=parsed.issues.size>0?
        [...parsed.issues]:['INVALID_SOURCE_LEXICAL_GRAMMAR'];
      return {...base,maxDepth:parsed.maxDepth,issues};
    }
    const issues=[...parsed.issues];
    return {...base,maxDepth:parsed.maxDepth,issues,
      disposition:issues.length?'REVIEW_ONLY_UNCERTAIN':'REVIEW_ONLY_LEXICAL'};
  }
  if(/[\r\n]/.test(raw))return {...base,issues:['INVALID_SOURCE_LEXICAL_GRAMMAR']};
  const res=parseKV(raw);
  if(!res)return {...base,issues:['INVALID_SOURCE_LEXICAL_GRAMMAR']};
  // Unknown or incompletely consumed source is never promoted with partial
  // fields. Exact lexical source claims are retained only on safe full replay.
  return {...base,issues:res.issues,
    disposition:res.issues.length?'REVIEW_ONLY_UNCERTAIN':'REVIEW_ONLY_LEXICAL',
    namedRawFields:res.issues.length?[]:res.fields};
}
