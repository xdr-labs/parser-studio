/**
 * Vendor-neutral, fail-closed source-field byte spans for RFC3164 and RFC5424.
 * Separate PoC observer, not a product parser or native Fluentd qualification.
 *
 * This grammar never decodes vendor/KV/CEF/LEEF message semantics and never
 * treats a syntactic match as an independently verified parse success.
 */
export type SyslogSourceState='REVIEW_ONLY'|'ABSTAIN_UNSAFE'|'RAW_ONLY';
export type SyslogSourceFormat='rfc3164'|'rfc5424'|'none';
export interface SyslogOriginalField{
  name:string;value:string;type:'string';
  startByte:number;endByte:number;
}
export interface SyslogSourceInspection{
  disposition:SyslogSourceState;
  format:SyslogSourceFormat;
  fields:SyslogOriginalField[];
  reason:string;
  sourceBytes:number;
  originalRaw:string;
  branchAttempts:number;
  maxDepth:number;
  autoPromoted:false;
  manufacturerSemantics:'NOT_CERTIFIED';
  nativeParser:'NOT_VERIFIED';
  /** Valid RFC5424 syntax, but repeated member meaning needs producer truth. */
  repeatedSdParamNames?:number;
}
const utf8=new TextEncoder();
const decoder=new TextDecoder('utf-8',{fatal:true});
const MONTHS=new Map<string,number>([
  ['Jan',1],['Feb',2],['Mar',3],['Apr',4],['May',5],['Jun',6],
  ['Jul',7],['Aug',8],['Sep',9],['Oct',10],['Nov',11],['Dec',12],
]);
const MAX_BYTES=8192;
const SD_UNSAFE=new Set(['__proto__','constructor','prototype']);
class Invalid extends Error{
  constructor(readonly code:string){super(code);}
}
function unicodeValid(value:string):boolean{
  for(let i=0;i<value.length;i++){
    const first=value.charCodeAt(i);
    if(first>=0xd800&&first<=0xdbff){
      const low=value.charCodeAt(++i);
      if(!Number.isInteger(low)||low<0xdc00||low>0xdfff)return false;
    }else if(first>=0xdc00&&first<=0xdfff)return false;
  }
  return true;
}
function calendarValid(year:number,month:number,day:number):boolean{
  if(year<1||year>9999||month<1||month>12||day<1)return false;
  const leap=year%4===0&&(year%100!==0||year%400===0);
  const days=[31,leap?29:28,31,30,31,30,31,31,30,31,30,31];
  return day<=days[month-1]!;
}
function validTimestamp(token:string):boolean{
  if(token==='-')return true;
  const m=/^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.([0-9]{1,9}))?(Z|[+-][0-9]{2}:[0-9]{2})$/.exec(token);
  return !!m&&calendarValid(+m[1]!,+m[2]!,+m[3]!)&&
    +m[4]!<=23&&+m[5]!<=59&&+m[6]!<=59&&
    (m[8]==='Z'||(+m[8]!.slice(1,3)<=23&&+m[8]!.slice(4,6)<=59));
}
function sdNameChar(code:number):boolean{
  return code>=33&&code<=126&&code!==34&&code!==61&&code!==93;
}
class ByteAwareFields{
  readonly fields:SyslogOriginalField[]=[];
  repeatedSdParamNames=0;
  constructor(readonly raw:string){}
  push(name:string,start:number,end:number){
    if(start<0||end<start||end>this.raw.length)
      throw new Invalid('SOURCE_RANGE_OUTSIDE_ORIGINAL');
    const value=this.raw.slice(start,end);
    if(value.length===0)return;
    const startByte=utf8.encode(this.raw.slice(0,start)).length;
    const endByte=utf8.encode(this.raw.slice(0,end)).length;
    if(this.fields.some(f=>f.name===name))
      throw new Invalid('COLLIDING_SOURCE_FIELD');
    this.fields.push({name,value,type:'string',startByte,endByte});
  }
  check():void{
    const source=utf8.encode(this.raw);
    const sorted=[...this.fields].sort((a,b)=>a.startByte-b.startByte);
    let cursor=0;
    for(const field of sorted){
      if(field.startByte<cursor||field.endByte>source.length)
        throw new Invalid('OVERLAPPING_OR_UNBOUNDED_SOURCE_SPANS');
      let replay:string;
      try{replay=decoder.decode(source.slice(field.startByte,field.endByte));}
      catch{throw new Invalid('INVALID_UTF8_SOURCE_SLICE');}
      if(replay!==field.value)throw new Invalid('BYTE_SPAN_VALUE_REPLAY_FAILED');
      cursor=field.endByte;
    }
  }
}
function rfc5424(raw:string,fields:ByteAwareFields):boolean{
  const pri=/^<([0-9]{1,3})>/.exec(raw);
  if(!pri||+pri[1]!>191||(+pri[1]!>0&&pri[1]![0]==='0'))
    return false;
  let cursor=pri[0].length;
  const version=/^([1-9][0-9]{0,2}) /.exec(raw.slice(cursor));
  if(!version)return false;
  fields.push('pri',1,pri[0].length-1);
  fields.push('version',cursor,cursor+version[1]!.length);
  cursor+=version[0].length;
  const keys=['timestamp','hostname','appname','procid','msgid'] as const;
  for(let index=0;index<keys.length;index++){
    const end=raw.indexOf(' ',cursor);
    if(end<cursor)throw new Invalid('RFC5424_MISSING_HEADER_SEPARATOR');
    const part=raw.slice(cursor,end);
    if(part.length<1||part.length>[255,255,48,128,32][index]!)
      throw new Invalid('RFC5424_HEADER_FIELD_BOUNDS');
    if(index===0){
      if(!validTimestamp(part))throw new Invalid('RFC5424_INVALID_TIMESTAMP');
    }else if(!/^[\x21-\x7e]+$/.test(part))
      throw new Invalid('RFC5424_NON_ASCII_HEADER_TOKEN');
    if(part!=='-')fields.push(keys[index]!,cursor,end);
    cursor=end+1;
  }
  const sdStart=cursor;
  if(raw[cursor]==='-'){
    cursor++;
  }else if(raw[cursor]==='['){
    const sdIds=new Set<string>();
    let sdElements=0,paramCount=0;
    do{
      if(++sdElements>64)throw new Invalid('RFC5424_SD_ELEMENT_LIMIT');
      cursor++;const idStart=cursor;
      while(cursor<raw.length&&sdNameChar(raw.charCodeAt(cursor))&&
        cursor-idStart<=32)cursor++;
      const id=raw.slice(idStart,cursor);
      if(!id||id.length>32||SD_UNSAFE.has(id)||sdIds.has(id))
        throw new Invalid('RFC5424_SD_DUPLICATE_OR_UNSAFE_ID');
      sdIds.add(id);
      // RFC 5424 §6.3.3 permits repeated SD-PARAM names in one SD element.
      // Count occurrences for later independent semantic qualification.
      // They remain valid source syntax but are not a unique decoded map.
      const seenParamNames=new Set<string>();
      while(raw[cursor]===' '){
        if(++paramCount>256)throw new Invalid('RFC5424_SD_PARAMETER_LIMIT');
        cursor++;
        const start=cursor;
        while(cursor<raw.length&&sdNameChar(raw.charCodeAt(cursor))&&
          cursor-start<=32)cursor++;
        const name=raw.slice(start,cursor);
        if(!name||name.length>32||SD_UNSAFE.has(name))
          throw new Invalid('RFC5424_SD_INVALID_OR_UNSAFE_PARAM_NAME');
        if(seenParamNames.has(name))fields.repeatedSdParamNames++;
        else seenParamNames.add(name);
        if(raw.slice(cursor,cursor+2)!=='="')
          throw new Invalid('RFC5424_SD_INVALID_PARAMETER_DELIMITER');
        cursor+=2;
        let closed=false;
        while(cursor<raw.length){
          const char=raw[cursor]!;
          if(char==='\\'){
            const next=raw[cursor+1];
            if(next===undefined||next==='\n'||next==='\r'||next==='\0')
              throw new Invalid('RFC5424_SD_TRUNCATED_ESCAPE');
            // RFC5424 §6.3.3 requires undefined escape sequences to remain
            // unchanged in the original wire. Do not reinterpret them as
            // CEF or vendor KV escape sequences or reject standard syntax.
            // This observer preserves the entire SD lexical source span.
            cursor+=2;continue;
          }
          if(char===']')throw new Invalid('RFC5424_SD_UNESCAPED_RIGHT_BRACKET');
          if(char==='"'){cursor++;closed=true;break;}
          if(char==='\r'||char==='\n'||char==='\0')
            throw new Invalid('RFC5424_SD_CONTROL_IN_PARAMETER');
          cursor++;
        }
        if(!closed)throw new Invalid('RFC5424_SD_UNTERMINATED_QUOTE');
      }
      if(raw[cursor]!==']')throw new Invalid('RFC5424_SD_MISSING_CLOSING_BRACKET');
      cursor++;
    }while(raw[cursor]==='[');
  }else throw new Invalid('RFC5424_MISSING_STRUCTURED_DATA');
  fields.push('structured_data_raw',sdStart,cursor);
  if(cursor===raw.length)return true;
  if(raw[cursor]!==' ')throw new Invalid('RFC5424_MSG_SEPARATOR_MISSING');
  cursor++;
  const message=raw.slice(cursor);
  // Unlike RFC3164, RFC5424 MSG may contain LF. Do not silently split another
  // PRI-prefixed physical record into a single successful source event.
  if(/[\r\n]/.test(message)&&/(?:^|[\r\n])<\d{1,3}>/.test(message))
    throw new Invalid('AMBIGUOUS_MULTIRECORD_SYSLOG_MSG');
  if(message.includes('\0'))throw new Invalid('RFC5424_MSG_CONTROL_NUL');
  if(message.length>0)fields.push('message',cursor,raw.length);
  return true;
}
function rfc3164(raw:string,fields:ByteAwareFields):boolean{
  if(/[\r\n\0]/.test(raw))return false;
  const match=/^<([0-9]{1,3})>([A-Z][a-z]{2})( +)([0-9]{1,2})( +)([0-9]{2}:[0-9]{2}:[0-9]{2})( +)([^ \t]+)( +)(.*)$/.exec(raw);
  if(!match||+match[1]!>191)return false;
  const month=MONTHS.get(match[2]!);
  const day=+match[4]!,clock=match[6]!;
  if(!month||day<1||day>(month===2?29:[4,6,9,11].includes(month)?30:31)||
     +clock.slice(0,2)>23||+clock.slice(3,5)>59||+clock.slice(6,8)>59)
    throw new Invalid('RFC3164_INVALID_CALENDAR_OR_CLOCK');
  if(!/^[A-Za-z0-9][A-Za-z0-9_.-]{0,254}$/.test(match[8]!))
    throw new Invalid('RFC3164_UNQUALIFIED_HOST');
  fields.push('pri',1,1+match[1]!.length);
  let pos=match[1]!.length+2;
  for(const [name,length] of [
    ['month',match[2]!.length],['skip',match[3]!.length],
    ['day',match[4]!.length],['skip',match[5]!.length],
    ['time',match[6]!.length],['skip',match[7]!.length],
    ['hostname',match[8]!.length],['skip',match[9]!.length],
  ] as const){
    if(name!=='skip')fields.push(name,pos,pos+length);
    pos+=length;
  }
  const message=match[10]!;
  const tagged=/^([A-Za-z0-9_.@/-]{1,128})(?:\[([0-9]{1,10})\])?:[ \t]*(.*)$/.exec(message);
  if(tagged&&tagged[1]!=='CEF'&&tagged[1]!=='LEEF'){
    fields.push('appname',pos+tagged.index,pos+tagged[1]!.length);
    if(tagged[2]){
      const procStart=tagged[1]!.length+1;
      fields.push('procid',pos+procStart,pos+procStart+tagged[2].length);
    }
    const messageStart=pos+tagged[0].length-tagged[3]!.length;
    if(tagged[3])fields.push('message',messageStart,raw.length);
  }else if(message.length>0)fields.push('message',pos,raw.length);
  return true;
}
export function inspectGeneralSyslogEnvelope(raw:string):SyslogSourceInspection{
  const size=utf8.encode(raw).length;
  const make=(disposition:SyslogSourceState,format:SyslogSourceFormat,
    reason:string,fields:SyslogOriginalField[]=[],branchAttempts=0):SyslogSourceInspection=>({
    disposition,format,fields,reason,sourceBytes:size,originalRaw:raw,
    branchAttempts,maxDepth:1,autoPromoted:false,
    manufacturerSemantics:'NOT_CERTIFIED',nativeParser:'NOT_VERIFIED',
  });
  if(!raw||size>MAX_BYTES||!unicodeValid(raw)||raw.includes('\0'))
    return make('RAW_ONLY','none','OUTSIDE_BOUNDED_SOURCE_CONTRACT');
  if(!/^<[0-9]{1,3}>/.test(raw))
    return make('RAW_ONLY','none','NO_SUPPORTED_PRI_HEADER');
  const attempt=new ByteAwareFields(raw);
  const isVersioned=/^<[0-9]{1,3}>[1-9][0-9]{0,2} /.test(raw);
  const kind:SyslogSourceFormat=isVersioned?'rfc5424':'rfc3164';
  try{
    const matched=isVersioned?rfc5424(raw,attempt):rfc3164(raw,attempt);
    if(!matched)return make('ABSTAIN_UNSAFE',kind,'AMBIGUOUS_OR_UNSUPPORTED_ENVELOPE',[],2);
    attempt.check();
    const observed=make(
      'REVIEW_ONLY',kind,'EXACT_SOURCE_LEXER_NOT_INDEPENDENTLY_CERTIFIED',
      attempt.fields,2,
    );
    return attempt.repeatedSdParamNames>0?
      {...observed,repeatedSdParamNames:attempt.repeatedSdParamNames}:observed;
  }catch(error){
    return make('ABSTAIN_UNSAFE',kind,
      error instanceof Invalid?error.code:'SOURCE_ENVELOPE_VERIFICATION_FAILED',[],2);
  }
}
