/** Isolated RFC5424 §6.3 SD-PARAM byte-level reference candidate.
 * Does not decode MSG/CEF/native KV or qualify any manufacturer implementation.
 */
import {createHash} from 'node:crypto';

export type SdByteParam={
  sdId:string; name:string; decodedValue:string;
  rawNameStart:number; rawNameEnd:number;
  rawValueStart:number; rawValueEnd:number;
  unrecognizedEscapes:number;
};
export type SdByteElement={id:string; start:number; end:number; params:SdByteParam[]};
export type SdByteResult={
  sourceSha256:string;
  sourceBytes:number;
  structuredDataStart:number;structuredDataEnd:number;
  messageStart:number|null;
  elements:SdByteElement[];
  standardContract:'RFC5424_SD_PARAM_ONLY';
  deviceImplementation:'NOT_CERTIFIED';
  nativeTarget:'NOT_VERIFIED';
  canAutoPromote:false;
};

const decoder=new TextDecoder('utf-8',{fatal:true});
const nameByte=(v:number)=>v>=33&&v<=126&&v!==34&&v!==61&&v!==93;
const segment=(raw:Uint8Array,start:number,end:number):string|null=>{
  try{return decoder.decode(raw.subarray(start,end));}catch{return null;}
};
const ascii=(raw:Uint8Array,start:number,end:number)=>{
  const value=raw.subarray(start,end);
  return value.every(b=>b<=127)?Buffer.from(value).toString('ascii'):null;
};
const invalidTime=(part:string):boolean=>{
  if(part==='-')return false;
  const m=/^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.([0-9]{1,6}))?(Z|[+-][0-9]{2}:[0-9]{2})$/.exec(part);
  if(!m)return true;
  const [year,month,day,hour,minute,second]=m.slice(1,7).map(Number);
  const leap=year%4===0&&(year%100!==0||year%400===0);
  const monthDays=[31,leap?29:28,31,30,31,30,31,31,30,31,30,31];
  if(month<1||month>12||day<1||day>monthDays[month-1]!||
    hour>23||minute>59||second>59)return true;
  const zone=m[8]!;
  if(zone!=='Z'){
    const offsetHour=Number(zone.slice(1,3));
    const offsetMinute=Number(zone.slice(4,6));
    if(offsetHour>23||offsetMinute>59)return true;
  }
  return false;
};

/** Returns null for unsupported/malformed frames; never guesses a vendor escape. */
export function rfc5424SdByteEscapes(source:Uint8Array):SdByteResult|null{
  if(!source.length||source.length>16384)return null;
  const data=Uint8Array.from(source);
  // Header and SD must qualify independently from MSG. RFC5424 §6.4
  // permits non-UTF-8 MSG-ANY bytes, so decoding the *whole* record as
  // UTF-8 before checking the ASCII header would lose legal source data.
  let pos=0;
  if(data[pos++]!==60)return null;
  let pri='';
  while(pos<data.length&&data[pos]!>=48&&data[pos]!<=57){
    if(pri.length>=3)return null;
    pri+=String.fromCharCode(data[pos]!);pos++;
  }
  if(pri.length===0||data[pos++]!==62||Number(pri)>191||
     (pri.length>1&&pri[0]==='0')||
     data[pos++]!==49||data[pos++]!==32)return null;
  const headerParts:string[]=[];
  // RFC5424: TIMESTAMP HOSTNAME APP-NAME PROCID MSGID (five space-separated tokens).
  for(let i=0;i<5;i++){
    const stop=data.indexOf(32,pos);
    if(stop<0){
      // MSGID is followed by a space as STRUCTURED-DATA is mandatory.
      return null;
    }
    const part=ascii(data,pos,stop);
    const maxLength=[255,255,48,128,32][i]!;
    if(!part||part.length>maxLength)return null;
    headerParts.push(part);
    pos=stop+1;
  }
  if(invalidTime(headerParts[0]!)||
     headerParts.slice(1).some(x=>!/^[\x21-\x7e]+$/.test(x)))
    return null;
  const sdStart=pos;
  if(data[pos]===45){ // NILVALUE '-'
    if(pos+1<data.length&&data[pos+1]!==32)return null;
    const after=pos+1===data.length?null:pos+2;
    return {sourceSha256:createHash('sha256').update(data).digest('hex'),
      sourceBytes:data.length,structuredDataStart:sdStart,
      structuredDataEnd:pos+1,messageStart:after,elements:[],
      standardContract:'RFC5424_SD_PARAM_ONLY',deviceImplementation:'NOT_CERTIFIED',
      nativeTarget:'NOT_VERIFIED',canAutoPromote:false};
  }
  if(data[pos]!==91)return null;
  const elements:SdByteElement[]=[];
  const ids=new Set<string>();
  let paramTotal=0;
  while(pos<data.length&&data[pos]===91){
    if(elements.length>=32)return null;
    const begin=pos++;
    const idStart=pos;
    while(pos<data.length&&nameByte(data[pos]!)&&pos-idStart<=32)pos++;
    if(pos===idStart||pos-idStart>32)return null;
    const sdId=ascii(data,idStart,pos);
    if(!sdId||ids.has(sdId))return null;
    ids.add(sdId);
    const params:SdByteParam[]=[];
    while(pos<data.length&&data[pos]===32){
      pos++;
      const nameStart=pos;
      while(pos<data.length&&nameByte(data[pos]!)&&pos-nameStart<=32)pos++;
      if(pos===nameStart||pos-nameStart>32||data[pos]!==61||data[pos+1]!==34)
        return null;
      const name=ascii(data,nameStart,pos);
      if(name===null)return null;
      pos+=2;
      const valueStart=pos;
      const decoded:number[]=[];
      let unknown=0,closed=false;
      while(pos<data.length){
        const ch=data[pos]!;
        if(ch===34){closed=true;break;}
        if(ch===93)return null; // ] inside PARAM-VALUE MUST be escaped.
        if(ch===92){
          if(pos+1>=data.length)return null;
          const next=data[pos+1]!;
          if(next===34||next===92||next===93)decoded.push(next);
          else {decoded.push(ch,next);unknown++;}
          pos+=2;
        }else{
          decoded.push(ch);
          pos++;
        }
        if(pos-valueStart>8192)return null;
      }
      if(!closed||paramTotal++>=256)return null;
      const valueEnd=pos;
      const value=segment(Uint8Array.from(decoded),0,decoded.length);
      if(value===null)return null;
      pos++;
      params.push({sdId,name,decodedValue:value,
        rawNameStart:nameStart,rawNameEnd:nameStart+name.length,
        rawValueStart:valueStart,rawValueEnd:valueEnd,
        unrecognizedEscapes:unknown});
    }
    if(data[pos]!==93)return null;
    pos++;
    elements.push({id:sdId,start:begin,end:pos,params});
  }
  // After SD can be MSG, beginning with exactly one SP.
  let messageStart:null|number=null;
  if(pos<data.length){
    if(data[pos]!==32)return null;
    messageStart=pos+1;
  }
  return {sourceSha256:createHash('sha256').update(data).digest('hex'),
    sourceBytes:data.length,structuredDataStart:sdStart,structuredDataEnd:pos,
    messageStart,elements,
    standardContract:'RFC5424_SD_PARAM_ONLY',
    deviceImplementation:'NOT_CERTIFIED',nativeTarget:'NOT_VERIFIED',
    canAutoPromote:false};
}
