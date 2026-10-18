import {utf8OriginalByteOffsets} from './utf8OriginalByteOffsets';

/**
 * Strict, browser-local bounded RFC5424 v1 structural header/SD scanner.
 * Mirrors only the reviewed backend's synthetic qualified subset. It never
 * establishes native Fluentd or proprietary target loader compatibility.
 */
export interface Rfc5424Fields {
  syslog_pri: number;
  syslog_version: 1;
  syslog_timestamp: string;
  syslog_hostname: string;
  syslog_appname: string;
  syslog_procid: string;
  syslog_msgid: string;
  syslog_structured_data: string;
}
export type Rfc5424Scan =
  | { ok: true; fields: Rfc5424Fields; message: string | null }
  | { ok: false; error: string };

function safeTimestamp(timestamp: string): boolean {
  if (timestamp === '-') return true;
  const match = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,6})?(?:Z|([+-])(\d{2}):(\d{2}))$/.exec(timestamp);
  if (!match) return false;
  const [,year,month,day,hour,minute,second,,offsetHour,offsetMinute] = match;
  const y=Number(year), m=Number(month), d=Number(day);
  if (m < 1 || m > 12 || d < 1 || d > 31 ||
      Number(hour) > 23 || Number(minute) > 59 || Number(second) > 59 ||
      (offsetHour !== undefined && (Number(offsetHour) > 23 || Number(offsetMinute) > 59))) return false;
  return new Date(Date.UTC(y, m-1, d)).getUTCDate() === d;
}

function scanStructuredData(rest: string): { structured: string; message: string | null } | null {
  if (rest === '-') return { structured: '-', message: null };
  if (rest.startsWith('- ')) return { structured: '-', message: rest.slice(2) };
  if (!rest.startsWith('[')) return null;

  let pos=0;
  const ids=new Set<string>();
  // RFC5424 §6.3.2: printable ASCII except SP, '=', '"' and ']'.
  // '[' and '\' are permitted inside an SD-NAME; only ']' terminates SD.
  const readName=():string|null=>{
    const start=pos;
    while (pos<rest.length) {
      const c=rest.charCodeAt(pos);
      if (c<33 || c>126 || [34,61,93].includes(c)) break;
      pos++;
    }
    return pos-start>=1 && pos-start<=32 ? rest.slice(start,pos) : null;
  };
  while (rest[pos] === '[') {
    pos++;
    const id=readName();
    if (!id || ids.has(id)) return null;
    ids.add(id);
    // RFC5424 §6.3.3 permits repeated PARAM-NAMEs within one SD-ELEMENT.
    // Preserve their exact ordered wire lexemes in syslog_structured_data.
    while (rest[pos] === ' ') {
      pos++;
      const name=readName();
      if(!name)return null;
      if(rest[pos++]!=='=' || rest[pos++]!=='"')return null;
      let terminated=false;
      while(pos<rest.length){
        const character=rest[pos++];
        const code=character.charCodeAt(0);
        if (character==='"') {terminated=true;break;}
        if (character==='\\'){
          const escaped=rest[pos++];
          // Only \", \\ and \] are decoded by RFC5424. Unknown backslash
          // sequences must remain literally unchanged (§6.3.3), not rejected.
          if(escaped===undefined) return null;
        } else if(character===']' || code<32 || code===127) return null;
        if (new TextEncoder().encode(rest.slice(0,pos)).length>1024) return null;
      }
      if(!terminated)return null;
    }
    if (rest[pos++]!==']') return null;
    if (new TextEncoder().encode(rest.slice(0,pos)).length>1024) return null;
  }
  const structured=rest.slice(0,pos);
  if (!structured || new TextEncoder().encode(structured).length>1024) return null;
  const trailer=rest.slice(pos);
  if (trailer==='')return {structured,message:null};
  if (!trailer.startsWith(' '))return null;
  return {structured,message:trailer.slice(1)};
}

export function parseRfc5424Subset(
  text:string,options?:{framing?:'RFC6587_OCTET_COUNTING'},
):Rfc5424Scan {
  const counted=options?.framing==='RFC6587_OCTET_COUNTING';
  // Do not infer a multi-line record boundary from arbitrary clipboard text.
  if((!counted&&/[\r\n\0]/.test(text))||
     (counted&&(utf8OriginalByteOffsets(text)===null||
       new TextEncoder().encode(text).length>8192)))
    return {ok:false,error:'RFC5424 MSG requires verified octet-counted framing'};
  const match=/^<(\d{1,3})>(\d{1,2}) (\S+) (\S+) (\S+) (\S+) (\S+) ([\s\S]+)$/.exec(text);
  if (!match || Number(match[1])>191 || match[2]!=='1') {
    return {ok:false,error:'Unsupported RFC5424 version or header'};
  }
  const limits=[255,48,128,32];
  for (const [index,maximum] of limits.entries()) {
    const token=match[index+4];
    if(!token || new TextEncoder().encode(token).length>maximum || !/^[!-~]+$/.test(token)) {
      return {ok:false,error:'Unsupported RFC5424 header token'};
    }
  }
  if (!safeTimestamp(match[3])) return {ok:false,error:'Unsupported RFC5424 timestamp'};
  const parsed=scanStructuredData(match[8]);
  if (!parsed) return {ok:false,error:'Unsupported RFC5424 structured data syntax'};
  return {ok:true,fields:{
    syslog_pri:Number(match[1]),syslog_version:1,
    syslog_timestamp:match[3],syslog_hostname:match[4],
    syslog_appname:match[5],syslog_procid:match[6],
    syslog_msgid:match[7],syslog_structured_data:parsed.structured,
  },message:parsed.message};
}
