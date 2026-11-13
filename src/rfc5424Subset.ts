/**
 * Strict, browser-local bounded RFC5424 v1 structural header/SD scanner.
 * Mirrors only the reviewed backend's synthetic qualified subset. It never
 * establishes native Fluentd or proprietary target loader compatibility.
 */
import { matchRfc5424Header } from './grammar/syslogHeader';

export interface Rfc5424SdElement {
  sd_id: string;
  params: Record<string,string>;
}
export interface Rfc5424Fields {
  syslog_pri: number;
  syslog_version: number;
  syslog_timestamp: string;
  syslog_hostname: string;
  syslog_appname: string;
  syslog_procid: string;
  syslog_msgid: string;
  syslog_structured_data: string;
  syslog_sd?: Record<string,Rfc5424SdElement>;
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

// Source SD-NAMEs may contain tokens outside the supported mapping-path grammar.
function safeParameterKey(name:string):string {
  if(/^[A-Za-z_][A-Za-z0-9_-]{0,63}$/.test(name) &&
     !['__proto__','constructor','prototype'].includes(name) &&
     !name.startsWith('param_hex_'))return name;
  return 'param_hex_'+Array.from(new TextEncoder().encode(name))
    .map(byte=>byte.toString(16).padStart(2,'0')).join('');
}

function scanStructuredData(rest: string): {
  structured: string; message: string | null;
  elements: Record<string,Rfc5424SdElement>;
} | null {
  if (rest === '-') return { structured: '-', message: null, elements:{} };
  if (rest.startsWith('- ')) return { structured: '-', message: rest.slice(2), elements:{} };
  if (!rest.startsWith('[')) return null;

  let pos=0;
  const ids=new Set<string>();
  const elements:Record<string,Rfc5424SdElement>={};
  // Backend's reviewed ASCII SD-NAME bytes: printable except \",=,[,],backslash.
  const readName=():string|null=>{
    const start=pos;
    while (pos<rest.length) {
      const c=rest.charCodeAt(pos);
      if (c<33 || c>126 || [34,61,91,92,93].includes(c)) break;
      pos++;
    }
    return pos-start>=1 && pos-start<=32 ? rest.slice(start,pos) : null;
  };
  while (rest[pos] === '[') {
    pos++;
    const id=readName();
    if (!id || ids.has(id)) return null;
    ids.add(id);
    const names=new Set<string>();
    const params:Record<string,string>={};
    while (rest[pos] === ' ') {
      pos++;
      const name=readName();
      if(!name || names.has(name)) return null;
      names.add(name);
      if(rest[pos++]!=='=' || rest[pos++]!=='"')return null;
      let terminated=false;
      let value='';
      while(pos<rest.length){
        const character=rest[pos++];
        const code=character.charCodeAt(0);
        if (character==='"') {terminated=true;break;}
        if (character==='\\'){
          const escaped=rest[pos++];
          if(escaped!==']' && escaped!=='"' && escaped!=='\\') return null;
          value+=escaped;
        } else {
          if(character===']' || code<32 || code===127)return null;
          value+=character;
        }
        if (new TextEncoder().encode(rest.slice(0,pos)).length>1024) return null;
      }
      if(!terminated)return null;
      const key=safeParameterKey(name);
      if(Object.prototype.hasOwnProperty.call(params,key))return null;
      params[key]=value;
    }
    if (rest[pos++]!==']') return null;
    elements['element_'+ids.size]={sd_id:id,params};
    if (new TextEncoder().encode(rest.slice(0,pos)).length>1024) return null;
  }
  const structured=rest.slice(0,pos);
  if (!structured || new TextEncoder().encode(structured).length>1024) return null;
  const trailer=rest.slice(pos);
  if (trailer==='')return {structured,message:null,elements};
  if (!trailer.startsWith(' '))return null;
  return {structured,message:trailer.slice(1),elements};
}

export function parseRfc5424Subset(text:string):Rfc5424Scan {
  if (text.includes('\n') || text.includes('\r')) return {ok:false,error:'RFC5424 multi-line message unsupported'};
  // Header grammar, token length limits, PRI range and the supported VERSION
  // list come from contracts/syslog-header-grammar.v1.json.
  const header=matchRfc5424Header(text);
  if (!header.ok) return {ok:false,error:'Unsupported RFC5424 version or header'};
  if (!safeTimestamp(header.timestamp)) return {ok:false,error:'Unsupported RFC5424 timestamp'};
  const parsed=scanStructuredData(header.rest);
  if (!parsed) return {ok:false,error:'Unsupported RFC5424 structured data syntax'};
  return {ok:true,fields:{
    syslog_pri:header.pri,syslog_version:Number(header.version),
    syslog_timestamp:header.timestamp,syslog_hostname:header.hostname,
    syslog_appname:header.appname,syslog_procid:header.procid,
    syslog_msgid:header.msgid,syslog_structured_data:parsed.structured,
    ...(Object.keys(parsed.elements).length?{syslog_sd:parsed.elements}:{}),
  },message:parsed.message};
}
