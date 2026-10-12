import type { ConcreteFormat, ParserDraft } from '../model';
import { extractFields, MAX_LINE_CHARS, MAX_DATASET_BYTES, MAX_EVENTS, splitEvents } from '../parser';

export type ReplayMutation = 'timestamp' | 'ip' | 'username' | 'url';
export interface SyntheticReplayPreview {
  mode: 'LOCAL_PREVIEW_ONLY';
  sentToSensor: false;
  log: string;
  mutations: ReplayMutation[];
}
const ORDER: ReplayMutation[]=['timestamp','ip','username','url'];
const IPV4=/^(?:\d{1,3}\.){3}\d{1,3}$/;
const UTC_TIME=/\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})/g;
const ISO_VALUE=/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})$/;
const IP_IN_TEXT=/(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])/g;
const URL_IN_TEXT=/https?:\/\/[^\s"'|<>;,^]+/g;
const USER_IN_TEXT=/\b(user|username|user_name|account|login)=("[^"]*"|'[^']*'|[^\s|^;]+)/gi;
const TIMESTAMP_FIELD=/^(?:(?:@)?timestamp|time|event_time|event_timestamp|datetime|date|ts)$/i;
const USER_FIELD=/^(?:user|username|user_name|account|account_name|login)$/i;
const URL_FIELD=/^(?:url|uri|request_url|request_uri|http_url)$/i;
const IP_FIELD=/(?:^|_)(?:ip|srcip|dstip|src_ip|dst_ip|source_ip|destination_ip|client_ip|server_ip)$/i;

function docIpNumber(value:string):boolean {
  return IPV4.test(value) && value.split('.').every(piece=>Number(piece)>=0 && Number(piece)<=255);
}
function secureEntropy():number {
  if(!globalThis.crypto?.getRandomValues) throw new Error('Local synthetic replay requires browser cryptographic randomness');
  const numbers=new Uint32Array(1);
  globalThis.crypto.getRandomValues(numbers);
  return numbers[0]/4294967296;
}
function draw(random:()=>number,ceiling:number):number {
  const value=random();
  if(!Number.isFinite(value)||value<0||value>=1)throw new Error('Invalid synthetic random source');
  return Math.floor(value*ceiling);
}

/** Pure single-record mutation. All synthetic destinations are reserved TEST
 * IP ranges / example.test, never live endpoints. No event is sent or stored.
 * The caller must explicitly opt into a bounded UI-only timer if desired.
 */
export function synthesizeReplayPreview(
  template:string,
  draft:ParserDraft,
  now:Date=new Date(),
  random:()=>number=secureEntropy,
):SyntheticReplayPreview {
  if(typeof template!=='string' || !template.trim() || template.length>MAX_LINE_CHARS ||
     template.includes('\n')||template.includes('\r')||
     !Number.isFinite(now.getTime()) ||
     !['json','kv','csv','cef','leef','syslog_rfc5424'].includes(draft.format)) {
    throw new Error('Only one bounded JSON/KV/CSV/CEF/LEEF/RFC5424 event supports synthetic preview');
  }
  const format=draft.format as ConcreteFormat;
  const input=extractFields(template,format,draft);
  if(input.errors.length)throw new Error('Cannot replay a malformed or unsupported source event');

  const categories=new Set<ReplayMutation>();
  const docIp=()=>{
    const prefix=['192.0.2','198.51.100','203.0.113'][draw(random,3)];
    const host=1+draw(random,254);
    categories.add('ip');
    return prefix+'.'+host;
  };
  const username=()=>{
    categories.add('username');
    return 'demo_user_'+(1000+draw(random,9000));
  };
  const fakeUrl=()=>{
    categories.add('url');
    return 'https://example.test/replay/'+(100000+draw(random,900000));
  };
  const stamp=()=>{
    categories.add('timestamp');
    return now.toISOString();
  };
  const transform=(key:string,value:unknown):unknown=>{
    if(value===null || value===undefined)return value;
    if(typeof value==='number' && TIMESTAMP_FIELD.test(key)) {
      categories.add('timestamp');
      return Math.abs(value)<100000000000 ? Math.floor(now.getTime()/1000) : now.getTime();
    }
    if(typeof value!=='string')return value;
    if((IP_FIELD.test(key)||docIpNumber(value)) && docIpNumber(value))return docIp();
    if(USER_FIELD.test(key))return username();
    if(URL_FIELD.test(key) && /^https?:\/\//i.test(value))return fakeUrl();
    if(TIMESTAMP_FIELD.test(key) && ISO_VALUE.test(value))return stamp();
    return value;
  };
  let result:string;
  if(format==='json'){
    const original:unknown=JSON.parse(template);
    const convert=(value:unknown,key:string,depth:number):unknown=>{
      if(depth>8)throw new Error('Nested JSON synthetic preview limit exceeded');
      if(Array.isArray(value))return value.map(item=>convert(item,key,depth+1));
      if(value && typeof value==='object'){
        const object:Record<string,unknown>={};
        for(const [child,content] of Object.entries(value)){
          if(['__proto__','constructor','prototype'].includes(child))throw new Error('Unsafe source object key');
          object[child]=convert(content,child,depth+1);
        }
        return object;
      }
      return transform(key,value);
    };
    result=JSON.stringify(convert(original,'',0));
  } else if(format==='csv'){
    const names=draft.csvColumns.split(',').map(name=>name.trim());
    const separator=draft.csvDelimiter??',';
    if(![',',';','\t'].includes(separator))throw new Error('Unreviewed CSV delimiter');
    result=names.map((key)=>{
      const item=String(transform(key,input.fields[key])??'');
      if(item.includes('\r')||item.includes('\n'))throw new Error('Multiline synthetic CSV is unsupported');
      return item.includes(separator)||item.includes('"') ? '"'+item.replace(/"/g,'""')+'"' : item;
    }).join(separator);
  } else {
    // Preserve reviewed RFC/CEF/LEEF envelopes and unknown extension keys;
    // update only literal ISO timestamps, IPv4s, URLs and labeled usernames.
    result=template.replace(UTC_TIME,()=>stamp());
    result=result.replace(IP_IN_TEXT,(ip)=>docIpNumber(ip)?docIp():ip);
    result=result.replace(URL_IN_TEXT,()=>fakeUrl());
    result=result.replace(USER_IN_TEXT,(_match:string,key:string,quoted:string)=>{
      const replaced=username();
      const quote=quoted.startsWith('"')||quoted.startsWith("'")?quoted[0]:'';
      return key+'='+(quote?quote+replaced+quote:replaced);
    });
  }
  if(result.length>MAX_LINE_CHARS || extractFields(result,format,draft).errors.length) {
    throw new Error('Generated preview does not satisfy the selected browser extraction format');
  }
  return {mode:'LOCAL_PREVIEW_ONLY',sentToSensor:false,log:result,mutations:ORDER.filter(type=>categories.has(type))};
}


/** Prepared in browser memory on explicit Start. All source records are
 * validated up front; never silently drop a malformed later event.
 * This in-memory plan can contain private event text: never send/store it. */
export interface LocalReplayPlan {
  mode: 'LOCAL_PREVIEW_ONLY';
  format: ParserDraft['format'];
  total: number;
  entries: ReadonlyArray<Readonly<{ raw: string; line: number }>>;
}

export function createLocalReplayPlan(sample: string, draft: ParserDraft): LocalReplayPlan {
  if (draft.guided?.eventBoundary && draft.guided.eventBoundary !== 'single-line') {
    throw new Error('Replay supports only single-line event boundaries; multiline source requires a separate review');
  }
  const size = new TextEncoder().encode(sample).byteLength;
  if (!size || size > MAX_DATASET_BYTES) throw new Error('Replay source exceeds the browser dataset size limit');
  const records = splitEvents(sample, 'single-line', MAX_EVENTS + 1);
  if (!records.length || records.length > MAX_EVENTS) {
    throw new Error('Replay needs between one and ' + MAX_EVENTS + ' bounded source events');
  }
  if (!['json', 'kv', 'csv', 'cef', 'leef', 'syslog_rfc5424'].includes(draft.format)) {
    throw new Error('Replay supports reviewed JSON/KV/CSV/CEF/LEEF/RFC5424 source formats only');
  }
  for (const record of records) {
    if (record.raw.length > MAX_LINE_CHARS ||
        extractFields(record.raw, draft.format as ConcreteFormat, draft).errors.length) {
      throw new Error('Unsupported or malformed replay source event at physical line ' + record.line);
    }
  }
  return {
    mode: 'LOCAL_PREVIEW_ONLY',
    format: draft.format,
    total: records.length,
    entries: records.map(({raw, line}) => ({raw, line})),
  };
}

/** Generates exactly one local-only event in a bounded round-robin sequence.
 * The UI owns its timer and stops it on edit, unmount, or explicit Stop. */
export function synthesizeFromReplayPlan(
  plan: LocalReplayPlan,
  draft: ParserDraft,
  cursor: number,
  now: Date = new Date(),
  random?: () => number,
): SyntheticReplayPreview & { sourceEvent: number; sourceLine: number; sourceTotal: number } {
  if (!Number.isSafeInteger(cursor) || cursor < 0 || plan.mode !== 'LOCAL_PREVIEW_ONLY' ||
      !plan.total || plan.total !== plan.entries.length || plan.format !== draft.format) {
    throw new Error('Invalid or stale synthetic replay plan');
  }
  const position = cursor % plan.total;
  const entry = plan.entries[position];
  const generated = random
    ? synthesizeReplayPreview(entry.raw, draft, now, random)
    : synthesizeReplayPreview(entry.raw, draft, now);
  return {
    ...generated,
    sourceEvent: position + 1,
    sourceLine: entry.line,
    sourceTotal: plan.total,
  };
}
