import type {EventResult,ParserDraft} from '../model';
import {parseSyslogEnvelope} from '../syslogEnvelope';

export interface RobustnessVariant{
  id:string;
  eventLine:number;
  label:string;
  source:string;
  transformation:'JSON_KEY_ORDER'|'KV_TOKEN_ORDER'|'CSV_SAFE_QUOTING'|'RFC3164_DAY_SPACING';
  semantics:'SYNTAX_EQUIVALENT_REVIEW_ONLY';
}

export interface RobustnessOutcome{
  id:string;
  eventLine:number;
  label:string;
  passed:boolean;
  reason:'SAME_NORMALIZED_OUTPUT'|'PARSER_REJECTED'|'OUTPUT_CHANGED';
}

function objectValue(value:unknown):Record<string,unknown>|null{
  return value&&typeof value==='object'&&!Array.isArray(value)
    ?value as Record<string,unknown>:null;
}

function stableWithoutRaw(value:unknown,path:readonly string[]=[]):unknown{
  if(Array.isArray(value))return value.map((item,index)=>
    stableWithoutRaw(item,[...path,String(index)]));
  const object=objectValue(value);
  if(!object)return value;
  return Object.fromEntries(Object.keys(object).sort().flatMap(key=>{
    const preservedRaw=path[0]==='parserstudio_source'&&
      ['source_raw','message_raw'].includes(key);
    return preservedRaw?[]:[[key,stableWithoutRaw(object[key],[...path,key])]];
  }));
}

function hasDuplicateTopLevelJsonKeys(raw:string):boolean{
  let depth=0,inString=false,escaped=false,stringStart=-1;
  const keys=new Set<string>();
  for(let index=0;index<raw.length;index++){
    const char=raw[index]!;
    if(inString){
      if(escaped){escaped=false;continue;}
      if(char==='\\'){escaped=true;continue;}
      if(char==='"'){
        if(depth===1&&stringStart>=0){
          let next=index+1;
          while(/\s/.test(raw[next]??''))next++;
          if(raw[next]===':'){
            try{
              const key=JSON.parse(raw.slice(stringStart,index+1));
              if(typeof key==='string'){
                if(keys.has(key))return true;
                keys.add(key);
              }
            }catch{return true;}
          }
        }
        inString=false;stringStart=-1;
      }
      continue;
    }
    if(char==='"'){inString=true;stringStart=index;continue;}
    if(char==='{'||char==='[')depth++;
    else if(char==='}'||char===']')depth--;
  }
  return false;
}

function reverseJson(raw:string):string|null{
  if(!raw.trimStart().startsWith('{')||hasDuplicateTopLevelJsonKeys(raw))return null;
  try{
    const parsed=JSON.parse(raw);
    const object=objectValue(parsed);
    if(!object||Object.keys(object).length<2)return null;
    const reversed=Object.fromEntries(Object.entries(object).reverse());
    const next=JSON.stringify(reversed);
    return next!==raw&&next.length<=8192?next:null;
  }catch{return null;}
}

function reverseSimpleKv(raw:string):string|null{
  const tokens=raw.trim().split(/ +/);
  if(tokens.length<2||tokens.length>64||
     !tokens.every(token=>/^[A-Za-z_][A-Za-z0-9_.-]{0,63}=[^\s"']{1,512}$/.test(token)))
    return null;
  const keys=tokens.map(token=>token.slice(0,token.indexOf('=')));
  if(new Set(keys).size!==keys.length)return null;
  const next=[...tokens].reverse().join(' ');
  return next!==raw?next:null;
}

function quoteSimpleCsvField(body:string):string|null{
  if(body.includes('"')||body.includes('\0'))return null;
  const values=body.split(',');
  if(values.length<2||values.length>150)return null;
  const index=values.findIndex(value=>/^[A-Za-z][A-Za-z0-9_.-]{1,31}$/.test(value));
  if(index<0)return null;
  const next=[...values];next[index]='"'+values[index]+'"';
  return next.join(',');
}

function csvVariant(event:EventResult):string|null{
  const generic=objectValue(event.fields.generic);
  const isCsv=event.effectiveFormat==='csv'||
    ['panos_traffic_csv','rfc3164_positional_csv','syslog_envelope_positional_csv']
      .includes(String(generic?.mode??''));
  if(!isCsv)return null;
  const envelope=parseSyslogEnvelope(event.raw);
  if(envelope&&envelope.message&&event.raw.endsWith(envelope.message)){
    const body=quoteSimpleCsvField(envelope.message);
    if(body&&body!==envelope.message)return event.raw.slice(0,event.raw.length-envelope.message.length)+body;
  }
  return quoteSimpleCsvField(event.raw);
}

function rfc3164Spacing(raw:string):string|null{
  const envelope=parseSyslogEnvelope(raw);
  if(!envelope||!envelope.variant.startsWith('rfc3164')||!envelope.month||!envelope.day||
     envelope.day.length!==1)return null;
  const pattern=new RegExp('^((?:<\\d{1,3}>)?'+envelope.month+')( +)('+envelope.day+')( +)');
  const match=pattern.exec(raw);
  if(!match)return null;
  const spacing=match[2]==='  '?' ':'  ';
  return raw.replace(pattern,match[1]+spacing+match[3]+match[4]);
}

export function buildRobustnessVariants(
  events:readonly EventResult[],draft:ParserDraft,limit=12,
):RobustnessVariant[]{
  if((draft.guided?.eventBoundary??'single-line')!=='single-line'||limit<1)return [];
  const variants:RobustnessVariant[]=[];
  const add=(event:EventResult,label:string,source:string|null,
    transformation:RobustnessVariant['transformation'])=>{
    if(!source||source===event.raw||/[\r\n]/.test(source)||new TextEncoder().encode(source).byteLength>8192)return;
    variants.push({id:'event-'+event.line+'-'+transformation,eventLine:event.line,label,source,
      transformation,semantics:'SYNTAX_EQUIVALENT_REVIEW_ONLY'});
  };
  for(const event of events){
    if(variants.length>=limit)break;
    if(!event.matched||!event.extracted)continue;
    if(event.effectiveFormat==='json')add(event,'JSON key order',reverseJson(event.raw),'JSON_KEY_ORDER');
    if(event.effectiveFormat==='kv')add(event,'Key/value token order',reverseSimpleKv(event.raw),'KV_TOKEN_ORDER');
    add(event,'Equivalent CSV quoting',csvVariant(event),'CSV_SAFE_QUOTING');
    add(event,'RFC3164 one-digit day spacing',rfc3164Spacing(event.raw),'RFC3164_DAY_SPACING');
  }
  return variants.slice(0,limit);
}

export function compareRobustnessOutcome(
  variant:RobustnessVariant,original:EventResult,mutated:EventResult|undefined,
):RobustnessOutcome{
  if(!mutated||!mutated.matched||!mutated.extracted||!mutated.normalizedOk)
    return {id:variant.id,eventLine:variant.eventLine,label:variant.label,
      passed:false,reason:'PARSER_REJECTED'};
  const before=JSON.stringify(stableWithoutRaw(original.normalized));
  const after=JSON.stringify(stableWithoutRaw(mutated.normalized));
  return {id:variant.id,eventLine:variant.eventLine,label:variant.label,
    passed:before===after,reason:before===after?'SAME_NORMALIZED_OUTPUT':'OUTPUT_CHANGED'};
}
