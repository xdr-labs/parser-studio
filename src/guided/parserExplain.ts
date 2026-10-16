import type {EventResult,ParserDraft} from '../model';
import {listSafeLeafPaths,lookupFieldValue} from '../fieldPaths';

export interface ParserExplainStep{
  id:'boundary'|'envelope'|'format'|'extraction'|'mapping'|'compatibility';
  status:'PASS'|'REVIEW'|'INFO';
  title:string;
  summary:string;
  details:string[];
}

export interface ParserExplainReport{
  steps:ParserExplainStep[];
  parsedLeafCount:number;
  mappingSourceCount:number;
}

function objectValue(value:unknown):Record<string,unknown>|null{
  return value&&typeof value==='object'&&!Array.isArray(value)
    ?value as Record<string,unknown>:null;
}
function display(value:unknown):string{
  if(value===undefined||value===null||value==='')return '';
  return String(value);
}
function headerDetails(syslog:Record<string,unknown>):string[]{
  const out:string[]=[];
  if(display(syslog.pri))out.push('PRI: '+display(syslog.pri));
  if(display(syslog.hostname))out.push('Host: '+display(syslog.hostname));
  const date=[display(syslog.month),display(syslog.day),display(syslog.year)]
    .filter(Boolean).join(' ');
  const clock=display(syslog.time)||display(syslog.timestamp);
  if(date||clock)out.push('Time: '+[date,clock].filter(Boolean).join(' '));
  if(display(syslog.appname))out.push('Application: '+display(syslog.appname));
  if(display(syslog.app_tag))out.push('Tag: '+display(syslog.app_tag));
  return out.slice(0,6);
}
function formatDescription(fields:Record<string,unknown>,multiPassSyntax?:string){
  const generic=objectValue(fields.generic);
  const mode=display(generic?.mode);
  const details:string[]=[];
  if(multiPassSyntax?.trim())details.push('Engine path: '+multiPassSyntax.trim());
  if(mode==='panos_traffic_csv'){
    const named=objectValue(generic?.fields)??{};
    const extras=Object.keys(named).filter(key=>/^vendor_extra_\d+$/.test(key)).length;
    const known=Object.keys(named).length-extras;
    details.push(known+' reviewed ordered field'+(known===1?'':'s')+' named');
    if(extras)details.push(extras+' later vendor field'+(extras===1?'':'s')+
      ' preserved without shifting known columns');
    return {
      title:'Palo Alto Networks PAN-OS TRAFFIC ordered CSV',
      summary:'Reviewed PAN-OS TRAFFIC anchors matched before semantic field names were assigned.',
      details,
    };
  }
  if(objectValue(fields.asa)){
    const asa=objectValue(fields.asa)!;
    if(display(asa.message_id))details.push('Message ID: '+display(asa.message_id));
    return {
      title:'Cisco ASA / FTD security message',
      summary:'A bounded ASA / FTD message grammar matched the event body.',
      details,
    };
  }
  const labels:Record<string,string>={
    rfc3164_positional_csv:'Positional security CSV',
    syslog_envelope_positional_csv:'Syslog positional CSV',
    syslog_envelope_json:'Syslog JSON',
    syslog_envelope_cef:'Syslog CEF',
    syslog_envelope_leef:'Syslog LEEF',
    syslog_envelope_bracket_colon_kv:'Syslog structured key/value',
    comma_kv:'Comma-delimited key/value',
    space_kv:'Space-delimited key/value',
    delimited_kv:'Delimited key/value',
    prefixed_json:'Prefixed JSON',
  };
  if(mode)details.push('Parser mode: '+mode);
  return {
    title:labels[mode]??(Object.keys(fields).length?'Bounded structured message':'Unresolved message format'),
    summary:Object.keys(fields).length
      ?'A bounded parser path produced structured source fields.'
      :'No bounded parser path produced source fields for this event.',
    details,
  };
}

export function buildParserExplain(
  event:EventResult|undefined,draft:ParserDraft,multiPassSyntax?:string,
):ParserExplainReport{
  if(!event)return {steps:[],parsedLeafCount:0,mappingSourceCount:0};
  const fields=event.fields??{};
  const leaves=listSafeLeafPaths(fields)
    .filter(path=>!/(?:^|\.)(?:source_raw|message_raw)$/.test(path));
  const steps:ParserExplainStep[]=[];
  const boundary=event.trace.find(step=>step.stage==='Event boundary');
  steps.push({
    id:'boundary',status:boundary?.ok===false?'REVIEW':'PASS',
    title:'Event boundary',
    summary:boundary?.detail??'Parser Studio treated this source record as one logical event.',
    details:[],
  });

  const syslog=objectValue(fields.syslog);
  steps.push(syslog?{
    id:'envelope',status:'PASS',title:'Syslog envelope',
    summary:'Syslog envelope fields were separated before the message body.',
    details:headerDetails(syslog),
  }:{
    id:'envelope',status:'INFO',title:'Syslog envelope',
    summary:'No separate Syslog envelope was required for this event.',
    details:[],
  });

  const format=formatDescription(fields,multiPassSyntax);
  steps.push({
    id:'format',status:Object.keys(fields).length?'PASS':'REVIEW',
    title:'Message format',
    summary:format.title+' · '+format.summary,
    details:format.details,
  });

  steps.push({
    id:'extraction',status:event.extracted?'PASS':'REVIEW',
    title:'Source extraction',
    summary:event.extracted
      ?String(leaves.length)+' source leaf field'+(leaves.length===1?'':'s')+' extracted; source values preserved for review and mapping.'
      :'No trusted source fields were emitted for this event.',
    details:[],
  });

  const mappingSourceCount=draft.mappings.filter(mapping=>
    lookupFieldValue(fields,mapping.source.trim()).found).length;
  steps.push({
    id:'mapping',
    status:draft.mappings.length&&mappingSourceCount===draft.mappings.length?'PASS':'REVIEW',
    title:'Destination mapping',
    summary:draft.mappings.length
      ?String(mappingSourceCount)+' of '+String(draft.mappings.length)+' current mapping source'+(draft.mappings.length===1?'':'s')+' exist in this event.'
      :'No destination mapping has been reviewed yet.',
    details:draft.mappings.slice(0,8).map(mapping=>
      mapping.source+' → '+mapping.target+(mapping.type==='string'?'':' · '+mapping.type)),
  });

  steps.push({
    id:'compatibility',status:'INFO',
    title:'Verification scope',
    summary:'Native Fluentd and Stellar target import verification remain separate evidence gates.',
    details:['This explanation describes the current local Parser Studio result only.'],
  });

  return {steps,parsedLeafCount:leaves.length,mappingSourceCount};
}
