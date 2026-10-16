import {breakSecurityInput, type SecurityEventBreakResult} from './securityEventBreaker';
import {extractGenericStructural} from './genericStructural';
import {extractStructuredFamily} from './structuredFamilies';
import {parseJsonObjectBatch} from './jsonBatch';

export interface SecurityPipelineEvent{
  index:number;
  fields:Record<string,unknown>;
  raw?:string;
}

export interface SecurityPipelineSuccess{
  ok:true;
  kind:'single_event'|Exclude<SecurityEventBreakResult extends infer R ? R extends {ok:true;kind:infer K}?K:never:never,never>;
  container:boolean;
  source_raw:string;
  events:SecurityPipelineEvent[];
  context?:Record<string,unknown>;
}

export type SecurityPipelineResult=SecurityPipelineSuccess|{ok:false;error:string};

function extractSingleEvent(raw:string):{fields:Record<string,unknown>;errors:string[]}{
  const generic=extractGenericStructural(raw);
  if(!generic.errors.length)return generic;
  if(raw.startsWith('CEF:')){
    const parsed=extractStructuredFamily(raw,'cef');
    return parsed.errors.length?{fields:{},errors:parsed.errors}:{fields:parsed.fields,errors:[]};
  }
  if(raw.startsWith('LEEF:')){
    const parsed=extractStructuredFamily(raw,'leef');
    return parsed.errors.length?{fields:{},errors:parsed.errors}:{fields:parsed.fields,errors:[]};
  }
  if(raw.trimStart().startsWith('{')){
    const batch=parseJsonObjectBatch('['+raw+']');
    if(batch.ok&&batch.batch.records.length===1)
      return {fields:batch.batch.records[0]!,errors:[]};
    return {fields:{},errors:['Standalone JSON object failed bounded validation']};
  }
  return generic;
}

function genericEvent(index:number,raw:string):SecurityPipelineEvent|null{
  const parsed=extractSingleEvent(raw);
  return parsed.errors.length?null:{index,raw,fields:parsed.fields};
}

export function parseSecurityInput(raw:string):SecurityPipelineResult{
  const broken=breakSecurityInput(raw);
  if(!broken.ok){
    if(broken.claimed)return {ok:false,error:broken.error};
    const single=genericEvent(0,raw);
    return single?{ok:true,kind:'single_event',container:false,source_raw:raw,events:[single]}:
      {ok:false,error:'Input did not match a bounded container or single-event grammar'};
  }

  switch(broken.kind){
    case 'rfc6587_syslog': {
      const events:SecurityPipelineEvent[]=[];
      for(let index=0;index<broken.payload.records.length;index++){
        const event=genericEvent(index,broken.payload.records[index]!);
        if(!event)return {ok:false,error:'A framed Syslog record failed structural parsing'};
        events.push(event);
      }
      return {ok:true,kind:broken.kind,container:true,source_raw:raw,events,context:{framing:broken.payload.mode}};
    }
    case 'json_batch': {
      const events=broken.payload.batch.records.map((record,index)=>({
        index,fields:{body:record,generic:{mode:'json_batch_object',source_index:index}},
      }));
      return {ok:true,kind:broken.kind,container:true,source_raw:raw,events,
        ...(broken.payload.batch.container?{context:{container:broken.payload.batch.container}}:{})};
    }
    case 'json_seq': {
      const events=broken.payload.sequence.records.map((record,index)=>({
        index,raw:broken.payload.sequence.rawJsonTexts[index],
        fields:{body:record,generic:{mode:'json_text_sequence_object',source_raw:broken.payload.sequence.rawJsonTexts[index]}},
      }));
      return {ok:true,kind:broken.kind,container:true,source_raw:raw,events};
    }
    case 'gelf_tcp': {
      const events=broken.payload.messages.map((message,index)=>({
        index,raw:message.raw,fields:{gelf:message.fields,generic:{mode:'gelf_tcp',source_raw:message.raw}},
      }));
      return {ok:true,kind:broken.kind,container:true,source_raw:raw,events};
    }
    case 'ndjson': {
      const events=broken.payload.stream.records.map((record,index)=>({
        index,raw:broken.payload.stream.rawRecords[index],
        fields:{body:record,generic:{mode:'ndjson_object',source_raw:broken.payload.stream.rawRecords[index]}},
      }));
      return {ok:true,kind:broken.kind,container:true,source_raw:raw,events};
    }
    case 'journal_export_text': {
      const events=broken.payload.entries.map((entry,index)=>{
        const fields:Record<string,unknown>={
          journal:entry.fields,
          generic:{mode:'journal_export_text',source_raw:entry.raw},
        };
        const message=entry.fields.MESSAGE;
        if(typeof message==='string'){
          const nested=extractSingleEvent(message);
          if(!nested.errors.length)fields.message_structured=nested.fields;
        }
        return {index,raw:entry.raw,fields};
      });
      return {ok:true,kind:broken.kind,container:true,source_raw:raw,events};
    }
    case 'w3c_log': {
      const events=broken.payload.block.rows.map((row,index)=>({
        index,fields:{w3c:row,generic:{mode:'w3c_schema_row',source_index:index}},
      }));
      return {ok:true,kind:broken.kind,container:true,source_raw:raw,events,context:{
        schema:broken.payload.block.schema,directives:broken.payload.block.directives,
      }};
    }
    case 'zeek_tsv': {
      const events=broken.payload.block.rows.map((row,index)=>({
        index,fields:{zeek:row,generic:{mode:'zeek_schema_row',source_index:index}},
      }));
      return {ok:true,kind:broken.kind,container:true,source_raw:raw,events,context:{
        fields:broken.payload.block.fields,types:broken.payload.block.types,
        ...(broken.payload.block.path?{path:broken.payload.block.path}:{}),
      }};
    }
    case 'linux_audit': {
      const events=broken.payload.events.map((event,index)=>({
        index,fields:{linux_audit_event:event,generic:{mode:'linux_audit_event_group',source_index:index}},
      }));
      return {ok:true,kind:broken.kind,container:true,source_raw:raw,events};
    }
    case 'rfc4180_csv': {
      const events=broken.payload.table.rows.map((row,index)=>({
        index,fields:{csv:row,generic:{mode:'rfc4180_header_row',source_index:index}},
      }));
      return {ok:true,kind:broken.kind,container:true,source_raw:raw,events,context:{header:broken.payload.table.header}};
    }
  }
}
