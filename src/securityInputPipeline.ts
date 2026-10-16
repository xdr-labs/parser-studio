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
  kind:'single_event'|'line_event_stream'|Exclude<SecurityEventBreakResult extends infer R ? R extends {ok:true;kind:infer K}?K:never:never,never>;
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

function lineEventStream(raw:string):SecurityPipelineResult|null{
  if(!/[\r\n]/.test(raw))return null;
  const hasCrlf=raw.includes('\r\n');
  const withoutCrlf=raw.replace(/\r\n/g,'');
  if(withoutCrlf.includes('\r'))
    return {ok:false,error:'Line event stream contains an unsupported carriage return'};
  if(hasCrlf&&withoutCrlf.includes('\n'))
    return {ok:false,error:'Line event stream mixes LF and CRLF boundaries'};
  const normalized=hasCrlf?raw.replace(/\r\n/g,'\n'):raw;
  const body=normalized.endsWith('\n')?normalized.slice(0,-1):normalized;
  const lines=body.split('\n');
  if(lines.length<2)return null;
  if(lines.length>1000)return {ok:false,error:'Line event stream exceeds the event limit'};
  if(lines.some(line=>line.length===0))
    return {ok:false,error:'Line event stream contains an empty event boundary'};
  const events:SecurityPipelineEvent[]=[];
  for(let index=0;index<lines.length;index++){
    const line=lines[index]!;
    if(new TextEncoder().encode(line).byteLength>64*1024)
      return {ok:false,error:'Line event exceeds the parser limit'};
    const event=genericEvent(index,line);
    if(!event)
      return {ok:false,error:'Line '+String(index+1)+' failed reviewed single-event parsing'};
    events.push(event);
  }
  return {
    ok:true,kind:'line_event_stream',container:true,source_raw:raw,events,
    context:{framing:hasCrlf?'crlf':'lf'},
  };
}

export function parseSecurityInput(raw:string):SecurityPipelineResult{
  if(raw.startsWith('\uFEFF')){
    if(raw.startsWith('\uFEFF\uFEFF'))
      return {ok:false,error:'Input contains more than one UTF-8 BOM preamble'};
    const parsed=parseSecurityInput(raw.slice(1));
    if(!parsed.ok)return parsed;
    return {
      ...parsed,
      source_raw:raw,
      context:{...(parsed.context??{}),utf8_bom:true},
    };
  }
  const broken=breakSecurityInput(raw);
  if(!broken.ok){
    if(broken.claimed)return {ok:false,error:broken.error};
    const lines=lineEventStream(raw);
    if(lines)return lines;
    const single=genericEvent(0,raw);
    return single?{ok:true,kind:'single_event',container:false,source_raw:raw,events:[single]}:
      {ok:false,error:'Input did not match a bounded container or single-event grammar'};
  }

  switch(broken.kind){
    case 'cri_log': {
      const events=broken.payload.events.map((entry,index)=>{
        const nested=extractSingleEvent(entry.content);
        const fields:Record<string,unknown>={
          cri:{
            stream:entry.stream,first_timestamp:entry.first_timestamp,last_timestamp:entry.last_timestamp,
            fragments:entry.fragments,raw_lines:entry.raw_lines,
          },
          generic:{mode:'cri_log_event',source_index:index},
        };
        if(!nested.errors.length)fields.message_structured=nested.fields;
        else fields.message=entry.content;
        return {index,raw:entry.raw_lines.join('\n'),fields};
      });
      return {ok:true,kind:broken.kind,container:true,source_raw:raw,events};
    }
    case 'docker_json_log': {
      const events=broken.payload.events.map((entry,index)=>{
        const nested=extractSingleEvent(entry.content);
        const fields:Record<string,unknown>={
          docker:{stream:entry.stream,time:entry.time,log:entry.log,extra:entry.extra},
          generic:{mode:'docker_json_log_event',source_index:index},
        };
        if(!nested.errors.length)fields.message_structured=nested.fields;
        else fields.message=entry.content;
        return {index,raw:entry.raw,fields};
      });
      return {ok:true,kind:broken.kind,container:true,source_raw:raw,events};
    }
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
