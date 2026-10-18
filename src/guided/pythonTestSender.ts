import template from './pythonTestSenderTemplate.py?raw';
import {MAX_DATASET_BYTES,MAX_EVENTS,splitEvents} from '../parser';
import type {ParserDraft} from '../model';
import type {EventBoundary} from './contract';

export interface PythonSenderPrepared{
  script:string;
  filename:string;
  eventCount:number;
  warnings:string[];
}
const allowedFormats=new Set([
  'auto','json','kv','csv','cef','leef','mixed','syslog_rfc3164',
  'syslog_rfc5424','syslog','generic_structural','regex','java_stacktrace',
]);
function encodeBase64(text:string):string{
  const bytes=new TextEncoder().encode(text);
  // Avoid spread arguments on a 64 KiB log; some JS engines cap arg lists.
  let binary='';
  for(let i=0;i<bytes.length;i+=8192){
    binary+=String.fromCharCode(...bytes.subarray(i,i+8192));
  }
  return btoa(binary);
}
export function preparePythonTestSender(
  source:string,
  draft:ParserDraft,
):PythonSenderPrepared{
  if(typeof source!=='string'||!source.trim()||
     new TextEncoder().encode(source).length>MAX_DATASET_BYTES)
    throw new Error('Enter sample logs of at most 64 KiB before generating a test sender.');
  const boundary:EventBoundary=draft.guided?.eventBoundary??'single-line';
  if(!['single-line','blank-line'].includes(boundary))
    throw new Error('Choose a supported event boundary before generating a sender.');
  if(!allowedFormats.has(draft.format))
    throw new Error('Unsupported source format for synthetic log sending.');
  const records=splitEvents(source,boundary,MAX_EVENTS+1);
  if(records.length<1||records.length>MAX_EVENTS||
     records.some(record=>!record.raw.trim()))
    throw new Error('The source must contain between 1 and 500 nonempty events.');
  const csvColumns=draft.csvColumns.split(',').map(s=>s.trim()).filter(Boolean);
  const validCsvColumns=csvColumns.length>=2&&csvColumns.length<=100&&
    csvColumns.every(name=>/^[A-Za-z_][A-Za-z0-9_]{0,63}$/.test(name))&&
    new Set(csvColumns.map(name=>name.toLowerCase())).size===csvColumns.length;
  if(draft.format==='csv'&&!validCsvColumns)
    throw new Error('Review valid CSV column names before generating a CSV test sender.');
  const delimiter=draft.csvDelimiter??',';
  if(![',',';','\t'].includes(delimiter))
    throw new Error('CSV delimiters must be comma, semicolon or TAB.');
  const config={
    events:records.map(record=>record.raw),
    format:draft.format,
    csv_columns:validCsvColumns?csvColumns:[],
    csv_delimiter:delimiter,
    event_boundary:boundary,
  };
  const b64=encodeBase64(JSON.stringify(config));
  const marker='__PARSER_STUDIO_CONFIG_B64__';
  if(template.split(marker).length!==2)
    throw new Error('Bundled Python generator template is not trustworthy.');
  const script=template.replace(marker,b64);
  const warnings=[
    'The downloaded .py file embeds the entire original log sample in base64, which is NOT encryption. Review or redact sensitive information before sharing the file.',
    'The script prompts for the destination IP, port, protocol, event count and explicit YES approval when you execute it. Parser Studio never sends test logs to a sensor.',
    'Recognized timestamps, addresses, email, user and location fields are regenerated where safely possible. Unknown formats and ambiguous values remain unchanged; generated data is not guaranteed anonymous.',
    'Simple UDP datagrams and LF-framed TCP are supported; destination ingest, vendor-specific TCP octet-counting and parser accuracy are NOT VERIFIED.',
  ];
  if(draft.format==='auto'||draft.format==='mixed')
    warnings.push('Mixed and unknown records use conservative per-record detection. Review the generated data with your target parser.');
  if(boundary==='blank-line')
    warnings.push('Blank-line records are sent as one UDP datagram or TCP LF LF separated records.');
  if(draft.format==='csv'&&!validCsvColumns)
    throw new Error('CSV column names are required for safe positional mutation.');
  return {script,filename:'parser_studio_test_sender.py',
    eventCount:records.length,warnings};
}
