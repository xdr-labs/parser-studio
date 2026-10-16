import {splitSyslogStream} from './syslogFraming';
import {parseNdjsonObjectStream} from './ndjsonStream';
import {parseJsonTextSequence} from './jsonTextSequence';
import {parseGelfTcpStream} from './gelfTcp';
import {parseJsonObjectBatch} from './jsonBatch';
import {parseJournalTextExport} from './journalExport';
import {parseRfc4180HeaderCsv} from './rfc4180Csv';
import {parseZeekTsvBlock} from './zeekTabular';
import {parseW3cLogBlock} from './w3cTabular';
import {groupLinuxAuditStream} from './linuxAudit';
import {looksLikeDockerJsonLogStream,parseCriLogStream,parseDockerJsonLogStream} from './containerLogFraming';

export type SecurityEventBreakResult=
  |{ok:true;kind:'cri_log';count:number;payload:ReturnType<typeof parseCriLogStream> & {ok:true}}
  |{ok:true;kind:'docker_json_log';count:number;payload:ReturnType<typeof parseDockerJsonLogStream> & {ok:true}}
  |{ok:true;kind:'rfc6587_syslog';count:number;payload:ReturnType<typeof splitSyslogStream> & {ok:true}}
  |{ok:true;kind:'json_batch';count:number;payload:ReturnType<typeof parseJsonObjectBatch> & {ok:true}}
  |{ok:true;kind:'json_seq';count:number;payload:ReturnType<typeof parseJsonTextSequence> & {ok:true}}
  |{ok:true;kind:'gelf_tcp';count:number;payload:ReturnType<typeof parseGelfTcpStream> & {ok:true}}
  |{ok:true;kind:'ndjson';count:number;payload:ReturnType<typeof parseNdjsonObjectStream> & {ok:true}}
  |{ok:true;kind:'journal_export_text';count:number;payload:ReturnType<typeof parseJournalTextExport> & {ok:true}}
  |{ok:true;kind:'zeek_tsv';count:number;payload:ReturnType<typeof parseZeekTsvBlock> & {ok:true}}
  |{ok:true;kind:'w3c_log';count:number;payload:ReturnType<typeof parseW3cLogBlock> & {ok:true}}
  |{ok:true;kind:'linux_audit';count:number;payload:ReturnType<typeof groupLinuxAuditStream> & {ok:true}}
  |{ok:true;kind:'rfc4180_csv';count:number;payload:ReturnType<typeof parseRfc4180HeaderCsv> & {ok:true}}
  |{ok:false;claimed:boolean;error:string};

const MAX_INPUT_BYTES=1024*1024;
function bytes(value:string):number{return new TextEncoder().encode(value).byteLength;}

function looksLikeJsonArrayContainer(raw:string):boolean{
  const trimmed=raw.trimStart();
  if(!trimmed.startsWith('['))return false;
  const rest=trimmed.slice(1).trimStart();
  if(!rest)return true;
  const first=rest[0]!;
  return ['{','[','"',']','-'].includes(first)||/[0-9]/.test(first)||
    rest.startsWith('true')||rest.startsWith('false')||rest.startsWith('null');
}

export function breakSecurityInput(raw:string):SecurityEventBreakResult{
  if(!raw||bytes(raw)>MAX_INPUT_BYTES)
    return {ok:false,claimed:true,error:'Input is empty, binary, or exceeds the event-breaker limit'};

  // Use strong container signatures first. A successful lower-level parser is
  // still required; signatures only select which bounded grammar may run.
  if(/^\d{4}-\d{2}-\d{2}T\S+ +(?:stdout|stderr) +[PF] +/.test(raw)){
    const cri=parseCriLogStream(raw);
    if(cri.ok)return {ok:true,kind:'cri_log',count:cri.events.length,payload:cri};
    return {ok:false,claimed:true,error:'Input resembles a Kubernetes CRI log stream but failed strict framing'};
  }

  if(looksLikeDockerJsonLogStream(raw)){
    const docker=parseDockerJsonLogStream(raw);
    if(docker.ok)return {ok:true,kind:'docker_json_log',count:docker.events.length,payload:docker};
    return {ok:false,claimed:true,error:'Input resembles a Docker json-file stream but failed strict framing'};
  }

  if(raw.trimStart().startsWith('{')&&raw.includes('\0')){
    const gelf=parseGelfTcpStream(raw);
    if(gelf.ok)return {ok:true,kind:'gelf_tcp',count:gelf.messages.length,payload:gelf};
    return {ok:false,claimed:true,error:'Input resembles a NUL-framed GELF TCP stream but failed strict validation'};
  }

  if(raw.charCodeAt(0)===0x1e){
    const sequence=parseJsonTextSequence(raw);
    if(sequence.ok)return {ok:true,kind:'json_seq',count:sequence.sequence.records.length,payload:sequence};
    return {ok:false,claimed:true,error:'Input resembles an RFC7464 JSON text sequence but failed strict validation'};
  }

  if(raw.trimStart().startsWith('{')||looksLikeJsonArrayContainer(raw)){
    const batch=parseJsonObjectBatch(raw);
    if(batch.ok)return {ok:true,kind:'json_batch',count:batch.batch.records.length,payload:batch};
    if(raw.endsWith('\n')){
      const ndjson=parseNdjsonObjectStream(raw);
      if(ndjson.ok)return {ok:true,kind:'ndjson',count:ndjson.stream.records.length,payload:ndjson};
    }
    const trimmed=raw.trimStart();
    if(trimmed.startsWith('[')||raw.includes('\n{'))
      return {ok:false,claimed:true,error:'Input resembles a multi-event JSON container but failed strict validation'};
  }

  if((raw.startsWith('#Version:')||raw.startsWith('#Software:')||raw.startsWith('#Fields:'))&&raw.includes('#Fields:')){
    const w3c=parseW3cLogBlock(raw);
    if(w3c.ok)return {ok:true,kind:'w3c_log',count:w3c.block.rows.length,payload:w3c};
    return {ok:false,claimed:true,error:'Input resembles a W3C log block but failed strict validation'};
  }

  if(raw.startsWith('#separator')||raw.includes('\n#fields\t')){
    const zeek=parseZeekTsvBlock(raw);
    if(zeek.ok)return {ok:true,kind:'zeek_tsv',count:zeek.block.rows.length,payload:zeek};
    return {ok:false,claimed:true,error:'Input resembles a Zeek TSV block but failed strict validation'};
  }

  if(raw.includes('\n')&&/^(?:node=[^ ]+ +)?type=[A-Z0-9_]+ +msg=audit\(/.test(raw)){
    const audit=groupLinuxAuditStream(raw);
    if(audit.ok)return {ok:true,kind:'linux_audit',count:audit.events.length,payload:audit};
    return {ok:false,claimed:true,error:'Input resembles a Linux Audit stream but failed strict validation'};
  }

  if(/^(?:__|_[A-Z]|[A-Z][A-Z0-9_]*=)/.test(raw)&&raw.includes('\n\n')){
    const journal=parseJournalTextExport(raw);
    if(journal.ok)return {ok:true,kind:'journal_export_text',count:journal.entries.length,payload:journal};
    return {ok:false,claimed:true,error:'Input resembles a systemd journal export but failed strict validation'};
  }

  if(/^[1-9]\d* +<\d{1,3}>/.test(raw)||
     (/^<\d{1,3}>/.test(raw)&&(raw.includes('\n<')||raw.includes('\0<')))){
    const syslog=splitSyslogStream(raw);
    if(syslog.ok)return {ok:true,kind:'rfc6587_syslog',count:syslog.records.length,payload:syslog};
    return {ok:false,claimed:true,error:'Input resembles a multi-record Syslog stream but failed strict framing'};
  }

  // NDJSON does not have a unique magic marker beyond one-object-per-line.
  // Try it only for multi-line object-shaped input after stronger signatures.
  if(/^\s*\{/.test(raw)&&raw.includes('\n{')){
    const ndjson=parseNdjsonObjectStream(raw);
    if(ndjson.ok)return {ok:true,kind:'ndjson',count:ndjson.stream.records.length,payload:ndjson};
  }

  if(raw.includes(',')&&/[\r\n]/.test(raw)){
    const csv=parseRfc4180HeaderCsv(raw);
    if(csv.ok)return {ok:true,kind:'rfc4180_csv',count:csv.table.rows.length,payload:csv};
  }

  return {ok:false,claimed:false,error:'Input does not match a bounded multi-event container grammar'};
}
