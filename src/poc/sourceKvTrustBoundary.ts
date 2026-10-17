/** Isolated PoC trust boundary. Never grants semantic, native, or product approval. */
import {createHash} from 'node:crypto';
import type {SecurityPipelineResult} from '../securityInputPipeline';
import {scoreKvFields,type KvFieldScore} from './syslogKvFieldFidelity';

export type SourceKvQualification=
  'SOURCE_FIELD_EXACT'|'SOURCE_FIELD_MISMATCH'|'SOURCE_UNSCORABLE'|
  'ORACLE_SOURCE_DRIFT'|'PARSER_NOT_SINGLE_EVENT'|'RAW_NOT_PRESERVED';

export type SourceKvVerdict={
  qualification:SourceKvQualification;
  structurallyAccepted:boolean;
  independentSourceFields:number;
  score:KvFieldScore|null;
  semanticMapping:'NOT_SCORED';
  nativeParser:'NOT_VERIFIED';
  productApproval:false;
};

type Evaluation={
  raw:string;
  result:SecurityPipelineResult;
  // Null means independently unscorable, even if the parser reports ok:true.
  expected:ReadonlyMap<string,string>|null;
  sourceSha256:string|null;
  fixedContract:'fortinet.fields'|'generic.kv';
};
const sha=(value:string)=>createHash('sha256').update(value).digest('hex');

export function evaluateSourceKvTrust(input:Evaluation):SourceKvVerdict{
  const structurallyAccepted=input.result.ok;
  const decision=(qualification:SourceKvQualification,score:KvFieldScore|null=null):SourceKvVerdict=>({
    qualification,structurallyAccepted,
    independentSourceFields:input.expected?.size??0,score,
    semanticMapping:'NOT_SCORED',nativeParser:'NOT_VERIFIED',productApproval:false,
  });
  if(!input.expected)return decision('SOURCE_UNSCORABLE');
  if(!input.sourceSha256||!/^[a-f0-9]{64}$/.test(input.sourceSha256)||
     sha(input.raw)!==input.sourceSha256)return decision('ORACLE_SOURCE_DRIFT');
  if(!input.result.ok||input.result.events.length!==1)
    return decision('PARSER_NOT_SINGLE_EVENT',
      scoreKvFields(input.expected,null));
  const event=input.result.events[0]!;
  const vendor=event.fields?.fortinet as Record<string,unknown>|undefined;
  const generic=event.fields?.generic as Record<string,unknown>|undefined;
  const candidate=input.fixedContract==='fortinet.fields'?vendor?.fields:generic?.kv;
  const score=scoreKvFields(input.expected,candidate);
  if(input.result.source_raw!==input.raw||event.raw!==input.raw)
    return decision('RAW_NOT_PRESERVED',score);
  return decision(score.exactEvent?'SOURCE_FIELD_EXACT':'SOURCE_FIELD_MISMATCH',score);
}
