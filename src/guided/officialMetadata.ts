import type { FieldType, ParserDraft } from '../model';
import { defaultGuidedOptions } from './contract';

/**
 * Small factual reference subset present in Stellar Cyber's public *6.5/7.0* Standard
 * Metadata Dictionary. Not an import schema, compatibility certification,
 * or promise that older/target DP versions implement the same fields.
 *
 * Only scalar metadata with a reviewed local backend cast is included.
 */
export const officialDictionaryUrl = 'https://docs.stellarcyber.ai/7.0.xs/Common/Metadata-Dictionary.htm';
export const officialDictionaryUrl65 = 'https://docs.stellarcyber.ai/6.5.xs/Common/Metadata-Dictionary.htm';
export interface OfficialMetadataField {
  name: string;
  documentedType: 'string' | 'integer' | 'ip';
  uiType: Extract<FieldType, 'string' | 'integer' | 'ip' | 'port'>;
  label: string;
}
export const curatedOfficialMetadata: readonly OfficialMetadataField[] = [
  {name:'srcip',documentedType:'ip',uiType:'ip',label:'출발지 IP'},
  {name:'dstip',documentedType:'ip',uiType:'ip',label:'목적지 IP'},
  {name:'srcport',documentedType:'integer',uiType:'port',label:'출발지 포트'},
  {name:'dstport',documentedType:'integer',uiType:'port',label:'목적지 포트'},
  {name:'action',documentedType:'string',uiType:'string',label:'허용·차단 등 동작'},
  {name:'event_name',documentedType:'string',uiType:'string',label:'이벤트 이름 (탐지 Job)'},
  {name:'event_description',documentedType:'string',uiType:'string',label:'이벤트 설명'},
  {name:'severity',documentedType:'integer',uiType:'integer',label:'이벤트 심각도'},
  {name:'proto_name',documentedType:'string',uiType:'string',label:'네트워크 프로토콜 이름'},
  {name:'hostname',documentedType:'string',uiType:'string',label:'호스트 이름 (Linux Audit)'},
  {name:'hostip',documentedType:'ip',uiType:'ip',label:'호스트 IP'},
  {name:'username',documentedType:'string',uiType:'string',label:'사용자 이름'},
  {name:'login_result',documentedType:'string',uiType:'string',label:'로그인 결과'},
  {name:'file_name',documentedType:'string',uiType:'string',label:'파일 이름'},
  {name:'file_path',documentedType:'string',uiType:'string',label:'파일 경로'},
  {name:'process_name',documentedType:'string',uiType:'string',label:'프로세스 이름 (에이전트)'},
  {name:'sha256',documentedType:'string',uiType:'string',label:'파일 SHA-256'},
  {name:'url',documentedType:'string',uiType:'string',label:'URL'},
  {name:'file_size',documentedType:'integer',uiType:'integer',label:'파일 크기'},
] as const;

export type OfficialMetadataSelection =
  | {ok:true;draft:ParserDraft}
  | {ok:false;error:string};

function overlaps(a:string,b:string):boolean {
  return a===b || a.startsWith(b+'.') || b.startsWith(a+'.');
}

/** Explicit user selection only; never silently relabel a parsed source or
 * copy customer sample bytes. Preserves all other rules and groups. */
export function applyOfficialMetadataField(
  draft: ParserDraft, mappingId: string, metadataName: string,
): OfficialMetadataSelection {
  const field = curatedOfficialMetadata.find(x => x.name === metadataName);
  if (!field) return {ok:false,error:'선택한 필드는 검토된 6.5/7.0 표준 메타데이터 후보가 아닙니다.'};
  const mapping = draft.mappings.find(x => x.id === mappingId);
  if (!mapping) return {ok:false,error:'선택할 매핑 규칙을 찾지 못했습니다.'};
  if (!mapping.source.trim()) return {ok:false,error:'먼저 원본 필드를 선택해야 표준 목적지를 연결할 수 있습니다.'};
  if (draft.mappings.some(other => other.id !== mappingId && overlaps(other.target, field.name))) {
    return {ok:false,error:'선택한 표준 필드가 기존 정규화 목적지와 충돌합니다.'};
  }
  const options = draft.guided ?? defaultGuidedOptions();
  return {
    ok:true,
    draft: {
      ...draft,
      mappings: draft.mappings.map(x => x.id === mappingId
        ? {...x,target:field.name,type:field.uiType} : x),
      guided: {...options,groups:{...options.groups,[mappingId]:'top_fields'}},
    },
  };
}
