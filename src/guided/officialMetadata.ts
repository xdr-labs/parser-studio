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
  {name:'srcip',documentedType:'ip',uiType:'ip',label:'Source IP'},
  {name:'dstip',documentedType:'ip',uiType:'ip',label:'Destination IP'},
  {name:'srcport',documentedType:'integer',uiType:'port',label:'Source Port'},
  {name:'dstport',documentedType:'integer',uiType:'port',label:'Destination Port'},
  {name:'action',documentedType:'string',uiType:'string',label:'Action (allow, deny, etc.)'},
  {name:'event_name',documentedType:'string',uiType:'string',label:'Event name (detection job)'},
  {name:'event_description',documentedType:'string',uiType:'string',label:'Event description'},
  {name:'severity',documentedType:'integer',uiType:'integer',label:'Event severity'},
  {name:'proto_name',documentedType:'string',uiType:'string',label:'Network protocol name'},
  {name:'hostname',documentedType:'string',uiType:'string',label:'Host name (Linux audit)'},
  {name:'hostip',documentedType:'ip',uiType:'ip',label:'Host IP'},
  {name:'username',documentedType:'string',uiType:'string',label:'Username'},
  {name:'login_result',documentedType:'string',uiType:'string',label:'Login outcome'},
  {name:'file_name',documentedType:'string',uiType:'string',label:'Filename'},
  {name:'file_path',documentedType:'string',uiType:'string',label:'File path'},
  {name:'process_name',documentedType:'string',uiType:'string',label:'Process name (endpoint)'},
  {name:'sha256',documentedType:'string',uiType:'string',label:'File SHA-256'},
  {name:'url',documentedType:'string',uiType:'string',label:'URL'},
  {name:'file_size',documentedType:'integer',uiType:'integer',label:'File size'},
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
  if (!field) return {ok:false,error:'Selected field is not a reviewed public 6.5/7.0 metadata candidate.'};
  const mapping = draft.mappings.find(x => x.id === mappingId);
  if (!mapping) return {ok:false,error:'Selected mapping rule was not found.'};
  if (!mapping.source.trim()) return {ok:false,error:'Select a source field before linking a standard destination.'};
  if (draft.mappings.some(other => other.id !== mappingId && overlaps(other.target, field.name))) {
    return {ok:false,error:'Selected standard field conflicts with an existing normalized destination.'};
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
