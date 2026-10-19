import type {ParserDraft,SuiteResult} from '../model';
import {convertValue} from '../parser';
import {lookupFieldValue} from '../fieldPaths';
import {inspectEventProfile} from './multiEventRouting';

export type ReviewedEventValueEvidence=
  | {ok:true;skipped:number}
  | {ok:false;reason:string};

/**
 * Preview every supplied event for the explicitly selected family and type.
 * This is a conservative local warning, never native or target certification.
 * Missing and declared ignored values are deliberately omitted, not invented.
 */
export function inspectReviewedEventValues(
  suite:SuiteResult|undefined,draft:ParserDraft,
):ReviewedEventValueEvidence{
  if(!suite||!suite.events.length||!draft.eventProfiles)
    return {ok:false,reason:'Review source events and explicit type rules first.'};
  let skipped=0;
  const ignored=new Set(['','N/A','-']);
  for(const event of suite.events){
    if(!event.extracted)return {ok:false,reason:
      'Some source events remain unparsed. Review them before approving event types.'};
    const selected=inspectEventProfile(event.fields,draft.eventProfiles);
    if(!selected.profile)return {ok:false,reason:
      'A source event does not match the selected explicit event type rules.'};
    for(const mapping of selected.profile.mappings){
      const found=lookupFieldValue(event.fields,mapping.source);
      if(!found.found||found.value===null||found.value===undefined||
        ignored.has(String(found.value))){
        skipped++;
        continue;
      }
      if(mapping.type==='string')continue;
      const converted=convertValue(found.value,mapping.type);
      if(converted.error)return {ok:false,reason:
        'Event type '+selected.name+': field '+mapping.source+
        ' cannot be interpreted as '+mapping.type+
        ' in the provided examples. Change the output type or review the source.'};
    }
  }
  return {ok:true,skipped};
}
