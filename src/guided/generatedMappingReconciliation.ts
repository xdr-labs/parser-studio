import type {MappingRule,ParserDraft,SuiteResult} from '../model';
import {suggestNormalizationCandidatesFromSuite} from './normalizationCandidates';
import {compactLegacyAutoVendorMappings} from './vendorFieldNames';

const AUTO=/^auto-(?:generic-)?\d+$/;
const overlaps=(a:string,b:string)=>a===b||a.startsWith(b+'.')||b.startsWith(a+'.');
function originalGeneratedTarget(mapping:MappingRule):boolean{
  const leaf=mapping.source.split('.').at(-1);
  return [mapping.source,mapping.source.replace(/\./g,'_'),leaf].includes(mapping.target);
}
function generatedConditional(m:MappingRule,source:string,target:string):boolean{
  if(m.id!=='auto-semantic-'+target||m.source!==source||m.target!==target||
    m.when?.operator!=='in')return false;
  const prefix=source.includes('.')?source.slice(0,source.lastIndexOf('.')+1):'';
  return m.when.sourcePath===prefix+'protocol-id'&&
    JSON.stringify(m.when.values)===JSON.stringify(['6','17']);
}

/** Re-run one catalog-backed semantic decision for untouched generated fields.
 * Used at the boundary between the automatic authoring engine and Map Fields.
 * Preserves the owner's manual mappings, destination collisions, and source
 * evidence. No manufacturer or field-name-specific mapping rule lives here.
 */
export function reconcileGeneratedMappings(draft:ParserDraft,suite:SuiteResult|undefined):ParserDraft{
  const names=compactLegacyAutoVendorMappings(draft.mappings,draft.guided?.groups??{});
  const renamed=names===draft.mappings?draft:{...draft,mappings:names};
  if(!suite?.events.length||!renamed.guided)return renamed;
  const choices=suggestNormalizationCandidatesFromSuite(suite,[],{})
    .filter(c=>c.safeForBulk&&c.confidence==='HIGH'&&!c.when);
  if(!choices.length)return renamed;
  let mappings=[...renamed.mappings];
  const groups={...renamed.guided.groups};
  let upgraded=false;
  for(const candidate of choices){
    const generated=mappings.filter(m=>m.source===candidate.source&&AUTO.test(m.id)&&
      groups[m.id]==='vendor_fields'&&!m.when&&originalGeneratedTarget(m));
    if(generated.length!==1)continue;
    const original=generated[0]!;
    const redundant=mappings.find(m=>generatedConditional(m,candidate.source,candidate.target)&&
      groups[m.id]===candidate.group);
    const collision=mappings.some(m=>m.id!==original.id&&m.id!==redundant?.id&&
      overlaps(m.target,candidate.target));
    if(collision)continue;
    mappings=mappings.filter(m=>m.id!==redundant?.id).map(m=>m.id===original.id
      ?{...m,target:candidate.target,type:candidate.type}:m);
    if(redundant)delete groups[redundant.id];
    groups[original.id]=candidate.group;
    upgraded=true;
  }
  return upgraded?{...renamed,mappings,guided:{...renamed.guided,groups}}:renamed;
}
