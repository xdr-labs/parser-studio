import type {ParserDraft} from '../model';

/** An explicit format choice retires metadata belonging to the previous grammar. */
export function selectDraftFormat(draft:ParserDraft,format:ParserDraft['format']):ParserDraft{
  const selected={...draft,format};
  if(format!=='generic_structural'){
    delete selected.genericStructuralProfile;delete selected.omitSourceRaw;delete selected.genericStructuralFamilyGrammar;
  }else if(draft.format!=='generic_structural'){
    // A newly selected Generic Structural parser reads CEF/LEEF with the dedicated grammar (owner policy D-2).
    selected.genericStructuralFamilyGrammar='dedicated';
  }
  return selected;
}
