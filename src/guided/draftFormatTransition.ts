import type {ParserDraft} from '../model';

/** An explicit format choice retires metadata belonging to the previous grammar. */
export function selectDraftFormat(draft:ParserDraft,format:ParserDraft['format']):ParserDraft{
  const selected={...draft,format};
  if(format!=='generic_structural'){delete selected.genericStructuralProfile;delete selected.omitSourceRaw;}
  return selected;
}
