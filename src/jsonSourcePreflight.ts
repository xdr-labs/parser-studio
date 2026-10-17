import {inspectSourceCompleteness} from './standardSourceCompletenessGate';

/**
 * Lossless JSON lexical eligibility before any JSON.parse that would drop
 * duplicate names, nonrepresentable numbers or isolated Unicode surrogates.
 * A lexically valid JSON event is NOT native/producer certified by this gate.
 */
export function jsonSourcePreflightError(raw:string,maxBytes=65536):string|null{
  const audit=inspectSourceCompleteness(raw,'json',{maxBytes});
  if(audit.disposition==='REVIEW_ONLY_LEXICAL')return null;
  const kind=audit.disposition==='REVIEW_ONLY_UNCERTAIN'?
    'JSON source requires review':'JSON source syntax is not qualified';
  return kind+': '+audit.issues.join(', ');
}
