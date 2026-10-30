/** Plain-language notices for ChatGPT replies that cannot be used as a parser recipe. */

export const COPY_DAMAGE_HINT=
  'The text may have been damaged while copying. In ChatGPT, use the code block\'s copy button instead of selecting the text, then paste it again.';

const MAX_REASON_CHARS=600;

export function describeNonJsonReply(text:string):{diagnostic:'REVIEW_REQUIRED'|'NOT_JSON';notice:string}{
  const trimmed=text.trim();
  if(!trimmed.startsWith('REVIEW_REQUIRED:'))return {
    diagnostic:'NOT_JSON',
    notice:'ChatGPT returned a diagnosis, not a parser recipe. No rules were applied. Review the source and use a guided retry only if the original log is valid.',
  };
  const reason=trimmed.slice('REVIEW_REQUIRED:'.length).trim();
  const shown=reason.length>MAX_REASON_CHARS?reason.slice(0,MAX_REASON_CHARS).trimEnd()+'…':reason;
  return {
    diagnostic:'REVIEW_REQUIRED',
    notice:'ChatGPT returned a diagnosis, not a parser recipe. ChatGPT said: '+(shown||'(no reason given)')+
      ' No rules were applied. If the reason points at your logs, fix them and prepare a new prompt.',
  };
}

/** Plain-language meaning of a rejected reply. The code stays visible in brackets for support. */
const REJECTED_REASON_TEXT:Record<string,string>={
  SOURCE_IDENTITY_MISMATCH:'This answer was written for different log lines or a different prompt. Copy the current prompt again, paste it into a new ChatGPT message, and paste the new answer here',
  INVALID_JSON:'The answer is not valid JSON',
  UNTRUSTED_RECIPE:'The answer does not follow the Parser Studio recipe format',
  FORMAT_MISMATCH:'The answer was made for a different log format than the one in your sample',
  UNSUPPORTED_OPERATION:'The answer uses a parsing step Parser Studio does not support',
  PROJECT_UNSUPPORTED:'This kind of parser cannot be changed with ChatGPT yet',
  CURRENT_RECIPE_UNAVAILABLE:'Parser Studio has no current parser to compare this answer with',
  INPUT_TOO_LARGE:'The answer is too large to check',
  SOURCE_LIMIT:'The sample is larger than Parser Studio can check in one step',
  UNTRUSTED_PREVIEW:'The preview this answer is based on could not be trusted',
  RECIPE_UNSUPPORTED:'The answer cannot be turned into a parser that Parser Studio can build',
};

export function describeRejectedReason(reason:string):string{
  const plain=REJECTED_REASON_TEXT[reason];
  return plain?plain+' ('+reason+')':reason;
}

export function describeRejectedReply(reason:string):string{
  const base='ChatGPT result rejected: '+describeRejectedReason(reason)+'. No parser rules changed.';
  return reason==='INVALID_JSON'?base+' '+COPY_DAMAGE_HINT:base;
}

const FAILED_CHECK_TEXT:Record<string,string>={
  NON_JSON_RESPONSE:'ChatGPT did not return a parser recipe',
  SCHEMA_REJECTED:'the recipe format was not accepted',
  SOURCE_IDENTITY_MISMATCH:'the answer does not match your log lines or this prompt',
  RECIPE_UNSUPPORTED:'the recipe cannot be built by Parser Studio',
  SAMPLE_REGRESSION:'the recipe broke values that were parsed correctly before',
  SYNTHETIC_VALUE_FAILURE:'the recipe only works for the exact values in your sample',
  HOLDOUT_REGRESSION:'the recipe failed on the different examples you supplied',
  NATIVE_VALIDATION_FAILED:'the generated parser failed a build check',
};

/** Plain wording for the "failed check" line above the improved-prompt button. */
export function describeFailedCheck(failure:string):string{
  const plain=FAILED_CHECK_TEXT[failure];
  return plain?plain+' ('+failure+')':failure;
}
