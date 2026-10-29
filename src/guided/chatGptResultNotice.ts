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
    notice:'ChatGPT did not return a parser recipe. It asked for a review first: '+(shown||'(no reason given)')+
      ' No rules were applied. If the reason points at your logs, fix them and prepare a new prompt.',
  };
}

export function describeRejectedReply(reason:string):string{
  const base='ChatGPT result rejected: '+reason+'. No parser rules changed.';
  return reason==='INVALID_JSON'?base+' '+COPY_DAMAGE_HINT:base;
}
