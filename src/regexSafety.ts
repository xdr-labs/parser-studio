/**
 * Conservative preview-only regular-expression linter. The separate Web Worker
 * still enforces an execution timeout, and this check is NOT a proof that all
 * accepted JS regexes have linear complexity or match native Ruby/Fluentd.
 */
/** Fail closed on quantified groups containing another repetition.
 * Length limits alone do not bound backtracking (for example (a{1,3})+).
 * The browser worker independently imposes a wall-clock deadline.
 */
function hasNestedQuantifiers(pattern:string):boolean {
  const stack:{repeated:boolean;alternative:boolean}[]=[];
  let characterClass=false;
  for(let i=0;i<pattern.length;i++){
    const char=pattern[i];
    if(char==='\\'){i++;continue;}
    if(char==='['&&!characterClass){characterClass=true;continue;}
    if(char===']'&&characterClass){characterClass=false;continue;}
    if(characterClass)continue;
    if(char==='('){
      stack.push({repeated:false,alternative:false});
      if(pattern.startsWith('(?:',i)){i+=2;continue;}
      if(pattern.startsWith('(?<',i)){
        const end=pattern.indexOf('>',i+3);
        if(end>=0){i=end;continue;}
      }
      continue;
    }
    if(char===')'){
      const frame=stack.pop();
      if(!frame)continue;
      const suffix=pattern.slice(i+1);
      const bound=/^\{(\d{1,8})(?:,(\d{0,8}))?\}/.exec(suffix);
      const repeats=suffix.startsWith('+')||suffix.startsWith('*')||
        Boolean(bound&&(bound[2]===''||Number(bound[2]??bound[1])>1));
      // Alternation hidden inside an enclosing repeated group is also
      // exponential (e.g. (?<field>((a|aa))+)). Propagate the fact that
      // any child has alternatives through otherwise harmless wrappers.
      if(repeats&&(frame.repeated||frame.alternative))return true;
      if(stack.length){
        if(frame.repeated||repeats)stack[stack.length-1]!.repeated=true;
        if(frame.alternative)stack[stack.length-1]!.alternative=true;
      }
      continue;
    }
    if(!stack.length)continue;
    if(char==='|')stack[stack.length-1]!.alternative=true;
    if(char==='*'||char==='+'||char==='?'){
      stack[stack.length-1]!.repeated=true;
    }else if(char==='{'){
      const bound=/^\{\d{1,8}(?:,\d{0,8})?\}/.exec(pattern.slice(i));
      if(bound){stack[stack.length-1]!.repeated=true;i+=bound[0].length-1;}
    }
  }
  return false;
}

/** Adjacent unbounded captures can overlap with polynomial backtracking
 * despite having no nested groups or identical literal atoms. Conservatively
 * require an explicit separator between consecutive quantified captures. */
function hasAdjacentQuantifiedCaptures(pattern:string):boolean{
  const capture=/\(\?<([A-Za-z_][A-Za-z0-9_]*)>((?:\\.|[^()])*)\)/g;
  let previousEnd=-1,previousQuantified=false;
  for(const match of pattern.matchAll(capture)){
    const body=match[2]!;
    const quantified=/(?:\+|\*|\{\d+(?:,\d*)?\})$/.test(body);
    if(previousEnd===match.index&&previousQuantified&&quantified)return true;
    previousEnd=match.index!+match[0].length;
    previousQuantified=quantified;
  }
  return false;
}

export function validatePreviewRegexPattern(pattern: string): string | null {
  if (!pattern.trim()) return 'Enter a named-group regular expression';
  if (pattern.length > 256) return 'Regex exceeds 256 characters';
  if (!pattern.includes('(?<')) return 'Add at least one (?<field>...) named capture';

  const unsupported = 'Regex uses an unsupported or potentially expensive construct';

  // Backreferences and lookbehind enable nonlocal matching/ambiguous nesting.
  if (/\\[1-9]|\\k<|\(\?<[=!]/.test(pattern)) return unsupported;

  // These forms can yield exponential backtracking even with short input:
  // repeated groups containing quantifiers, optional terms or alternatives.
  if (/\((?:[^()]|\\.)*[+*?](?:[^()]|\\.)*\)(?:[+*]|\{\d+(?:,\d*)?\})/.test(pattern)) {
    return unsupported;
  }
  if (/\((?:\?:)?[^()]*\|[^()]*\)(?:[+*]|\{\d+(?:,\d*)?\})/.test(pattern)) {
    return unsupported;
  }
  if (hasNestedQuantifiers(pattern)) return unsupported;
  if (hasAdjacentQuantifiedCaptures(pattern)) return unsupported;

  // Adjacent repetitions of the identical literal character are ambiguous.
  if (/([A-Za-z0-9])(?:[*+])\1(?:[*+])/.test(pattern)) return unsupported;

  // Prohibit very large unrolled repetition budgets, even without nested
  // quantifiers; the user can rewrite these as smaller typed expressions.
  for (const match of pattern.matchAll(/\{(\d{1,8})(?:,(\d{0,8}))?\}/g)) {
    const low = Number(match[1]);
    const high = match[2] === undefined || match[2] === '' ? low : Number(match[2]);
    if (low > 128 || high > 128) return unsupported;
  }
  return null;
}
