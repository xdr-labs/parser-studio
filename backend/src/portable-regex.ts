/**
 * Portable named-capture regex contract shared by browser previews and the
 * native Ruby authoring compiler. Do not import Node APIs: this module must
 * run identically in the browser bundle and in the backend.
 *
 * This is a deliberately conservative rejection gate, not a proof of
 * linear-time execution or universal JS/Ruby semantic equivalence. A compiled
 * parser requires independent native conformance before certification.
 */
export type PortableRegexIssue =
  'REGEX_DIALECT_ESCAPE'|'REGEX_POSIX_CLASS'|'REGEX_OVERLAPPING_REPETITION';

type Atom={kind:'wildcard'|'class'|'literal';token:string;quantified:boolean};

function possiblyOverlaps(a:Atom,b:Atom):boolean{
  if(a.kind==='wildcard'||b.kind==='wildcard')return true;
  if(a.kind==='class'&&b.kind==='class'){
    const signatures=[a.token,b.token];
    if((signatures.includes('\\s')&&signatures.some(v=>v==='\\w'||v==='\\d'))||
       (signatures.includes('\\S')&&signatures.includes('\\s'))||
       (signatures.includes('\\W')&&signatures.includes('\\w'))||
       (signatures.includes('\\D')&&signatures.includes('\\d')))
      return false;
    return true;
  }
  if(a.kind==='class'||b.kind==='class')return true;
  return a.token===b.token;
}

/** Conservative atom-level check: a*a*, .*.*, [ab]*[ab]* and bounded
 * overlapping classes have multiple parses for the same input. Quantified
 * wildcards repeated in a capture are also forbidden even when separated by
 * literals: .*a.*a.*a.* produces polynomial backtracking on nonmatches. */
export function portableRegexIssue(pattern:string):PortableRegexIssue|null{
  // Ruby recognizes POSIX bracket classes but JS regex has different syntax.
  // Reject before analyzing the class's internal nested '[' characters.
  if(/\[\[:[A-Za-z]+:\]\]/.test(pattern))return 'REGEX_POSIX_CLASS';
  const frames:Array<{previous:Atom|null;wildcards:number}>=[{previous:null,wildcards:0}];
  let index=0;
  while(index<pattern.length){
    const current=pattern[index]!;
    const frame=frames[frames.length-1]!;
    if(current==='('){
      frames.push({previous:null,wildcards:0});
      if(pattern.startsWith('(?<',index)){
        const end=pattern.indexOf('>',index+3);
        if(end>=0){index=end+1;continue;}
      }else if(pattern.startsWith('(?:',index)){
        index+=3;continue;
      }
      index++;continue;
    }
    if(current===')'){
      if(frames.length>1)frames.pop();
      frames[frames.length-1]!.previous=null;
      index++;continue;
    }
    if(current==='|'||current==='^'||current==='$'){
      frame.previous=null;if(current==='|')frame.wildcards=0;index++;continue;
    }
    let atom:Atom;
    if(current==='['){
      let end=index+1,escaped=false;
      while(end<pattern.length){
        const char=pattern[end]!;
        if(!escaped&&char===']')break;
        if(!escaped&&char==='\\')escaped=true;
        else escaped=false;
        end++;
      }
      const content=pattern.slice(index+1,end);
      // Revalidate escapes *inside* brackets: [\h] is just as nonportable as
      // bare \h, and JavaScript accepts unknown escapes here too.
      for(let k=0;k<content.length;k++){
        if(content[k]!=='\\')continue;
        const escaped=content[++k];
        if(!escaped)return 'REGEX_DIALECT_ESCAPE';
        if(escaped==='x'){
          if(!/^[0-9A-Fa-f]{2}$/.test(content.slice(k+1,k+3)))
            return 'REGEX_DIALECT_ESCAPE';
          k+=2;continue;
        }
        if(/[A-Za-z0-9]/.test(escaped)&&!'dDsSwWbtnrfv'.includes(escaped))
          return 'REGEX_DIALECT_ESCAPE';
      }
      atom={kind:'class',token:pattern.slice(index,end+1),quantified:false};
      index=end+1;
    }else if(current==='\\'){
      const escaped=pattern[index+1];
      if(!escaped)return 'REGEX_DIALECT_ESCAPE';
      // JS identity escapes can mean completely different Ruby assertions,
      // notably \A, \z and \h. Keep only independently reviewed shorthands.
      if(/[A-Za-z0-9]/.test(escaped)){
        if(escaped==='x'){
          if(!/^[0-9A-Fa-f]{2}$/.test(pattern.slice(index+2,index+4)))
            return 'REGEX_DIALECT_ESCAPE';
          atom={kind:'literal',token:pattern.slice(index,index+4),quantified:false};
          index+=4;
        }else if('dDsSwWbBtnrfv'.includes(escaped)){
          atom={kind:'class',token:'\\'+escaped,quantified:false};index+=2;
        }else return 'REGEX_DIALECT_ESCAPE';
      }else{
        if(!/^[\\.\^$*+?()[\]{}|/,:;=!'"-]$/.test(escaped))
          return 'REGEX_DIALECT_ESCAPE';
        atom={kind:'literal',token:escaped,quantified:false};index+=2;
      }
    }else if(current==='.'){
      atom={kind:'wildcard',token:'.',quantified:false};index++;
    }else if(current==='*'||current==='+'||current==='?'||current==='{'){
      // Quantifiers attached to groups are handled by the existing nested/
      // adjacent-capture gate. A malformed standalone quantifier is rejected
      // downstream by the syntax validator.
      frame.previous=null;index++;continue;
    }else{
      atom={kind:'literal',token:current,quantified:false};index++;
    }
    const remaining=pattern.slice(index);
    const quantifier=/^(?:[+*?]|\{\d{1,8}(?:,\d{0,8})?\})/.exec(remaining)?.[0];
    if(quantifier){
      atom.quantified=true;
      index+=quantifier.length;
      if(pattern[index]==='?')index++;
      if(frame.previous?.quantified&&possiblyOverlaps(frame.previous,atom))
        return 'REGEX_OVERLAPPING_REPETITION';
      if(atom.kind==='wildcard'&&++frame.wildcards>=3)
        return 'REGEX_OVERLAPPING_REPETITION';
      frame.previous=atom;
    }else frame.previous=null;
  }
  return null;
}
