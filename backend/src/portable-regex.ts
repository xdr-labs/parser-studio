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
  'REGEX_DIALECT_ESCAPE'|'REGEX_POSIX_CLASS'|'REGEX_OVERLAPPING_REPETITION'|
  'REGEX_UNSUPPORTED_GROUP'|'REGEX_AST_SYNTAX'|'REGEX_BOUND_LIMIT';

/** Versioned, inspection-only AST for the reviewed JS/Ruby regex subset.
 * This is not a regex evaluator or a promise of native execution. Runtime
 * parity remains subject to independent generated-Ruby conformance.
 */
export const PORTABLE_REGEX_AST_CONTRACT='parser-studio.portable-regex-ast.v1';
export type PortableRegexNode=
  |{kind:'sequence';nodes:PortableRegexNode[]}
  |{kind:'alternation';branches:PortableRegexNode[]}
  |{kind:'group';captureName:string|null;body:PortableRegexNode}
  |{kind:'repeat';min:number;max:number|null;lazy:boolean;atom:PortableRegexNode}
  |{kind:'literal'|'escape'|'class'|'wildcard'|'anchor';text:string};
export type PortableRegexAstResult=
  |{ok:true;contract:typeof PORTABLE_REGEX_AST_CONTRACT;
    ast:PortableRegexNode;captureNames:string[]}
  |{ok:false;issue:PortableRegexIssue};

export function parsePortableRegexAst(pattern:string):PortableRegexAstResult{
  let pos=0;
  const captureNames:string[]=[];
  const captures=new Set<string>();
  let issue:PortableRegexIssue|null=null;
  const fail=(reason:PortableRegexIssue):null=>{issue=reason;return null;};
  const atom=():PortableRegexNode|null=>{
    const c=pattern[pos++];
    if(c===undefined)return fail('REGEX_AST_SYNTAX');
    if(c==='('){
      let name:string|null=null;
      if(pattern.startsWith('?:',pos))pos+=2;
      else if(pattern.startsWith('?<',pos)){
        const end=pattern.indexOf('>',pos+2);
        if(end<0)return fail('REGEX_AST_SYNTAX');
        name=pattern.slice(pos+2,end);
        if(!/^[A-Za-z_][A-Za-z0-9_]*$/.test(name)||
           ['__proto__','constructor','prototype'].includes(name)||
           captures.has(name))return fail('REGEX_UNSUPPORTED_GROUP');
        captureNames.push(name);captures.add(name);pos=end+1;
      }else if(pattern[pos]==='?')return fail('REGEX_UNSUPPORTED_GROUP');
      const body=expression(true);
      if(!body||pattern[pos]!==')')return fail('REGEX_AST_SYNTAX');
      pos++;
      return {kind:'group',captureName:name,body};
    }
    if(c==='['){
      const start=pos-1;
      if(pattern[pos]==='^')pos++;
      const first=pos;
      while(pos<pattern.length){
        if(pattern[pos]==='\\'){pos+=2;continue;}
        if(pattern[pos]===']')break;
        pos++;
      }
      if(pos===first||pattern[pos]!==']')return fail('REGEX_AST_SYNTAX');
      pos++;
      return {kind:'class',text:pattern.slice(start,pos)};
    }
    if(c==='\\'){
      const escaped=pattern[pos++];
      if(escaped===undefined)return fail('REGEX_AST_SYNTAX');
      if(escaped==='x'){
        if(!/^[a-fA-F0-9]{2}$/.test(pattern.slice(pos,pos+2)))
          return fail('REGEX_DIALECT_ESCAPE');
        pos+=2;
      }
      return {kind:'escape',text:pattern.slice(pos-(escaped==='x'?4:2),pos)};
    }
    if(c==='*'||c==='+'||c==='?'||c==='{')return fail('REGEX_AST_SYNTAX');
    return c==='.'?{kind:'wildcard',text:c}:
      c==='^'||c==='$'?{kind:'anchor',text:c}:
      {kind:'literal',text:c};
  };
  const quantified=(base:PortableRegexNode):PortableRegexNode|null=>{
    const c=pattern[pos];
    if(c===undefined||!['*','+','?','{'].includes(c))return base;
    let min=0,max:number|null=null;
    if(c==='*'){pos++;}
    else if(c==='+'){min=1;pos++;}
    else if(c==='?'){max=1;pos++;}
    else{
      const m=/^\{(\d{1,8})(?:,(\d{0,8}))?\}/.exec(pattern.slice(pos));
      if(!m)return fail('REGEX_AST_SYNTAX');
      min=Number(m[1]);max=m[2]===undefined?min:m[2]===''?null:Number(m[2]);
      pos+=m[0].length;
      if(min>128||(max!==null&&(max>128||max<min)))
        return fail('REGEX_BOUND_LIMIT');
    }
    const lazy=pattern[pos]==='?';
    if(lazy)pos++;
    return {kind:'repeat',min,max,lazy,atom:base};
  };
  const expression=(nested:boolean):PortableRegexNode|null=>{
    const branches:PortableRegexNode[]=[];
    let nodes:PortableRegexNode[]=[];
    while(pos<pattern.length){
      if(pattern[pos]===')'){
        if(!nested)return fail('REGEX_AST_SYNTAX');
        break;
      }
      if(pattern[pos]==='|'){
        branches.push({kind:'sequence',nodes});nodes=[];pos++;continue;
      }
      const node=atom();
      if(!node)return null;
      const repeated=quantified(node);
      if(!repeated)return null;
      nodes.push(repeated);
    }
    branches.push({kind:'sequence',nodes});
    return branches.length===1?branches[0]!:{kind:'alternation',branches};
  };
  const ast=expression(false);
  if(!ast||pos!==pattern.length||issue)return {ok:false,issue:issue??'REGEX_AST_SYNTAX'};
  return {ok:true,contract:PORTABLE_REGEX_AST_CONTRACT,ast,captureNames};
}

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
  const grammar=parsePortableRegexAst(pattern);
  if(!grammar.ok)return grammar.issue;
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
