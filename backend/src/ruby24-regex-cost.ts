/**
 * Static backtracking-cost classification for the portable named-capture Regex
 * subset, used to decide whether a pattern may run NATIVELY on a Ruby runtime
 * that has no Regexp timeout (Stellar Cyber 7.0: Ruby 2.4.9 / Onigmo).
 *
 * Root cause this module addresses: Regexp.timeout= and Regexp::TimeoutError
 * only exist from Ruby 3.2. The Ruby 2.4.9 runtime therefore cannot bound a
 * backtracking match at run time, and the compiler previously delegated ALL
 * safety to that missing feature. This module instead bounds the cost at
 * generation time by construction.
 *
 * Model. The pattern is lowered to its Glushkov position automaton (one state
 * per consuming atom, no epsilon edges). A backtracking engine explores one
 * search-tree node per distinct path of the automaton, so its work on an input
 * of length n is the sum, over prefix lengths, of the number of live paths. We
 * accept a pattern only if that number is bounded by a pattern-dependent
 * constant, which gives O(n) work:
 *   1. no exponential degree of ambiguity (EDA): no state p with two distinct
 *      cycles p -> p reading the same word;
 *   2. no infinite degree of ambiguity (IDA): no distinct states p, q with a
 *      word v such that p -v-> p, p -v-> q and q -v-> q (Weber and Seidl);
 *   3. every NON-loop choice (alternation, optional atom) is deterministic:
 *      its alternatives cannot start with the same character;
 *   4. at most MAX_NONDETERMINISTIC_LOOPS loops may disagree with what follows
 *      them (a loop such as the leading .* in ^.*%FTD-...);
 *   5. an unanchored pattern is modelled with a virtual leading .* loop, so a
 *      pattern with loops must start with ^ to be accepted.
 * Anchors are treated as zero-width (they only remove paths, so ignoring them
 * can only over-approximate). All character sets are over-approximated when a
 * class cannot be parsed exactly; over-approximation can only add overlap and
 * therefore only causes rejection, never acceptance.
 *
 * This is a classification with a verified-by-execution backstop (the Ruby
 * 2.4.9 CI gate runs adversarial inputs under a wall-clock limit). It is NOT a
 * claim about regex engines other than backtracking Onigmo/V8. The runtime
 * helper additionally refuses multi-line input and input over
 * RUBY24_REGEX_MAX_INPUT_BYTES, which the analysis assumes.
 */
import {parsePortableRegexAst,portableRegexIssue,type PortableRegexNode}
  from './portable-regex.js';

export const RUBY24_REGEX_COST_CONTRACT='parser-studio.ruby24-regex-cost.v1';
export const RUBY24_REGEX_MAX_INPUT_BYTES=4096;
export const RUBY24_REGEX_MAX_POSITIONS=200;
const MAX_NONDETERMINISTIC_LOOPS=2;
const PAIR_BUDGET_NODES=400_000;
const TRIPLE_BUDGET_NODES=1_500_000;

export type Ruby24RegexRejection=
  'REGEX_NOT_PORTABLE'|'REGEX_TOO_MANY_POSITIONS'|'REGEX_NONDETERMINISTIC_CHOICE'|
  'REGEX_TOO_MANY_AMBIGUOUS_LOOPS'|'REGEX_EXPONENTIAL_AMBIGUITY'|
  'REGEX_POLYNOMIAL_AMBIGUITY'|'REGEX_ANALYSIS_BUDGET';

export const RUBY24_REGEX_REJECTION_TEXT:Record<Ruby24RegexRejection,string>={
  REGEX_NOT_PORTABLE:"the pattern uses syntax outside the portable subset",
  REGEX_TOO_MANY_POSITIONS:"the pattern is too large to analyse",
  REGEX_NONDETERMINISTIC_CHOICE:"an alternation or optional element can start with the same character as its alternative",
  REGEX_TOO_MANY_AMBIGUOUS_LOOPS:"more than two repeats overlap what follows them, or an unanchored pattern also has an overlapping repeat",
  REGEX_EXPONENTIAL_AMBIGUITY:"the pattern can backtrack exponentially",
  REGEX_POLYNOMIAL_AMBIGUITY:"two repeats can consume the same text, which can backtrack quadratically; anchor with ^ and separate them with a literal",
  REGEX_ANALYSIS_BUDGET:"the pattern is too complex to prove bounded",
};

export type Ruby24RegexCost=
  |{ok:true;contract:typeof RUBY24_REGEX_COST_CONTRACT;positions:number;
    anchored:boolean;ambiguousLoops:number}
  |{ok:false;reason:Ruby24RegexRejection};

type CharSet=Array<[number,number]>;
const MAX_CP=0x10ffff;
const FULL:CharSet=[[0,MAX_CP]];

function normalize(ranges:CharSet):CharSet{
  const sorted=ranges.map(r=>[r[0],r[1]] as [number,number]).sort((a,b)=>a[0]-b[0]);
  const out:CharSet=[];
  for(const [lo,hi] of sorted){
    const last=out[out.length-1];
    if(last&&lo<=last[1]+1)last[1]=Math.max(last[1],hi);
    else out.push([lo,hi]);
  }
  return out;
}
function intersect(a:CharSet,b:CharSet):CharSet{
  const out:CharSet=[];
  let i=0,j=0;
  while(i<a.length&&j<b.length){
    const lo=Math.max(a[i]![0],b[j]![0]),hi=Math.min(a[i]![1],b[j]![1]);
    if(lo<=hi)out.push([lo,hi]);
    if(a[i]![1]<b[j]![1])i++;else j++;
  }
  return out;
}
function complement(a:CharSet):CharSet{
  const out:CharSet=[];
  let next=0;
  for(const [lo,hi] of normalize(a)){
    if(lo>next)out.push([next,lo-1]);
    next=hi+1;
  }
  if(next<=MAX_CP)out.push([next,MAX_CP]);
  return out;
}
const overlaps=(a:CharSet,b:CharSet)=>intersect(a,b).length>0;
const single=(cp:number):CharSet=>[[cp,cp]];
const DIGIT:CharSet=[[48,57]];
const WORD:CharSet=normalize([[48,57],[65,90],[95,95],[97,122]]);
const SPACE:CharSet=[[9,13],[32,32]];
const SIMPLE_ESCAPES:Record<string,number>={t:9,n:10,v:11,f:12,r:13};

/** Set of one escape without its backslash; null means "cannot model exactly". */
function escapeSet(body:string,insideClass:boolean):CharSet|null{
  if(body==='d')return DIGIT;
  if(body==='D')return complement(DIGIT);
  if(body==='w')return WORD;
  if(body==='W')return complement(WORD);
  if(body==='s')return SPACE;
  if(body==='S')return complement(SPACE);
  if(body in SIMPLE_ESCAPES)return single(SIMPLE_ESCAPES[body]!);
  if(body==='b'&&insideClass)return single(8);
  const hex=/^x([0-9a-fA-F]{2})$/.exec(body);
  if(hex)return single(parseInt(hex[1]!,16));
  if([...body].length===1&&!/[A-Za-z0-9]/.test(body))return single(body.codePointAt(0)!);
  return null;
}

function classSet(text:string):CharSet{
  // text is the whole bracket expression including [ and ]. Any doubt makes
  // the set FULL: a superset can only create more overlap, never less.
  const content=[...text.slice(1,-1)];
  let negate=false;
  let index=0;
  if(content[0]==='^'){negate=true;index=1;}
  const parts:CharSet=[];
  const atom=():{set:CharSet;cp:number|null}|null=>{
    const c=content[index++];
    if(c===undefined)return null;
    if(c!=='\\')return {set:single(c.codePointAt(0)!),cp:c.codePointAt(0)!};
    let body=content[index++];
    if(body===undefined)return null;
    if(body==='x'){body+=(content[index]??'')+(content[index+1]??'');index+=2;}
    const set=escapeSet(body,true);
    if(!set)return null;
    const isSingle=set.length===1&&set[0]![0]===set[0]![1];
    return {set,cp:isSingle?set[0]![0]:null};
  };
  while(index<content.length){
    const first=atom();
    if(!first)return FULL;
    if(content[index]==='-'&&index+1<content.length){
      index++;
      const second=atom();
      if(!second||first.cp===null||second.cp===null||first.cp>second.cp)return FULL;
      parts.push([first.cp,second.cp]);
    }else parts.push(...first.set);
  }
  if(!parts.length)return FULL;
  const set=normalize(parts);
  return negate?complement(set):set;
}

function atomSet(node:PortableRegexNode):CharSet{
  switch(node.kind){
    case 'literal':return single(node.text.codePointAt(0)!);
    case 'wildcard':return complement(single(10));
    case 'class':return classSet(node.text);
    case 'escape':return escapeSet(node.text.slice(1),false)??FULL;
    default:return FULL;
  }
}

interface Built{nullable:boolean;first:number[];last:number[]}
interface RepeatRecord{lo:number;hi:number;first:number[];last:number[];
  min:number;max:number|null;lazy:boolean}

/** Classify a pattern. Never throws: unsupported shapes are rejected. */
export function analyzeRuby24RegexCost(pattern:string):Ruby24RegexCost{
  if(portableRegexIssue(pattern))return {ok:false,reason:'REGEX_NOT_PORTABLE'};
  const parsed=parsePortableRegexAst(pattern);
  if(!parsed.ok)return {ok:false,reason:'REGEX_NOT_PORTABLE'};

  const sets:CharSet[]=[];
  const follow:Array<Set<number>>=[];
  const repeats:RepeatRecord[]=[];
  const alternations:Array<Array<{first:number[];nullable:boolean}>>=[];
  let tooMany=false;
  const link=(from:number[],to:number[])=>{
    for(const a of from)for(const b of to)follow[a]!.add(b);
  };
  const build=(node:PortableRegexNode):Built=>{
    switch(node.kind){
      case 'anchor':return {nullable:true,first:[],last:[]};
      case 'sequence':{
        let result:Built={nullable:true,first:[],last:[]};
        for(const child of node.nodes){
          const next=build(child);
          link(result.last,next.first);
          result={
            nullable:result.nullable&&next.nullable,
            first:result.nullable?[...result.first,...next.first]:result.first,
            last:next.nullable?[...result.last,...next.last]:next.last,
          };
        }
        return result;
      }
      case 'alternation':{
        const branches=node.branches.map(build);
        alternations.push(branches.map(b=>({first:b.first,nullable:b.nullable})));
        return {
          nullable:branches.some(b=>b.nullable),
          first:branches.flatMap(b=>b.first),
          last:branches.flatMap(b=>b.last),
        };
      }
      case 'group':return build(node.body);
      case 'repeat':{
        const lo=sets.length;
        const inner=build(node.atom);
        const hi=sets.length;
        if(node.max===null||node.max>1)link(inner.last,inner.first);
        repeats.push({lo,hi,first:inner.first,last:inner.last,
          min:node.min,max:node.max,lazy:node.lazy});
        return {nullable:node.min===0||inner.nullable,first:inner.first,last:inner.last};
      }
      default:{
        if(sets.length>=RUBY24_REGEX_MAX_POSITIONS){
          tooMany=true;return {nullable:false,first:[],last:[]};
        }
        const id=sets.length;
        sets.push(atomSet(node));
        follow.push(new Set());
        return {nullable:false,first:[id],last:[id]};
      }
    }
  };
  const whole=build(parsed.ast);
  if(tooMany)return {ok:false,reason:'REGEX_TOO_MANY_POSITIONS'};

  // Anchored means every top-level branch starts with a start anchor.
  const startsAnchored=(node:PortableRegexNode):boolean=>{
    if(node.kind==='sequence'){
      const head=node.nodes[0];
      return head?.kind==='anchor'&&head.text==='^';
    }
    if(node.kind==='alternation')return node.branches.every(startsAnchored);
    return false;
  };
  const anchored=startsAnchored(parsed.ast);
  const union=(ids:number[])=>normalize(ids.flatMap(p=>sets[p]!));

  // Rule 3: non-loop choices must be deterministic.
  for(const branches of alternations){
    for(let i=0;i<branches.length;i++){
      if(branches[i]!.nullable)return {ok:false,reason:'REGEX_NONDETERMINISTIC_CHOICE'};
      for(let j=i+1;j<branches.length;j++)
        if(overlaps(union(branches[i]!.first),union(branches[j]!.first)))
          return {ok:false,reason:'REGEX_NONDETERMINISTIC_CHOICE'};
    }
  }
  let ambiguousLoops=0;
  for(const rep of repeats){
    if(!(rep.max===null||rep.max>rep.min))continue;
    const loop=rep.max===null||rep.max>1;
    const exits=new Set<number>();
    for(const last of rep.last)for(const next of follow[last]!)
      if(next<rep.lo||next>=rep.hi)exits.add(next);
    if(!(rep.lazy||overlaps(union(rep.first),union([...exits]))))continue;
    if(!loop)return {ok:false,reason:'REGEX_NONDETERMINISTIC_CHOICE'};
    ambiguousLoops++;
  }
  const total=sets.length+(anchored?0:1);
  // Rule 5: an unanchored scan is itself a loop over every start offset.
  if(!anchored){
    sets.push(FULL);
    const id=sets.length-1;
    follow.push(new Set([id,...whole.first]));
    ambiguousLoops++;
  }
  if(ambiguousLoops>MAX_NONDETERMINISTIC_LOOPS)
    return {ok:false,reason:'REGEX_TOO_MANY_AMBIGUOUS_LOOPS'};

  const n=sets.length;
  const common=(a:number,b:number)=>overlaps(sets[a]!,sets[b]!);

  // Rule 1: EDA via strongly connected components of the pair automaton.
  const pairCount=n*n;
  if(pairCount>PAIR_BUDGET_NODES)return {ok:false,reason:'REGEX_ANALYSIS_BUDGET'};
  const successors=(id:number):number[]=>{
    const p=Math.floor(id/n),q=id%n,out:number[]=[];
    for(const a of follow[p]!)for(const b of follow[q]!)
      if(common(a,b))out.push(a*n+b);
    return out;
  };
  const index=new Int32Array(pairCount).fill(-1);
  const low=new Int32Array(pairCount);
  const onStack=new Uint8Array(pairCount);
  const stack:number[]=[];
  let counter=0;
  for(let root=0;root<pairCount;root++){
    if(index[root]!==-1)continue;
    const work:Array<{node:number;next:number[];at:number}>=[];
    const open=(node:number)=>{
      index[node]=low[node]=counter++;stack.push(node);onStack[node]=1;
      work.push({node,next:successors(node),at:0});
    };
    open(root);
    while(work.length){
      const frame=work[work.length-1]!;
      if(frame.at<frame.next.length){
        const target=frame.next[frame.at++]!;
        if(index[target]===-1)open(target);
        else if(onStack[target])low[frame.node]=Math.min(low[frame.node]!,index[target]!);
        continue;
      }
      work.pop();
      const parent=work[work.length-1];
      if(parent)low[parent.node]=Math.min(low[parent.node]!,low[frame.node]!);
      if(low[frame.node]===index[frame.node]){
        let diagonal=false,off=false,member:number;
        do{
          member=stack.pop()!;onStack[member]=0;
          if(Math.floor(member/n)===member%n)diagonal=true;else off=true;
        }while(member!==frame.node);
        if(diagonal&&off)return {ok:false,reason:'REGEX_EXPONENTIAL_AMBIGUITY'};
      }
    }
  }

  // Rule 2: IDA via triple products from every ordered pair of cyclic states.
  const reach=(from:number,to:number):boolean=>{
    const seen=new Set<number>();const todo=[...follow[from]!];
    while(todo.length){
      const x=todo.pop()!;
      if(x===to)return true;
      if(seen.has(x))continue;seen.add(x);todo.push(...follow[x]!);
    }
    return false;
  };
  const cyclicStates=Array.from({length:n},(_,p)=>p).filter(p=>reach(p,p));
  let tripleNodes=0;
  for(const p of cyclicStates)for(const q of cyclicStates){
    if(p===q||!reach(p,q))continue;
    const target=p*n*n+q*n+q;
    const start=p*n*n+p*n+q;
    const seen=new Set<number>([start]);
    const queue=[start];
    while(queue.length){
      const id=queue.pop()!;
      const a=Math.floor(id/(n*n)),b=Math.floor(id/n)%n,c=id%n;
      for(const a2 of follow[a]!)for(const b2 of follow[b]!){
        if(!common(a2,b2))continue;
        const ab=intersect(sets[a2]!,sets[b2]!);
        for(const c2 of follow[c]!){
          if(!overlaps(ab,sets[c2]!))continue;
          const next=a2*n*n+b2*n+c2;
          if(next===target)return {ok:false,reason:'REGEX_POLYNOMIAL_AMBIGUITY'};
          if(seen.has(next))continue;
          seen.add(next);queue.push(next);
          if(++tripleNodes>TRIPLE_BUDGET_NODES)
            return {ok:false,reason:'REGEX_ANALYSIS_BUDGET'};
        }
      }
    }
  }
  return {ok:true,contract:RUBY24_REGEX_COST_CONTRACT,positions:total,anchored,ambiguousLoops};
}

export function ruby24RegexExportable(pattern:unknown):boolean{
  return typeof pattern==='string'&&analyzeRuby24RegexCost(pattern).ok;
}
