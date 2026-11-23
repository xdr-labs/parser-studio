import {parsePortableRegexAst,type PortableRegexNode} from '../../backend/src/portable-regex';

/**
 * Whether a named-capture pattern reads text of the line that no field keeps. Outside the named captures a pattern
 * may only spell the structure of the line: literal text, anchors, white space and zero-width assertions, which
 * can be written again from the pattern itself. A character class, a wildcard, a letter escape such as \S or \d,
 * a repeated literal (its count) or a choice between literal alternatives (which one) reads part of the event and
 * keeps it nowhere: a ChatGPT reply with ` \S+$` in place of `(?<type>\S+)$` silently dropped the content type of
 * every Squid line and was still reported as a complete parse (Phase 3 P2 ChatGPT Assisted check, 2026-11-23).
 * A pattern that does not parse counts as reading uncaptured text.
 */
export function regexReadsUncapturedText(pattern:string):boolean{
  const parsed=parsePortableRegexAst(pattern);
  return !parsed.ok||reads(parsed.ast);
}

// \r never reaches a pattern as data: an event with a bare carriage return is refused (UNSUPPORTED_LINE_ENDING).
const BLANK_ESCAPES=new Set(['\\s','\\t','\\x20','\\x09','\\r']);
const BLANK_CLASS=/^\[(?: |\\t|\\s)+\]$/u;
function blank(node:PortableRegexNode):boolean{
  return (node.kind==='literal'&&node.text===' ')||
    (node.kind==='escape'&&BLANK_ESCAPES.has(node.text))||
    (node.kind==='class'&&BLANK_CLASS.test(node.text));
}
/** White space only, also inside a non-capturing group or a sequence: `(?: )?` keeps no data. */
function blankRun(node:PortableRegexNode):boolean{
  switch(node.kind){
    case 'group':return node.captureName===null&&blankRun(node.body);
    case 'sequence':return node.nodes.length>0&&node.nodes.every(blankRun);
    case 'repeat':return blankRun(node.atom);
    default:return blank(node);
  }
}
function captures(node:PortableRegexNode):boolean{
  switch(node.kind){
    case 'sequence':return node.nodes.some(captures);
    case 'alternation':return node.branches.some(captures);
    case 'group':return node.captureName!==null||captures(node.body);
    case 'repeat':return captures(node.atom);
    default:return false;
  }
}
function reads(node:PortableRegexNode):boolean{
  switch(node.kind){
    case 'sequence':return node.nodes.some(reads);
    // Which branch matched is kept only when every branch keeps a capture of its own.
    case 'alternation':return node.branches.some(branch=>reads(branch)||!captures(branch));
    case 'group':return node.captureName===null&&reads(node.body);
    // A run of white space is no data; any other repetition outside a capture loses what it repeated.
    // An optional piece (min 0, max 1) tells by its presence what no field keeps, like a choice between
    // alternatives (re-audit 2026-11-23, Q2-3: `(?:DENIED )?` made a denied and an allowed line read alike).
    // A capture inside a piece that may repeat keeps its last repetition only (re-audit 3, Q3-2: `sudo -a -b -c`
    // and `sudo -c` read alike under `(?: (?<flag>-[a-z]))*`).
    case 'repeat':return reads(node.atom)||(node.max!==1&&captures(node.atom))||
      ((node.max!==1||node.min!==node.max)&&!blankRun(node.atom)&&!captures(node.atom));
    case 'literal':case 'anchor':return false;
    // \b and \B assert a position; \t and \xHH are one literal character; a letter class reads a character.
    case 'escape':return /^\\[dDwWsS]$/u.test(node.text)&&node.text!=='\\s';
    case 'class':case 'wildcard':return !blank(node);
  }
}
