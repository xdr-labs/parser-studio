/**
 * Pulls the JSON recipe out of a ChatGPT answer that wraps it in explanation.
 * Pure text handling: nothing is trusted here. The result still goes through
 * the normal recipe validator, so a wrong pick can only be rejected, never applied.
 */
export interface ExtractedRecipeJson{
  text:string;
  /** True when prose outside the JSON (and outside one wrapping fence) was dropped. */
  ignoredText:boolean;
}

const RECIPE_CONTRACT='parser-studio.recipe.v0.2';
const FENCE=/\x60\x60\x60[A-Za-z0-9_-]*[ \t]*\r?\n([\s\S]*?)\r?\n?\x60\x60\x60/g;

function parsesAsObject(text:string):Record<string,unknown>|null{
  try{
    const value=JSON.parse(text) as unknown;
    return value&&typeof value==='object'&&!Array.isArray(value)?value as Record<string,unknown>:null;
  }catch{return null;}
}

/** Balanced top-level `{...}` spans, aware of JSON strings and escapes. */
function objectSpans(text:string):string[]{
  const spans:string[]=[];
  for(let start=text.indexOf('{');start>=0;){
    let depth=0,inString=false,escaped=false,end=-1;
    for(let i=start;i<text.length;i++){
      const ch=text[i]!;
      if(inString){
        if(escaped)escaped=false;
        else if(ch==='\\')escaped=true;
        else if(ch==='"')inString=false;
      }else if(ch==='"')inString=true;
      else if(ch==='{')depth++;
      else if(ch==='}'&&--depth===0){end=i;break;}
    }
    if(end<0){start=text.indexOf('{',start+1);continue;}
    const span=text.slice(start,end+1);
    if(parsesAsObject(span))spans.push(span);
    start=text.indexOf('{',parsesAsObject(span)?end+1:start+1);
  }
  return spans;
}

function pickOne(candidates:string[]):string|null{
  const unique=[...new Set(candidates)];
  if(unique.length===1)return unique[0]!;
  const recipes=unique.filter(c=>parsesAsObject(c)?.contract===RECIPE_CONTRACT);
  return recipes.length===1?recipes[0]!:null;
}

export function extractRecipeJson(reply:string):ExtractedRecipeJson|null{
  const trimmed=typeof reply==='string'?reply.trim():'';
  if(!trimmed)return null;
  if(trimmed.startsWith('{')){
    if(parsesAsObject(trimmed))return {text:trimmed,ignoredText:false};
    const trailing=pickOne(objectSpans(trimmed));
    // Unreadable or truncated JSON stays as-is so the importer reports INVALID_JSON.
    return trailing?{text:trailing,ignoredText:true}:(objectSpans(trimmed).length?null:{text:trimmed,ignoredText:false});
  }
  const wrapped=/^\x60\x60\x60[A-Za-z0-9_-]*[ \t]*\r?\n([\s\S]*?)\r?\n?\x60\x60\x60$/.exec(trimmed);
  if(wrapped&&wrapped[1]!.trim().startsWith('{'))return {text:wrapped[1]!.trim(),ignoredText:false};
  const fenced=[...trimmed.matchAll(FENCE)].map(m=>m[1]!.trim()).filter(b=>parsesAsObject(b));
  const fromFence=pickOne(fenced);
  if(fromFence)return {text:fromFence,ignoredText:true};
  if(fenced.length>1)return null;
  const loose=pickOne(objectSpans(trimmed));
  return loose?{text:loose,ignoredText:true}:null;
}
