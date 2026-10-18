/**
 * Bounded, source-preserving single-record CSV cell grammar.
 * RFC4180 spaces inside unquoted fields are significant, and quoted
 * fields require an immediate delimiter or record end after closing quote.
 * Semicolon/tab are explicit browser dialect choices, not RFC4180 claims.
 * Native/parser-producer semantics are NOT certified by lexical inspection.
 */
export interface CsvSourceCell {
  start:number;
  end:number;
  value:string|null;
  quoted:boolean;
  /** Explicitly declared non-RFC4180 protected cell; source value unmodified. */
  bracedGroup?:true;
}
export type CsvSourceDelimiter=','|';'|'\t';
const MAX_COLUMNS=256;
export function readCsvSourceCells(raw:string,delimiter:CsvSourceDelimiter,
  nullable=false,options?:{
    declaredPaddingAfterDelimiter?:boolean;
    /** Opt-in zero-based protected-field ordinals, never auto-detected. */
    declaredBracedGroupColumns?:readonly number[];
  }):CsvSourceCell[]|null {
  if(raw.length===0)return null;
  const groups=options?.declaredBracedGroupColumns;
  if(groups!==undefined){
    if(!Array.isArray(groups)||groups.length>MAX_COLUMNS||
       groups.some(c=>!Number.isInteger(c)||c<0||c>=MAX_COLUMNS)||
       new Set(groups).size!==groups.length)return null;
  }
  const protectedOrdinals=new Set(groups??[]);
  const result:CsvSourceCell[]=[];
  let pos=0;
  while(pos<=raw.length){
    if(result.length>=MAX_COLUMNS)return null;
    // Optional explicit non-RFC dialect only for independently qualified
    // source layout; strict RFC4180 never ignores field-edge spaces.
    if(options?.declaredPaddingAfterDelimiter&&result.length>0)
      while(raw[pos]===' ')pos++;
    const start=pos,quoted=raw[pos]==='"';
    const isDeclaredGroup=!quoted&&raw[pos]==='{'&&
      protectedOrdinals.has(result.length);
    let value:string|null='';
    if(quoted){
      pos++;let decoded='',closed=false;
      while(pos<raw.length){
        const char=raw[pos]!;
        if(char==='"'){
          if(raw[pos+1]==='"'){decoded+='"';pos+=2;continue;}
          pos++;closed=true;break;
        }
        const code=char.charCodeAt(0);
        if(code===0||code===127||(code<32&&char!=='\n'&&char!=='\r'&&char!=='\t'))
          return null;
        decoded+=char;pos++;
      }
      if(!closed||(pos<raw.length&&raw[pos]!==delimiter))return null;
      value=decoded;
    }else if(isDeclaredGroup){
      // A declared, whole-cell balanced group is not RFC4180 quoting.
      // Only its explicitly marked ordinal can contain separator commas.
      // Unknown escape/quote semantics MUST abstain, not guess decoding.
      let depth=0,closed=false;
      while(pos<raw.length){
        const ch=raw[pos]!,code=ch.charCodeAt(0);
        if(code<32||code===127||ch==='\\'||ch==='"'||ch==="'")
          return null;
        if(ch==='{'){
          if(++depth>4)return null;
        }else if(ch==='}'){
          if(--depth<0)return null;
          if(depth===0){
            pos++;closed=true;
            if(pos<raw.length&&raw[pos]!==delimiter)return null;
            break;
          }
        }
        pos++;
      }
      if(!closed||depth!==0)return null;
      value=raw.slice(start,pos);
    }else{
      while(pos<raw.length&&raw[pos]!==delimiter){
        const char=raw[pos]!;
        const code=char.charCodeAt(0);
        if(char==='"'||char==='\r'||char==='\n'||code===0||code===127||
          (code<32&&char!=='\t'))return null;
        pos++;
      }
      value=start===pos&&nullable?null:raw.slice(start,pos);
    }
    result.push({start,end:pos,value,quoted,
      ...(isDeclaredGroup?{bracedGroup:true as const}:{})});
    if(pos===raw.length)break;
    pos++;
    if(pos===raw.length){
      if(result.length>=MAX_COLUMNS)return null;
      result.push({start:pos,end:pos,value:nullable?null:'',quoted:false});
      break;
    }
  }
  return result;
}
