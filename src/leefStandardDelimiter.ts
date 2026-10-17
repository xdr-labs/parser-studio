/**
 * LEEF 2.0 declared event-attribute delimiter grammar.
 * IBM QRadar LEEF event components: exactly one literal character or 1..4
 * hexadecimal code points preceded by 'x' or '0x'. Native target unverified.
 */
export function parseLeefStandardDelimiter(token:string):string|null{
  if(!token)return null;
  const hex=/^(?:0x|x)([0-9a-fA-F]{1,4})$/.exec(token);
  let delimiter=token;
  if(hex){
    const point=parseInt(hex[1]!,16);
    if(point>0x10ffff||(point>=0xd800&&point<=0xdfff))return null;
    delimiter=String.fromCodePoint(point);
  }
  const chars=Array.from(delimiter);
  if(chars.length!==1)return null;
  const code=delimiter.codePointAt(0)!;
  // Reject delimiters that destroy attribute key=value and safe framing.
  if(code===0||code===10||code===13||code===127||code===61||code===92||
    (code<32&&code!==9)||(code>=0xd800&&code<=0xdfff))
    return null;
  return delimiter;
}
