/** Mirrors the reviewed-CSV name rules and says which one is not met. */
const NAME=/^[A-Za-z][A-Za-z0-9_]{0,63}$/;

function shown(value:string):string{
  return '"'+(value.length>24?value.slice(0,24)+'…':value)+'"';
}

export function describeCsvColumnNameProblem(names:string[]):string|null {
  if(names.length<2)return 'Enter at least 2 field names, separated by commas.';
  if(names.length>100)return 'Use at most 100 field names.';
  const seen=new Set<string>();
  for(const name of names){
    if(seen.has(name))return 'Each field name must be unique. '+shown(name)+' is used more than once.';
    seen.add(name);
  }
  for(const name of names){
    if(!name)return 'One field has an empty name. Remove the extra comma or type a name.';
    if(name.length>64)return 'A field name is longer than 64 characters. Shorten '+shown(name)+'.';
    if(!NAME.test(name))
      return 'Field names must start with a letter and use only letters, numbers and underscores. Change '+
        shown(name)+'.';
  }
  return null;
}
