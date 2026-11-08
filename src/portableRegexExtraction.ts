/** One bounded regex extractor for standalone and Syslog-body previews. */
import {createPortableRegex} from '../backend/src/portable-regex';
import {validatePreviewRegexPattern} from './regexSafety';
import {validateConventionalTemporalCaptures} from './regexTemporalClaims';
import {jsonSourceValueValid} from './jsonSourceSafety';

export function extractPortableRegexFields(raw:string,pattern:string):{
 fields:Record<string,unknown>;errors:string[];
}{
 const issue=validatePreviewRegexPattern(pattern);
 if(issue)return {fields:{},errors:[issue]};
 if(!jsonSourceValueValid(raw))return {fields:{},errors:['Invalid source Unicode']};
 try{
  const matched=createPortableRegex(pattern).exec(raw);
  if(!matched?.groups)return {fields:{},errors:['Expression did not match this event']};
  const fields=Object.fromEntries(Object.entries(matched.groups).filter(([,value])=>value!==undefined));
  if(!Object.keys(fields).length)return {fields:{},errors:['Named captures returned no fields']};
  const temporal=validateConventionalTemporalCaptures(fields);
  return temporal?{fields:{},errors:[temporal]}:{fields,errors:[]};
 }catch{return {fields:{},errors:['Invalid regular expression']};}
}
