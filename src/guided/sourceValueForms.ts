/** Value forms shared by the ChatGPT Assisted review and the residual provenance check. */

/** Every scalar of a parser output, as the strings the review compares with source text. */
export function scalarValues(value:unknown):string[]{
 if(value===null)return ['null'];
 if(Array.isArray(value))return value.flatMap(scalarValues);
 if(typeof value==='object'&&value!==null)return Object.values(value as Record<string,unknown>).flatMap(scalarValues);
 return value===undefined?[]:[String(value)];
}

/** The forms one exact source value can take in parser output (quotes and backslash escapes decoded). */
export function sourceAlternatives(value:string):string[]{
 const out=[value];
 if(value.length>=2&&value[0]==='"'&&value.at(-1)==='"'){
  try{const parsed=JSON.parse(value);if(typeof parsed==='string')out.push(parsed);}catch{/* keep exact source */}
 }else if(value.length>=2&&value[0]==="'"&&value.at(-1)==="'")out.push(value.slice(1,-1));
 // The browser key=value reader decodes backslash escapes (`\=` -> `=`) while the backend span
 // evidence keeps the raw text, so a decoded form of the same value is also the same value.
 for(const item of [...out])if(item.includes('\\'))out.push(item.replace(/\\(.)/gs,'$1'));
 return [...new Set(out)];
}
