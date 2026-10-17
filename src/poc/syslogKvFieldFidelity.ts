/** PoC-only, source KV name/value fidelity. Not semantic or native approval. */
const keyRule=/^[A-Za-z_][A-Za-z0-9_.-]{0,127}$/;
const unsafe=new Set(['__proto__','constructor','prototype']);

export interface KvFieldScore {
  expected:number;extracted:number;exact:number;wrongValue:number;
  missing:number;unexpected:number;exactNameSet:boolean;exactEvent:boolean;
}

/** Refuse ambiguous, duplicate or malformed independent reference entries. */
export function sourceKvReference(value:unknown):Map<string,string>{
  if(!Array.isArray(value)||value.length<2||value.length>256)
    throw Error('Unscoreable independent KV field count');
  const names=new Set<string>();
  const out=new Map<string,string>();
  for(const item of value){
    if(!Array.isArray(item)||item.length!==2)
      throw Error('Unscoreable independent KV token');
    const [key,field]=item as unknown[];
    if(typeof key!=='string'||!keyRule.test(key)||unsafe.has(key)||
       typeof field!=='string'||field.includes('\0')||/[\r\n]/.test(field))
      throw Error('Unsafe or invalid independent KV source field');
    const canonical=key.replaceAll('-','_');
    if(names.has(canonical))throw Error('Ambiguous independent KV source name');
    names.add(canonical);
    out.set(key,field);
  }
  return out;
}

/** Wrong values count as both a false positive and a false negative. */
export function scoreKvFields(expected:ReadonlyMap<string,string>,candidate:unknown):KvFieldScore{
  if(expected.size<2||expected.size>256)
    throw Error('Expected KV source denominator must be nonempty and bounded');
  const actual=candidate!==null&&typeof candidate==='object'&&!Array.isArray(candidate)
    ?new Map(Object.entries(candidate)):new Map<string,unknown>();
  let exact=0,wrongValue=0,missing=0,unexpected=0;
  for(const [key,value] of expected){
    if(!actual.has(key))missing++;
    else if(typeof actual.get(key)==='string'&&actual.get(key)===value)exact++;
    else wrongValue++;
  }
  for(const key of actual.keys())if(!expected.has(key))unexpected++;
  const extracted=actual.size;
  if(exact+wrongValue+missing!==expected.size||
     exact+wrongValue+unexpected!==extracted)
    throw Error('KV field scorer accounting invariant failed');
  return {
    expected:expected.size,extracted,exact,wrongValue,missing,unexpected,
    exactNameSet:missing===0&&unexpected===0,
    exactEvent:missing===0&&unexpected===0&&wrongValue===0,
  };
}
