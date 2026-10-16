const UNSAFE_ZEEK_FIELDS=new Set(['__proto__','constructor','prototype']);

export interface ZeekTsvSchema{
  fields:string[];
  separator:'\t';
}

function safeField(value:string):boolean{
  return /^[A-Za-z_][A-Za-z0-9_.-]{0,127}$/.test(value)&&!UNSAFE_ZEEK_FIELDS.has(value);
}

export function parseZeekFieldsHeader(raw:string):ZeekTsvSchema|null{
  if(!raw.startsWith('#fields\t')||raw.includes('\0')||/[\r\n]/.test(raw))return null;
  if(new TextEncoder().encode(raw).byteLength>8192)return null;
  const fields=raw.split('\t').slice(1);
  if(fields.length<6||fields.length>128||fields.some(field=>!safeField(field)))return null;
  if(new Set(fields).size!==fields.length)return null;
  return {fields,separator:'\t'};
}

export function mapZeekTsvRow(raw:string,schema:ZeekTsvSchema):Record<string,string>|null{
  if(raw.includes('\0')||/[\r\n]/.test(raw)||new TextEncoder().encode(raw).byteLength>8192)return null;
  if(schema.separator!=='\t'||schema.fields.length<6||schema.fields.length>128||
     schema.fields.some(field=>!safeField(field))||new Set(schema.fields).size!==schema.fields.length)return null;
  const values=raw.split('\t');
  if(values.length!==schema.fields.length)return null;
  const fields:Record<string,string>=Object.create(null);
  for(let index=0;index<schema.fields.length;index++){
    const key=schema.fields[index]!,value=values[index]!;
    if(new TextEncoder().encode(value).byteLength>2048)return null;
    fields[key]=value;
  }
  return fields;
}
