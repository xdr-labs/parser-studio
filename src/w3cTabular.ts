const UNSAFE_W3C_FIELDS=new Set(['__proto__','constructor','prototype']);

export interface W3cSchema{
  fields:string[];
  delimiter:'space';
}

function safeField(value:string):boolean{
  return /^[A-Za-z][A-Za-z0-9_.()\/-]{0,127}$/.test(value)&&!UNSAFE_W3C_FIELDS.has(value);
}

export function parseW3cFieldsHeader(raw:string):W3cSchema|null{
  if(!raw.startsWith('#Fields: ')||raw.includes('\0')||/[\r\n]/.test(raw))return null;
  if(new TextEncoder().encode(raw).byteLength>8192)return null;
  const fields=raw.slice(9).trim().split(/ +/);
  if(fields.length<1||fields.length>128||fields.some(field=>!safeField(field)))return null;
  if(new Set(fields).size!==fields.length)return null;
  return {fields,delimiter:'space'};
}

function splitQuotedSpaceRow(raw:string):string[]|null{
  const values:string[]=[];let token='',quote='',escaped=false;
  for(let index=0;index<raw.length;index++){
    const ch=raw[index]!;
    if(quote){
      if(escaped){token+=ch;escaped=false;continue;}
      if(ch==='\\'){escaped=true;continue;}
      if(ch===quote){quote='';continue;}
      token+=ch;continue;
    }
    if(ch==='"'||ch==="'"){quote=ch;continue;}
    if(ch===' '||ch==='\t'){
      if(token){values.push(token);token='';}
      continue;
    }
    token+=ch;
  }
  if(quote||escaped)return null;
  if(token)values.push(token);
  return values;
}

export function mapW3cRow(raw:string,schema:W3cSchema):Record<string,string>|null{
  if(raw.startsWith('#')||raw.includes('\0')||/[\r\n]/.test(raw)||new TextEncoder().encode(raw).byteLength>8192)return null;
  if(schema.delimiter!=='space'||schema.fields.length<1||schema.fields.length>128||
     schema.fields.some(field=>!safeField(field))||new Set(schema.fields).size!==schema.fields.length)return null;
  const values=splitQuotedSpaceRow(raw);
  if(!values||values.length!==schema.fields.length)return null;
  const fields:Record<string,string>=Object.create(null);
  for(let index=0;index<schema.fields.length;index++){
    const key=schema.fields[index]!,value=values[index]!;
    if(new TextEncoder().encode(value).byteLength>2048)return null;
    fields[key]=value;
  }
  return fields;
}
