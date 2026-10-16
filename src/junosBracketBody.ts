export interface JunosBracketEvent{
  appname:string;
  procid:string;
  msgid:string;
  structuredDataRaw:string;
  fields:Record<string,string>;
}

const UNSAFE=new Set(['__proto__','constructor','prototype']);

export function parseJunosBracketAttributes(raw:string):Record<string,string>|null{
  if(!raw.startsWith('[junos@')||!raw.endsWith(']')||raw.includes('\0')||
     /[\r\n]/.test(raw)||new TextEncoder().encode(raw).byteLength>8192)return null;
  const inner=raw.slice(1,-1);
  const head=/^junos@[A-Za-z0-9.:-]{1,64}/.exec(inner);
  if(!head)return null;
  let pos=head[0].length;
  const fields:Record<string,string>=Object.create(null);
  while(pos<inner.length){
    if(inner[pos]!==' ')return null;
    pos++;
    const keyMatch=/^[A-Za-z_][A-Za-z0-9_-]{0,63}/.exec(inner.slice(pos));
    if(!keyMatch)return null;
    const key=keyMatch[0]!;
    pos+=key.length;
    if(inner.slice(pos,pos+2)!=='="')return null;
    pos+=2;
    let value='',closed=false;
    while(pos<inner.length){
      const ch=inner[pos]!;
      if(ch==='"'){pos++;closed=true;break;}
      if(ch==='\\'){
        const next=inner[pos+1];
        if(next===undefined||!['"','\\',']'].includes(next))return null;
        value+=next;pos+=2;continue;
      }
      if(ch.charCodeAt(0)<32||ch.charCodeAt(0)===127)return null;
      value+=ch;pos++;
    }
    if(!closed)return null;
    const normalized=key.replaceAll('-','_');
    if(UNSAFE.has(key)||UNSAFE.has(normalized)||
       Object.prototype.hasOwnProperty.call(fields,normalized))return null;
    fields[normalized]=value;
    if(Object.keys(fields).length>64)return null;
  }
  return Object.keys(fields).length>0?fields:null;
}

export function parseJunosBracketEvent(message:string):JunosBracketEvent|null{
  const marker=message.indexOf(' [junos@');
  if(marker<0||message.indexOf(' [junos@',marker+1)>=0)return null;
  const parts=message.slice(0,marker).split(' ');
  if(parts.length!==3||!/^RT_[A-Z0-9_]{1,40}$/.test(parts[0]??'')||
     parts[1]!=='-'||!/^[A-Z][A-Z0-9_]{2,79}$/.test(parts[2]??''))return null;
  const structuredDataRaw=message.slice(marker+1);
  const fields=parseJunosBracketAttributes(structuredDataRaw);
  return fields?{appname:parts[0]!,procid:parts[1]!,msgid:parts[2]!,structuredDataRaw,fields}:null;
}
