export function isIpv4Token(value:string):boolean{
  const parts=value.split('.');
  return parts.length===4&&parts.every(part=>
    /^\d{1,3}$/.test(part)&&Number(part)>=0&&Number(part)<=255
  );
}

export function isIpv6Token(input:string):boolean{
  if(!input.includes(':')||input.includes('%')||input.includes('[')||input.includes(']'))return false;
  if(input.indexOf('::')!==input.lastIndexOf('::'))return false;

  let value=input;
  if(value.includes('.')){
    const colon=value.lastIndexOf(':');
    if(colon<0)return false;
    const tail=value.slice(colon+1);
    if(!isIpv4Token(tail))return false;
    value=value.slice(0,colon+1)+'0:0';
  }
  if(!/^[0-9A-Fa-f:]+$/.test(value))return false;

  const compressed=value.includes('::');
  const sides=value.split('::');
  if(sides.length>2)return false;
  const left=sides[0]?sides[0]!.split(':'):[];
  const right=sides.length===2&&sides[1]?sides[1]!.split(':'):[];
  const groups=[...left,...right];
  if(groups.some(group=>!/^[0-9A-Fa-f]{1,4}$/.test(group)))return false;
  return compressed?groups.length<8:groups.length===8;
}

export function isIpToken(value:string):boolean{
  return isIpv4Token(value)||isIpv6Token(value);
}

export function isPortToken(value:string):boolean{
  if(!/^\d{1,5}$/.test(value))return false;
  const port=Number(value);
  return Number.isInteger(port)&&port>=0&&port<=65535;
}

export function isIpPortToken(value:string,allowDash=false):boolean{
  if(allowDash&&value==='-')return true;
  let host='',port='';
  const bracketed=/^\[([^\]]+)\]:(\d{1,5})$/.exec(value);
  if(bracketed){host=bracketed[1]!;port=bracketed[2]!;}
  else{
    const colon=value.lastIndexOf(':');
    if(colon<=0)return false;
    host=value.slice(0,colon);port=value.slice(colon+1);
  }
  return isIpToken(host)&&isPortToken(port);
}
