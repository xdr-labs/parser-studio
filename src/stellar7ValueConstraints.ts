/** Semantic checks for manually selected Stellar Cyber 7.0 scalar fields.
 *
 * This does NOT validate a source's vendor meaning or a target deployment.
 * It only prevents a typed value from silently violating a stronger, known
 * official destination constraint after the user bypasses a suggestion.
 * Kept independent of the parser to avoid cyclic imports in normalizer UI.
 */
export function meetsStellar7ValueConstraints(
  target:string,raw:unknown,converted:unknown,
):boolean{
  const hash=/(?:^|\.)(md5|sha1|sha256)$/.exec(target)?.[1];
  if(hash){
    const widths:Record<string,number>={md5:32,sha1:40,sha256:64};
    return typeof raw==='string'&&
      new RegExp('^[0-9a-fA-F]{'+widths[hash]+'}$').test(raw);
  }
  if(target==='action')return typeof raw==='string';
  if(target==='proto')return typeof converted==='number'&&
    Number.isInteger(converted)&&converted>=0&&converted<=255;
  if(target==='proto_name')return typeof raw==='string'&&
    ['tcp','udp','icmp','igmp'].includes(raw.trim().toLowerCase());

  if(target==='srcport'||target==='dstport')
    return typeof converted==='number'&&Number.isInteger(converted)&&
      converted>=0&&converted<=65535;
  if(target==='severity')
    return typeof converted==='number'&&Number.isInteger(converted)&&
      converted>=0&&converted<=100;
  return true;
}

/** Official IP protocol assignments for the supported transport names. */
export function officialProtocolPairConflict(proto:unknown,protoName:unknown):boolean{
  if(proto===undefined||proto===null||protoName===undefined||protoName===null)return false;
  const codes:Record<string,number[]>={tcp:[6],udp:[17],icmp:[1,58],igmp:[2]};
  const allowed=typeof protoName==='string'?codes[protoName.trim().toLowerCase()]:undefined;
  return !allowed||!allowed.includes(Number(proto));
}
