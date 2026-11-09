import policy from '../../runtime/multipass/semantic-policy.v1.json';

const TRANSLATED=new Set(policy.excludedPortSourceSegments);
/** Split each path segment into independent semantic tokens. Dots are source
 * hierarchy; hyphen/underscore/camelCase variants represent the same NAT role.
 * Do not block unrelated names like `national` or `natural`.
 */
export function sourceHasExcludedPortSegment(source:string):boolean{
  return source.split('.').some(segment=>{
    const normalized=segment.replace(/([a-z0-9])([A-Z])/g,'$1_$2').toLowerCase();
    const words=normalized.split(/[-_]+/).filter(Boolean);
    return words.some(word=>TRANSLATED.has(word));
  });
}
export function explicitPortSourceAlias(source:string,target:string):boolean{
  const leaf=source.split('.').at(-1)?.toLowerCase();
  return !sourceHasExcludedPortSegment(source)&&leaf!==undefined&&
    policy.explicitPortSourceAliases[
      leaf as keyof typeof policy.explicitPortSourceAliases]===target;
}
