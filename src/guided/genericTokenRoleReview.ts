import type {MultiPassSourcePreview} from './multipassPreviewClient';

/** Structural token coverage must not imply that field roles were identified. */
export function hasUnlabeledGenericPositions(
  preview:Pick<MultiPassSourcePreview,'status'|'fields'>
):boolean{
  if(preview.status!=='SOURCE_PARSED')return false;
  const keys=Object.keys(preview.fields);
  if(!keys.includes('generic')||keys.some(key=>key!=='generic'&&key!=='syslog'))
    return false;
  const generic=preview.fields.generic;
  if(!generic||typeof generic!=='object'||Array.isArray(generic))return false;
  const tokens=(generic as Record<string,unknown>).tokens;
  return Array.isArray(tokens)&&tokens.some(token=>typeof token==='string'&&token.length>0);
}
