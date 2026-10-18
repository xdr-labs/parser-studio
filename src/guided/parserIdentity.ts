const SAFE_PART=/[^a-z0-9]+/g;

function slugPart(value:string):string{
  return value.normalize('NFKD').toLowerCase()
    .replace(/[\u0300-\u036f]/g,'')
    .replace(SAFE_PART,'_').replace(/^_+|_+$/g,'');
}

/** Match Stellar custom-parser naming convention: customized_<vendor>_<product>. */
export function parserIdentitySlug(vendor:string,product:string):string{
  const combined=[slugPart(vendor),slugPart(product)].filter(Boolean).join('_');
  let slug=combined||'parser_product';
  if(!/^[a-z]/.test(slug))slug='parser_'+slug;
  slug=slug.replace(/_+/g,'_').slice(0,48).replace(/_+$/,'');
  if(slug.length<2)slug=(slug+'_parser').slice(0,48);
  return slug;
}

export function parserArtifactBaseName(vendor:string,product:string):string{
  return 'customized_'+parserIdentitySlug(vendor,product);
}
