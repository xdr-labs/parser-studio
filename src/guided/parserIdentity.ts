const SAFE_PART=/[^a-z0-9]+/g;

function slugPart(value:string):string{
  return value.normalize('NFKD').toLowerCase()
    .replace(/[\u0300-\u036f]/g,'')
    .replace(SAFE_PART,'_').replace(/^_+|_+$/g,'');
}

/** Matches the parser-project schema maximum for vendor and product (128 characters). */
export const MAX_PARSER_IDENTITY_TEXT=128;
const MAX_SLUG=48;
const MAX_PRODUCT_PART=24;

/** Match Stellar custom-parser naming convention: customized_<vendor>_<product>. */
export function parserIdentitySlug(vendor:string,product:string):string{
  let vendorPart=slugPart(vendor),productPart=slugPart(product);
  if(vendorPart&&productPart&&vendorPart.length+1+productPart.length>MAX_SLUG){
    // Keep the product recognisable: a very long manufacturer must not erase it.
    productPart=productPart.slice(0,MAX_PRODUCT_PART).replace(/_+$/,'');
    vendorPart=vendorPart.slice(0,MAX_SLUG-1-productPart.length).replace(/_+$/,'');
  }
  const combined=[vendorPart,productPart].filter(Boolean).join('_');
  let slug=combined||'parser_product';
  if(!/^[a-z]/.test(slug))slug='parser_'+slug;
  slug=slug.replace(/_+/g,'_').slice(0,48).replace(/_+$/,'');
  if(slug.length<2)slug=(slug+'_parser').slice(0,48);
  return slug;
}

export function parserArtifactBaseName(vendor:string,product:string):string{
  return 'customized_'+parserIdentitySlug(vendor,product);
}

/** Plain-language reason when the manufacturer or product is blank (the project schema requires both). */
export function missingParserIdentityMessage(vendor:string,product:string):string|null{
  const noVendor=!vendor.trim(),noProduct=!product.trim();
  if(noVendor&&noProduct)return 'Enter the manufacturer and product name first. They are used in the parser file names.';
  if(noVendor)return 'Enter the manufacturer first. It is used in the parser file names.';
  if(noProduct)return 'Enter the product name first. It is used in the parser file names.';
  return null;
}

export const PLACEHOLDER_PARSER_VENDOR='Demo Local Draft';
export const PLACEHOLDER_PARSER_PRODUCT='Untitled parser';

/** Which of the two demo placeholders is still in place (blank counts as unset too). */
export function placeholderParserIdentityParts(vendor:string,product:string):('manufacturer'|'product')[]{
  const parts:('manufacturer'|'product')[]=[];
  if(!vendor.trim()||vendor===PLACEHOLDER_PARSER_VENDOR)parts.push('manufacturer');
  if(!product.trim()||product===PLACEHOLDER_PARSER_PRODUCT)parts.push('product');
  return parts;
}
