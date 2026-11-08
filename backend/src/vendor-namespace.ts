/** Manufacturer is a literal top-level output key in generated Ruby.
 * Preserve visible Unicode names; reject controls, format/invisible chars,
 * surrogates and line separators rather than silently rewriting field keys.
 */
const NON_PRINTING=/[\p{Cc}\p{Cf}\p{Cs}\p{Zl}\p{Zp}]/u;
const UNSAFE_ROOTS=new Set(["__proto__","prototype","constructor"]);
export function validManufacturerNamespace(value:string):boolean{
  return value.length>=1&&value.length<=128&&value===value.trim()&&
    !NON_PRINTING.test(value)&&!UNSAFE_ROOTS.has(value);
}
