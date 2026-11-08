/** Exact output namespace policy for generated Ruby.
 * Only printable ASCII manufacturer identities are supported; do not change
 * the UTF-8 policy for raw logs, source field names or event values.
 */
const MANUFACTURER=/^[A-Za-z0-9][A-Za-z0-9 ._&()\-]*$/;
const UNSAFE_ROOTS=new Set(['__proto__','prototype','constructor']);
export function validManufacturerNamespace(value:string):boolean {
  return value.length>=1&&value.length<=128&&value===value.trim()&&
    MANUFACTURER.test(value)&&!UNSAFE_ROOTS.has(value);
}
