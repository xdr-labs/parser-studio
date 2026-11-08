/** Canonical, browser-safe scalar coercion and calendar semantics. */
import officialTypes from './stellar7-enrichment-types.json' with {type:'json'};
export type CanonicalValueType='string'|'integer'|'number'|'boolean'|'port'|'ip'|'timestamp';
/** Reject impossible ISO calendar dates before Date.parse normalizes them.
 * Keep timezone interpretation in the existing explicit-offset parser. */
export function validIsoCalendarDate(value:string):boolean{
  const match=/^(\d{4})-(\d{2})-(\d{2})T/.exec(value);
  if(!match)return false;
  const year=Number(match[1]),month=Number(match[2]),day=Number(match[3]);
  if(year<1||month<1||month>12||day<1)return false;
  const leap=year%4===0&&(year%100!==0||year%400===0);
  const days=[31,leap?29:28,31,30,31,30,31,31,30,31,30,31];
  return day<=days[month-1]!;
}


/** ISO timestamp subset shared with the generated Ruby coercion contract.
 * Do not let Date.parse or Time.iso8601 repair invalid clock components. */
export function validIsoTimestamp(value:string):boolean{
  if(!validIsoCalendarDate(value))return false;
  const matched=/^\d{4}-\d{2}-\d{2}T(?:[01]\d|2[0-3]):[0-5]\d:[0-5]\d(?:\.\d{1,9})?(?:Z|[+-](?:[01]\d|2[0-3]):[0-5]\d)$/.test(value);
  if(!matched||!Number.isFinite(Date.parse(value)))return false;
  const utc=new Date(value).toISOString();
  return /^[0-9]{4}-/.test(utc)&&Number(utc.slice(0,4))>=1;
}

function asIPv4(value: string): boolean {
  const parts = value.split('.');
  return parts.length === 4 && parts.every(part =>
    /^(?:0|[1-9]\d{0,2})$/.test(part) && Number(part) <= 255);
}

function asIP(value: string): boolean {
  if (!value.includes(':')) return asIPv4(value);
  // RFC 4291: exactly eight 16-bit groups, optionally shortened once by ::.
  // A dotted IPv4 tail consumes two groups. Reject zones and URL brackets:
  // neither is a literal IP value in the normalized Stellar metadata field.
  if (value.length > 45 || !/^[0-9a-fA-F:.]+$/.test(value)) return false;
  let address = value;
  if (address.includes('.')) {
    const separator = address.lastIndexOf(':');
    if (separator === -1 || !asIPv4(address.slice(separator + 1))) return false;
    address = address.slice(0, separator + 1) + '0:0';
  }
  const halves = address.split('::');
  if (halves.length > 2) return false;
  const groups = (text: string) => text ? text.split(':') : [];
  const left = groups(halves[0]!);
  const right = halves.length === 2 ? groups(halves[1]!) : [];
  const validGroup = (group: string) => /^[0-9a-fA-F]{1,4}$/.test(group);
  if (![...left, ...right].every(validGroup)) return false;
  const explicitGroups = left.length + right.length;
  return halves.length === 2 ? explicitGroups < 8 : explicitGroups === 8;
}

// Native Ruby String#strip trims ASCII whitespace, not NBSP/BOM/EM SPACE.
 // This is typed-value handling, never a mutation of the original field.
export const trimCanonicalAscii=(value:string):string=>value.replace(
  /^[ \t\n\r\f\v]+|[ \t\n\r\f\v]+$/g,'');

export function coerceCanonicalValue(raw: unknown, type: CanonicalValueType): { value?: unknown; error?: string } {
  if (raw === undefined || raw === null ||
      (typeof raw === 'string' && !trimCanonicalAscii(raw))) return { error: 'Missing value' };
  if(type==='string'&&typeof raw==='object')return {value:JSON.stringify(raw)};
  if(typeof raw==='object')return {error:'Expected scalar value'};
  const value = typeof raw === 'string' ? trimCanonicalAscii(raw) : String(raw);
  switch (type) {
    case 'string':
      return { value: typeof raw === 'object' ? JSON.stringify(raw) : String(raw) };
    case 'integer':
      return /^-?\d+$/.test(value) && Number.isSafeInteger(Number(value)) ? { value: Number(value) } : { error: 'Expected safe integer' };
    case 'number':
      return value !== '' && Number.isFinite(Number(value)) ? { value: Number(value) } : { error: 'Expected finite number' };
    case 'boolean':
      if (/^(?:true|1)$/i.test(value)) return { value: true };
      if (/^(?:false|0)$/i.test(value)) return { value: false };
      return { error: 'Expected boolean (true/false/1/0)' };
    case 'port':
      return /^\d+$/.test(value) && Number(value) <= 65535 ? { value: Number(value) } : { error: 'Expected port 0..65535' };
    case 'ip':
      return asIP(value) ? { value } : { error: 'Expected valid IP address' };
    case 'timestamp':
      return validIsoTimestamp(value)
        ? { value: new Date(value).toISOString() } : { error: 'Expected ISO timestamp with explicit timezone' };
  }
}

/** Validate the final scalar against the pinned destination type as well as
 * the author's declared source coercion. Unknown vendor extensions stay free. */
export function canonicalOfficialScalarValid(target:string,value:unknown):boolean{
  if(!Object.prototype.hasOwnProperty.call(officialTypes,target))return true;
  const kind=(officialTypes as Record<string,string>)[target];
  if(kind==='string')return typeof value==='string';
  if(kind==='integer')return typeof value==='number'&&Number.isSafeInteger(value);
  if(kind==='port')return typeof value==='number'&&Number.isSafeInteger(value)&&value>=0&&value<=65535;
  if(kind==='number')return typeof value==='number'&&Number.isFinite(value);
  if(kind==='boolean')return typeof value==='boolean';
  if(kind==='timestamp')return typeof value==='string'&&validIsoTimestamp(value);
  if(kind==='ip')return typeof value==='string'&&asIP(value);
  return false;
}
