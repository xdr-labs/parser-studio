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
  return matched&&Number.isFinite(Date.parse(value));
}
