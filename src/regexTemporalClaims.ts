/** Source-supported validation for explicitly named partial date/time captures.
 * A regex match is not evidence that a numeric calendar value is meaningful.
 * This checks only conventional month_day (MM.DD or MM-DD) and clock
 * (HH:MM:SS with optional fractional seconds) fields. It does not infer
 * year, timezone, vendor event semantics or validate arbitrary field names.
 */
export function validateConventionalTemporalCaptures(
  fields: Record<string,string>,
): string|null {
  if (Object.prototype.hasOwnProperty.call(fields,'month_day')) {
    const value=fields.month_day;
    const parts=typeof value==='string'?
      /^(\d{2})[.-](\d{2})$/.exec(value):null;
    if(!parts)return 'Invalid month_day capture';
    const month=Number(parts[1]),day=Number(parts[2]);
    // Without a year, February 29 stays reviewable. Never invent a year.
    const maximum=[0,31,29,31,30,31,30,31,31,30,31,30,31];
    if(month<1||month>12||day<1||day>maximum[month])
      return 'Invalid month_day capture';
  }
  if (Object.prototype.hasOwnProperty.call(fields,'clock')) {
    const value=fields.clock;
    const parts=typeof value==='string'?
      /^(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,9})?$/.exec(value):null;
    if(!parts)return 'Invalid clock capture';
    const [hour,minute,second]=[Number(parts[1]),Number(parts[2]),Number(parts[3])];
    // A possible leap second is not itself proof of a timezone or date.
    if(hour>23||minute>59||second>60)return 'Invalid clock capture';
  }
  return null;
}
