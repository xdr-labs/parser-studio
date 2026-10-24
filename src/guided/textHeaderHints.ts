/** Value-free observations of bounded, common free-text header layouts.
 * These describe syntax, not vendor semantics or a verified native parser.
 * All raw source values remain only in the existing original-source prompt.
 */
export type TextHeaderShape='BRACKET_MONTH_DAY_PROCESS_TARGET'|'SIX_DIGIT_DATE_TIME_SEVERITY_COMPONENT'|'ANDROID_LOGCAT_THREADTIME';
export interface TextHeaderHints{
 contract:'parser-studio.text-header-hints.v0.1';
 inspectedRecords:number;
 matchedHeaderRecords:number;
 patterns:Array<{shape:TextHeaderShape;records:number;availableUnverifiedNames:string[]}>;
 messageSemanticsVerified:false;
 dateYearOrTimezoneInferred:false;
 nativeParserVerified:false;
}
// Anchored bounded patterns mirror only the grammar classes that
// were independently corroborated in the private 24k-line Loghub benchmark.
const BRACKET=/^\[(\d{2})\.(\d{2}) (\d{2}):(\d{2}):(\d{2})\] [^\r\n\[\]]{1,128} - [^\r\n]+$/;
const DATECODE=/^(\d{2})(\d{2})(\d{2}) (\d{2})(\d{2})(\d{2}) \d{1,8} (?:TRACE|DEBUG|INFO|WARN|ERROR|FATAL) [A-Za-z_][A-Za-z0-9_.$/-]{0,159}: [^\r\n]+$/;
const LOGCAT=/^(\d{2})-(\d{2}) (\d{2}):(\d{2}):(\d{2})\.\d{3}[ \t]+\d{1,7}[ \t]+\d{1,7} [VDIWEFS] [A-Za-z0-9_.$/\-]{1,96}: [^\r\n]+$/;
function validClock(hour:string,minute:string,second:string):boolean{
 return Number(hour)<=23&&Number(minute)<=59&&Number(second)<=60;
}
const days=[0,31,29,31,30,31,30,31,31,30,31,30,31] as const;
function validMonthDay(month:string,day:string):boolean{
 const m=Number(month);return m>=1&&m<=12&&Number(day)>=1&&Number(day)<=days[m]!;
}

export function inferTextHeaderHints(source:string):TextHeaderHints|null{
 if(!source||source.includes('\r')||source.includes('\x00')||
   new TextEncoder().encode(source).byteLength>65536)return null;
 const lines=source.split('\n').filter(line=>line.length>0);
 if(!lines.length||lines.length>500||lines.some(line=>line.length>8192))return null;
 let bracket=0,datecode=0,logcat=0;
 for(const line of lines){
  const b=BRACKET.exec(line);
  const h=DATECODE.exec(line);
  const a=LOGCAT.exec(line);
  if(b&&validMonthDay(b[1]!,b[2]!)&&validClock(b[3]!,b[4]!,b[5]!))bracket++;
  else if(h&&validMonthDay(h[2]!,h[3]!)&&validClock(h[4]!,h[5]!,h[6]!))datecode++;
  else if(a&&validMonthDay(a[1]!,a[2]!)&&validClock(a[3]!,a[4]!,a[5]!))logcat++;
 }
 if(!bracket&&!datecode&&!logcat)return null;
 const patterns:TextHeaderHints['patterns']=[];
 if(bracket)patterns.push({shape:'BRACKET_MONTH_DAY_PROCESS_TARGET',records:bracket,
   availableUnverifiedNames:['month_day_text','clock_text','application','message']});
 if(datecode)patterns.push({shape:'SIX_DIGIT_DATE_TIME_SEVERITY_COMPONENT',records:datecode,
   availableUnverifiedNames:['datecode_text','clockcode_text','pid','severity','component','message']});
 if(logcat)patterns.push({shape:'ANDROID_LOGCAT_THREADTIME',records:logcat,
   availableUnverifiedNames:['month_day_text','clock_text','pid','tid','priority','tag','message']});
 return {contract:'parser-studio.text-header-hints.v0.1',
   inspectedRecords:lines.length,matchedHeaderRecords:bracket+datecode+logcat,patterns,
   messageSemanticsVerified:false,dateYearOrTimezoneInferred:false,nativeParserVerified:false};
}
