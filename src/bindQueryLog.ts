import {parseBindQueryMessage} from './commonSecurityProfiles';

const MONTHS=['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'] as const;

function validDate(dayText:string,monthText:string,yearText:string,time:string):boolean{
  const month=MONTHS.indexOf(monthText as typeof MONTHS[number])+1;
  const year=Number(yearText),day=Number(dayText);
  const clock=/^(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,9})?$/.exec(time);
  if(month<1||year<1||year>9999||!clock||Number(clock[1])>23||Number(clock[2])>59||Number(clock[3])>59)return false;
  const leap=year%4===0&&(year%100!==0||year%400===0);
  const days=[31,leap?29:28,31,30,31,30,31,31,30,31,30,31];
  return day>=1&&day<=days[month-1]!;
}

export function parseBindQueryLog(raw:string):Record<string,unknown>|null{
  if(!raw||raw.includes('\0')||/[\r\n]/.test(raw)||new TextEncoder().encode(raw).byteLength>8192)return null;
  const match=/^(\d{1,2})-([A-Z][a-z]{2})-(\d{4}) +(\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?) +([A-Za-z0-9_.-]{1,64}): +([A-Za-z0-9_.-]{1,32}): +(.+)$/.exec(raw);
  if(!match||!validDate(match[1]!,match[2]!,match[3]!,match[4]!))return null;
  const query=parseBindQueryMessage(match[7]!);
  if(!query)return null;
  return {
    bind:{
      day:match[1],month:match[2],year:match[3],time:match[4],
      category:match[5],level:match[6],
      ...query,source_raw:raw,
    },
    generic:{mode:'bind_query_log',source_raw:raw},
  };
}

export function extractBindQueryMessage(raw:string):Record<string,unknown>|null{
  const query=parseBindQueryMessage(raw);
  return query?{
    bind_query:{...query,source_raw:raw},
    generic:{mode:'bind_query_message',source_raw:raw},
  }:null;
}
