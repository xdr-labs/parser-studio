export interface Rfc4180CsvTable{
  header:string[];
  rows:Array<Record<string,string>>;
  rawRows:string[][];
  lineEnding:'lf'|'crlf'|'none';
}

export type Rfc4180CsvResult=
  |{ok:true;table:Rfc4180CsvTable}
  |{ok:false;error:string};

const MAX_BYTES=1024*1024;
const MAX_ROWS=1000;
const MAX_COLUMNS=256;
const MAX_FIELD_BYTES=64*1024;
const UNSAFE_HEADERS=new Set(['__proto__','constructor','prototype']);

function bytes(value:string):number{return new TextEncoder().encode(value).byteLength;}

function safeHeader(value:string):boolean{
  return value===value.trim()&&
    /^[A-Za-z_][A-Za-z0-9_.:/()# -]{0,127}$/.test(value)&&
    !UNSAFE_HEADERS.has(value);
}

function parseRows(raw:string):{rows:string[][];lineEnding:'lf'|'crlf'|'none'}|null{
  const rows:string[][]=[];let row:string[]=[];let field='';
  let quoted=false,afterQuote=false,fieldStarted=false;
  let lineEnding:'lf'|'crlf'|'none'='none';
  const commitField=()=>{
    if(bytes(field)>MAX_FIELD_BYTES)return false;
    row.push(field);field='';quoted=false;afterQuote=false;fieldStarted=false;
    return row.length<=MAX_COLUMNS;
  };
  const commitRow=()=>{
    if(!commitField()||!row.length)return false;
    rows.push(row);row=[];
    return rows.length<=MAX_ROWS+1;
  };

  for(let index=0;index<raw.length;index++){
    const ch=raw[index]!;
    if(quoted){
      if(ch==='"'){
        if(raw[index+1]==='"'){field+='"';index++;continue;}
        quoted=false;afterQuote=true;continue;
      }
      if(ch==='\r'){
        if(raw[index+1]!=='\n')return null;
        field+='\r\n';index++;continue;
      }
      if(ch==='\n'){field+='\n';continue;}
      field+=ch;continue;
    }
    if(afterQuote){
      if(ch===','){if(!commitField())return null;continue;}
      if(ch==='\r'||ch==='\n'){
        if(ch==='\r'){if(raw[index+1]!=='\n')return null;index++;if(lineEnding==='lf')return null;lineEnding='crlf';}
        else {if(lineEnding==='crlf')return null;lineEnding='lf';}
        if(!commitRow())return null;continue;
      }
      return null;
    }
    if(ch==='"'){
      if(fieldStarted)return null;
      quoted=true;fieldStarted=true;continue;
    }
    if(ch===','){if(!commitField())return null;continue;}
    if(ch==='\r'||ch==='\n'){
      if(ch==='\r'){if(raw[index+1]!=='\n')return null;index++;if(lineEnding==='lf')return null;lineEnding='crlf';}
      else {if(lineEnding==='crlf')return null;lineEnding='lf';}
      if(!commitRow())return null;continue;
    }
    field+=ch;fieldStarted=true;
  }
  if(quoted)return null;
  if(afterQuote||fieldStarted||row.length){if(!commitRow())return null;}
  return rows.length?{rows,lineEnding}:null;
}

export interface Rfc4180SingleDataRow{
  values:string[];
  quotedFields:number;
}

export function parseRfc4180SingleDataRow(raw:string):Rfc4180SingleDataRow|null{
  if(!raw||raw.includes('\0')||/[\r\n]/.test(raw)||bytes(raw)>64*1024)return null;
  const values:string[]=[];let quotedFields=0,cursor=0;
  while(cursor<raw.length){
    if(values.length>0)while(raw[cursor]===' ')cursor++;
    let value='';
    if(raw[cursor]==='"'){
      quotedFields++;
      cursor++;
      let closed=false;
      while(cursor<raw.length){
        const ch=raw[cursor]!;
        if(ch==='"'){
          if(raw[cursor+1]==='"'){value+='"';cursor+=2;continue;}
          cursor++;closed=true;break;
        }
        value+=ch;cursor++;
      }
      if(!closed)return null;
      while(raw[cursor]===' ')cursor++;
      if(cursor<raw.length&&raw[cursor]!==',')return null;
    }else{
      while(cursor<raw.length&&raw[cursor]!==','){
        if(raw[cursor]==='"')return null;
        value+=raw[cursor]!;
        cursor++;
      }
    }
    if(bytes(value)>MAX_FIELD_BYTES)return null;
    values.push(value);
    if(values.length>MAX_COLUMNS)return null;
    if(cursor===raw.length)break;
    if(raw[cursor]!==',')return null;
    cursor++;
    if(cursor===raw.length){values.push('');break;}
  }
  return values.length?{values,quotedFields}:null;
}

export function parseRfc4180SingleQuotedRow(raw:string):string[]|null{
  const parsed=parseRfc4180SingleDataRow(raw);
  return parsed&&parsed.quotedFields===parsed.values.length?parsed.values:null;
}

export function parseRfc4180HeaderCsv(raw:string):Rfc4180CsvResult{
  if(!raw||raw.includes('\0')||bytes(raw)>MAX_BYTES)
    return {ok:false,error:'Invalid or oversized CSV input'};
  const parsed=parseRows(raw);
  if(!parsed||parsed.rows.length<2)return {ok:false,error:'CSV requires a header and at least one data row'};
  const [header,...dataRows]=parsed.rows;
  if(!header||header.length<2||header.length>MAX_COLUMNS||
     header.some(value=>!safeHeader(value))||new Set(header).size!==header.length)
    return {ok:false,error:'CSV header is unsafe or ambiguous'};
  if(dataRows.some(row=>row.length!==header.length))
    return {ok:false,error:'CSV row width does not match the header'};
  const rows:Array<Record<string,string>>=[];
  for(const values of dataRows){
    const record:Record<string,string>=Object.create(null);
    header.forEach((name,index)=>{record[name]=values[index]!;});
    rows.push(record);
  }
  return {ok:true,table:{header,rows,rawRows:dataRows,lineEnding:parsed.lineEnding}};
}
