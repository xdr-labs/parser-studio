import {utf8OriginalByteOffsets} from './utf8OriginalByteOffsets';
import {readCsvSourceCells} from './csvSourceCells';
export interface Rfc4180OriginalCellSpan{
  rowIndex:number;
  columnIndex:number;
  columnName:string;
  rawLexeme:string;
  decodedValue:string;
  quoted:boolean;
  startByte:number;
  endByte:number;
}
export interface Rfc4180OriginalRecordSpan{
  rowIndex:number;
  startByte:number;
  endByte:number;
  terminatorBytes:number;
  physicalLines:number;
}
export interface Rfc4180CsvTable{
  header:string[];
  rows:Array<Record<string,string>>;
  rawRows:string[][];
  lineEnding:'lf'|'crlf'|'none';
  sourceBytes:number;
  headerFieldSpans:Rfc4180OriginalCellSpan[];
  rowFieldSpans:Rfc4180OriginalCellSpan[][];
  recordSourceSpans:Rfc4180OriginalRecordSpan[];
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

interface CsvOriginalCell {
  rawLexeme:string;decodedValue:string;quoted:boolean;
  startByte:number;endByte:number;
}
interface CsvOriginalRecord {
  startByte:number;endByte:number;
  terminatorBytes:number;physicalLines:number;
}
function parseRows(raw:string):{
  rows:string[][];lineEnding:'lf'|'crlf'|'none';
  sourceBytes:number;
  sourceCells:CsvOriginalCell[][];
  sourceRecords:CsvOriginalRecord[];
}|null{
  // One grammar owns both decoded fields and original source intervals;
  // never parse a second time with a different delimiter/escape lexer.
  const byteOffsets=utf8OriginalByteOffsets(raw);
  if(!byteOffsets)return null;
  const sourceBytes=byteOffsets[raw.length]!;
  const original=new TextEncoder().encode(raw);
  if(sourceBytes!==original.length)return null;
  const decoder=new TextDecoder('utf-8',{fatal:true});
  const rows:string[][]=[];
  const sourceCells:CsvOriginalCell[][]=[];
  const sourceRecords:CsvOriginalRecord[]=[];
  let row:string[]=[],currentCells:CsvOriginalCell[]=[];
  let field='',quoted=false,afterQuote=false,fieldStarted=false,fieldQuoted=false;
  let fieldStart=0,rowStart=0,physicalLines=1;
  let lineEnding:'lf'|'crlf'|'none'='none';

  const commitField=(endChar:number):boolean=>{
    if(bytes(field)>MAX_FIELD_BYTES||endChar<fieldStart)return false;
    const startByte=byteOffsets[fieldStart]!;
    const endByte=byteOffsets[endChar]!;
    const rawLexeme=raw.slice(fieldStart,endChar);
    if(decoder.decode(original.subarray(startByte,endByte))!==rawLexeme)
      return false;
    row.push(field);
    currentCells.push({
      rawLexeme,decodedValue:field,quoted:fieldQuoted,
      startByte,endByte,
    });
    field='';quoted=false;afterQuote=false;fieldStarted=false;fieldQuoted=false;
    return row.length<=MAX_COLUMNS;
  };
  const commitRow=(endChar:number,terminatorChars:number):boolean=>{
    if(!commitField(endChar)||!row.length)return false;
    rows.push(row);
    sourceCells.push(currentCells);
    const startByte=byteOffsets[rowStart]!;
    const endByte=byteOffsets[endChar]!;
    const nextChar=endChar+terminatorChars;
    if(nextChar>raw.length)return false;
    const terminatorBytes=byteOffsets[nextChar]!-endByte;
    sourceRecords.push({
      startByte,endByte,terminatorBytes,physicalLines,
    });
    row=[];currentCells=[];physicalLines=1;
    rowStart=nextChar;fieldStart=nextChar;
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
        // RFC4180 escaped fields allow CR, LF and CRLF source bytes.
        field+='\r';
        if(raw[index+1]==='\n'){field+='\n';index++;}
        physicalLines++;continue;
      }
      if(ch==='\n'){field+='\n';physicalLines++;continue;}
      const code=ch.charCodeAt(0);
      if(code<32||code===127)return null;
      field+=ch;continue;
    }
    if(afterQuote){
      if(ch===','){
        if(!commitField(index))return null;
        fieldStart=index+1;continue;
      }
      if(ch==='\r'||ch==='\n'){
        const recordEnd=index;
        const terminatorChars=ch==='\r'?2:1;
        if(ch==='\r'){
          if(raw[index+1]!=='\n'||lineEnding==='lf')return null;
          index++;lineEnding='crlf';
        }else {
          if(lineEnding==='crlf')return null;
          lineEnding='lf';
        }
        if(!commitRow(recordEnd,terminatorChars))return null;
        continue;
      }
      return null;
    }
    if(ch==='"'){
      if(fieldStarted)return null;
      quoted=true;fieldStarted=true;fieldQuoted=true;continue;
    }
    if(ch===','){
      if(!commitField(index))return null;
      fieldStart=index+1;continue;
    }
    if(ch==='\r'||ch==='\n'){
      const recordEnd=index;
      const terminatorChars=ch==='\r'?2:1;
      if(ch==='\r'){
        if(raw[index+1]!=='\n'||lineEnding==='lf')return null;
        index++;lineEnding='crlf';
      }else{
        if(lineEnding==='crlf')return null;
        lineEnding='lf';
      }
      if(!commitRow(recordEnd,terminatorChars))return null;
      continue;
    }
    if(ch.charCodeAt(0)<32||ch.charCodeAt(0)===127)return null;
    field+=ch;fieldStarted=true;
  }
  if(quoted)return null;
  if(afterQuote||fieldStarted||row.length){
    if(!commitRow(raw.length,0))return null;
  }
  if(!rows.length)return null;
  let consumed=0;
  for(const record of sourceRecords){
    if(record.startByte!==consumed||record.endByte<consumed)return null;
    consumed=record.endByte+record.terminatorBytes;
  }
  if(consumed!==sourceBytes)return null;
  return {rows,lineEnding,sourceBytes,sourceCells,sourceRecords};
}

export interface Rfc4180SingleDataRow{
  values:string[];
  quotedFields:number;
}

export function parseRfc4180SingleDataRow(raw:string,
  options?:{declaredPaddingAfterDelimiter?:boolean}):Rfc4180SingleDataRow|null{
  if(!raw||raw.includes('\0')||/[\r\n]/.test(raw)||bytes(raw)>64*1024)
    return null;
  const cells=readCsvSourceCells(raw,',',false,options);
  if(!cells||cells.some(x=>bytes(x.value??'')>MAX_FIELD_BYTES))return null;
  return {values:cells.map(x=>x.value??''),
    quotedFields:cells.filter(x=>x.quoted).length};
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
  const toFieldSpan=(cell:CsvOriginalCell,rowIndex:number,
    columnIndex:number):Rfc4180OriginalCellSpan=>({
      rowIndex,columnIndex,columnName:header[columnIndex]!,
      rawLexeme:cell.rawLexeme,decodedValue:cell.decodedValue,
      quoted:cell.quoted,startByte:cell.startByte,endByte:cell.endByte,
    });
  const headerFieldSpans=parsed.sourceCells[0]!.map((cell,index)=>
    toFieldSpan(cell,-1,index));
  const rowFieldSpans=parsed.sourceCells.slice(1).map((cells,rowIndex)=>
    cells.map((cell,index)=>toFieldSpan(cell,rowIndex,index)));
  const recordSourceSpans=parsed.sourceRecords.map((record,index)=>({
    ...record,rowIndex:index-1,
  }));
  return {ok:true,table:{
    header,rows,rawRows:dataRows,lineEnding:parsed.lineEnding,
    sourceBytes:parsed.sourceBytes,headerFieldSpans,rowFieldSpans,
    recordSourceSpans,
  }};
}
