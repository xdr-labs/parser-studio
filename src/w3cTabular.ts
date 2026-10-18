const UNSAFE_W3C_FIELDS=new Set(['__proto__','constructor','prototype']);

export interface W3cSchema{
  fields:string[];
  delimiter:'space'|'tab';
}

function safeField(value:string):boolean{
  return /^[A-Za-z][A-Za-z0-9_.()\/-]{0,127}$/.test(value)&&!UNSAFE_W3C_FIELDS.has(value);
}

export function parseW3cFieldsHeader(raw:string,delimiter:W3cSchema['delimiter']='space'):W3cSchema|null{
  if(!raw.startsWith('#Fields: ')||raw.includes('\0')||/[\r\n]/.test(raw))return null;
  if(new TextEncoder().encode(raw).byteLength>8192)return null;
  const fields=raw.slice(9).trim().split(/ +/);
  if(fields.length<1||fields.length>128||fields.some(field=>!safeField(field)))return null;
  if(new Set(fields).size!==fields.length)return null;
  if(delimiter!=='space'&&delimiter!=='tab')return null;
  return {fields,delimiter};
}

interface W3cLexicalCell {
  start:number;end:number;rawLexeme:string;decoded:string;
}

/** W3C EFL strings use doubled quotes; backslash is literal, not a C escape. */
function scanW3cRowCells(raw:string,delimiter:W3cSchema['delimiter']):W3cLexicalCell[]|null{
  const cells:W3cLexicalCell[]=[];
  const tabMode=delimiter==='tab';
  const separator=(c:string|undefined)=>tabMode?c==='\t':c===' ';
  const badControl=(c:string)=>{
    const code=c.charCodeAt(0);
    return code<32||code===127;
  };
  if(raw.includes('\0')||/[\r\n]/.test(raw))return null;
  let pos=0;
  while(pos<raw.length){
    if(cells.length>=128)return null;
    if(!tabMode){while(raw[pos]===' ')pos++;}
    if(pos===raw.length)break;
    const start=pos;
    let decoded='';
    if(raw[pos]==='"'){
      pos++;
      let terminated=false;
      while(pos<raw.length){
        const c=raw[pos++]!;
        if(c==='"'){
          if(raw[pos]==='"'){decoded+='"';pos++;continue;}
          terminated=true;break;
        }
        // A field control byte is never "decoded" by guessing a producer.
        if(badControl(c))return null;
        decoded+=c;
      }
      if(!terminated||(pos<raw.length&&!separator(raw[pos])))return null;
    }else{
      while(pos<raw.length&&!separator(raw[pos])){
        const c=raw[pos]!;
        if(c==='"'||badControl(c))return null;
        decoded+=c;pos++;
      }
    }
    cells.push({start,end:pos,rawLexeme:raw.slice(start,pos),decoded});
    if(pos===raw.length)break;
    if(tabMode){pos++;if(pos===raw.length){
      cells.push({start:pos,end:pos,rawLexeme:'',decoded:''});break;
    }}else{while(raw[pos]===' ')pos++;}
  }
  if(!cells.length||cells.length>128)return null;
  return cells;
}

export function mapW3cRow(raw:string,schema:W3cSchema):Record<string,string>|null{
  if(raw.startsWith('#')||raw.includes('\0')||/[\r\n]/.test(raw)||new TextEncoder().encode(raw).byteLength>8192)return null;
  if(!['space','tab'].includes(schema.delimiter)||schema.fields.length<1||schema.fields.length>128||
     schema.fields.some(field=>!safeField(field))||new Set(schema.fields).size!==schema.fields.length)return null;
  const cells=scanW3cRowCells(raw,schema.delimiter);
  if(!cells||cells.length!==schema.fields.length)return null;
  const values=cells.map(c=>c.decoded);
  const fields:Record<string,string>=Object.create(null);
  for(let index=0;index<schema.fields.length;index++){
    const key=schema.fields[index]!,value=values[index]!;
    if(new TextEncoder().encode(value).byteLength>2048)return null;
    fields[key]=value;
  }
  return fields;
}

export interface W3cLogBlock{
  schema:W3cSchema;
  rows:Array<Record<string,string>>;
  directives:Record<string,string|string[]>;
  lineEnding:'lf'|'crlf';
  /** Original received UTF-8 offsets for each declared field occurrence. */
  rowFieldSpans:Array<Array<{name:string;rawLexeme:string;startByte:number;endByte:number}>>;
  sourceBytes:number;
  physicalLines:number;
}

export type W3cLogBlockResult=
  |{ok:true;block:W3cLogBlock}
  |{ok:false;error:string};

const MAX_W3C_BLOCK_BYTES=1024*1024;
const MAX_W3C_ROWS=2000;

function addDirective(target:Record<string,string|string[]>,key:string,value:string):boolean{
  if(!/^[A-Za-z][A-Za-z0-9_-]{0,63}$/.test(key)||UNSAFE_W3C_FIELDS.has(key)||
     new TextEncoder().encode(value).byteLength>8192)return false;
  const previous=target[key];
  target[key]=previous===undefined?value:Array.isArray(previous)?[...previous,value]:[previous,value];
  return Object.keys(target).length<=128;
}

export function parseW3cLogBlock(raw:string):W3cLogBlockResult{
  if(!raw||raw.includes('\0')||new TextEncoder().encode(raw).byteLength>MAX_W3C_BLOCK_BYTES)
    return {ok:false,error:'Invalid or oversized W3C log block'};
  const hasCrlf=raw.includes('\r\n');
  const withoutCrlf=raw.replace(/\r\n/g,'');
  if(withoutCrlf.includes('\r'))return {ok:false,error:'Unsupported W3C line ending'};
  if(hasCrlf&&withoutCrlf.includes('\n'))return {ok:false,error:'Mixed W3C line endings are unsupported'};
  // The W3C Extended Log draft requires a physical line terminator for
  // every entry. Do not call a truncated final source row complete.
  if(!raw.endsWith(hasCrlf?'\r\n':'\n'))
    return {ok:false,error:'W3C final source row has no record terminator'};
  const lineEnding:'lf'|'crlf'=hasCrlf?'crlf':'lf';
  const normalized=hasCrlf?raw.replace(/\r\n/g,'\n'):raw;
  const endsWithEol=normalized.endsWith('\n');
  const lines=endsWithEol?normalized.slice(0,-1).split('\n'):normalized.split('\n');
  if(!lines.length||lines.some(line=>line===''))return {ok:false,error:'W3C block contains an empty line'};
  const encoder=new TextEncoder();
  const sourceBytes=encoder.encode(raw).length;
  const originalEolBytes=hasCrlf?2:1;
  let runningByte=0;
  const physicalLines=lines.map((line,index)=>{
    const startByte=runningByte;
    runningByte+=encoder.encode(line).length+
      (index<lines.length-1||endsWithEol?originalEolBytes:0);
    return {line,startByte};
  });
  if(runningByte!==sourceBytes)
    return {ok:false,error:'W3C physical source bytes not accounted'};

  let fieldsHeader:string|undefined;
  let versionHeader:'1.0'|undefined;
  const directives:Record<string,string|string[]> = Object.create(null);
  const dataLines:Array<{line:string;startByte:number}>=[];
  for(const {line,startByte} of physicalLines){
    if(line.startsWith('#Version:')){
      // W3C Working Draft: Version and Fields are required and must
      // precede all original entries. Only v1 is qualified here.
      if(versionHeader||dataLines.length||line!=='#Version: 1.0')
        return {ok:false,error:'W3C Version directive is repeated, late, or unsupported'};
      versionHeader='1.0';
      if(!addDirective(directives,'Version',versionHeader))
        return {ok:false,error:'Unsupported W3C Version directive'};
      continue;
    }
    if(line.startsWith('#Fields:')){
      if(fieldsHeader||dataLines.length)
        return {ok:false,error:'W3C Fields header is repeated or late'};
      fieldsHeader=line;continue;
    }
    if(line.startsWith('#')){
      const match=/^#([A-Za-z][A-Za-z0-9_-]{0,63}):(?: +(.*))?$/.exec(line);
      if(!match)return {ok:false,error:'Malformed W3C directive'};
      if(!addDirective(directives,match[1]!,match[2]??''))return {ok:false,error:'Unsafe W3C directive'};
      continue;
    }
    if(!fieldsHeader)return {ok:false,error:'W3C data row appeared before Fields header'};
    dataLines.push({line,startByte});
    if(dataLines.length>MAX_W3C_ROWS)return {ok:false,error:'W3C row limit exceeded'};
  }
  if(!versionHeader||!fieldsHeader||!dataLines.length)
    return {ok:false,error:'W3C v1 source requires Version, Fields, and data rows'};

  const headerFields=fieldsHeader.slice(9).trim().split(/ +/);
  const tabMode=dataLines.every(entry=>entry.line.includes('\t'));
  const spaceMode=dataLines.every(entry=>!entry.line.includes('\t'));
  if(!tabMode&&!spaceMode)return {ok:false,error:'Mixed W3C row delimiters are unsupported'};
  const schema=parseW3cFieldsHeader(fieldsHeader,tabMode?'tab':'space');
  if(!schema||schema.fields.length!==headerFields.length)return {ok:false,error:'Invalid W3C Fields header'};
  const rows:Array<Record<string,string>>=[];
  const rowFieldSpans:W3cLogBlock['rowFieldSpans']=[];
  const rawBytes=encoder.encode(raw);
  const decoder=new TextDecoder('utf8',{fatal:true});
  for(const {line,startByte} of dataLines){
    const row=mapW3cRow(line,schema);
    if(!row)return {ok:false,error:'W3C row does not match Fields schema'};
    const cells=scanW3cRowCells(line,schema.delimiter);
    if(!cells||cells.length!==schema.fields.length)
      return {ok:false,error:'W3C source row cell count mismatch'};
    const spans:W3cLogBlock['rowFieldSpans'][number]=[];
    for(let index=0;index<cells.length;index++){
      const c=cells[index]!;
      const begin=startByte+encoder.encode(line.slice(0,c.start)).length;
      const end=startByte+encoder.encode(line.slice(0,c.end)).length;
      if(decoder.decode(rawBytes.subarray(begin,end))!==c.rawLexeme)
        return {ok:false,error:'W3C original UTF-8 span is not replayable'};
      spans.push({
        name:schema.fields[index]!,rawLexeme:c.rawLexeme,
        startByte:begin,endByte:end,
      });
    }
    rows.push(row);rowFieldSpans.push(spans);
  }
  return {ok:true,block:{
    schema,rows,directives,lineEnding,rowFieldSpans,
    sourceBytes,physicalLines:physicalLines.length,
  }};
}
