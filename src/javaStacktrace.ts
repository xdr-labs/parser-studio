/** P0 strict, deterministic browser mirror of the reviewed Native Ruby Java
 * subset. It does not reassemble source streams or execute untrusted code.
 * Transport MUST frame each complete exception with literal LF LF.
 */
export interface JavaTraceExtraction {
  fields:Record<string,unknown>;
  errors:string[];
}
const CLASS=String.raw`(?:[A-Za-z_$][A-Za-z0-9_$]*\.)+[A-Za-z_$][A-Za-z0-9_$]*(?:Exception|Error)`;
const HEADER=new RegExp('^('+CLASS+')(?:\\: [^\\n]{1,256})?$');
const FRAME=/^[ \t]+at [A-Za-z_$][A-Za-z0-9_.$/]*\((?:[A-Za-z0-9_.$/-]+\.java:\d{1,5}|Unknown Source|Native Method)\)$/;
const CAUSE=new RegExp('^Caused by: ('+CLASS+')(?:\\: [^\\n]{1,256})?$');
const MORE=/^[ \t]*\.\.\. [1-9]\d{0,2} more$/;
const error=():JavaTraceExtraction=>({
  fields:{},errors:['Java exception does not match the bounded TCP blank-line-framed grammar']
});
export function parseJavaStacktrace(text:string):JavaTraceExtraction{
  if(typeof text!=='string'||text.includes('\r')||
    text.includes('\n\n')||!text.includes('\n')||
    new TextEncoder().encode(text).byteLength>8192)return error();
  const lines=text.split('\n');
  if(lines.length<2||lines.length>64||
     lines.some(line=>line.length===0||
       new TextEncoder().encode(line).byteLength>512))return error();
  const head=HEADER.exec(lines[0]!);
  if(!head)return error();
  let frames=0,causes=0,root:string|undefined;
  let last:'header'|'frame'|'cause'|'more'='header';
  for(const line of lines.slice(1)){
    if(FRAME.test(line)){frames++;last='frame';}
    else{
      const matched=CAUSE.exec(line);
      if(matched){
        causes++;
        if(causes>4)return error();
        root=matched[1];
        last='cause';
      }else if(MORE.test(line)&&causes>0&&last==='frame')last='more';
      else return error();
    }
  }
  if(frames===0||last==='cause')return error();
  return {fields:{
    exception_class:head[1],
    frame_count:frames,
    ...(root?{cause_class:root}:{})
  },errors:[]};
}
