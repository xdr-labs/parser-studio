import {useState} from 'react';
import {Plus,Trash2} from 'lucide-react';
import type {NamedLogAnalysis,NamedLogType} from './namedLogTypes';
import {MAX_NAMED_LOG_BYTES,MAX_NAMED_LOG_TYPES,
  newNamedLogType,validateNamedLogs} from './namedLogTypes';
import {HelpTip} from './BeginnerHelp';

interface Props {
  groups:NamedLogType[]|null;
  onEnable:()=>void;
  onChange:(groups:NamedLogType[])=>void;
  onExit:()=>void;
  analysis?:{groups:NamedLogAnalysis[];unassigned:number};
}
const bytes=(value:string)=>new TextEncoder().encode(value).length;
export default function NamedLogTypesPanel({
  groups,onEnable,onChange,onExit,analysis,
}:Props){
  const [fileError,setFileError]=useState('');
  if(!groups)return <section className="named-log-intro" aria-label="Add multiple log types">
    <p><strong>Does this product produce different kinds of logs?</strong>
      {' '}Add Threat, Traffic, User, Asset, or other examples separately.
      Parser Studio will review every type together without guessing the format.</p>
    <button type="button" onClick={onEnable} className="named-log-add">
      <Plus size={16}/> Add Another Log Type
    </button>
    <small>Existing pasted logs stay in the first group. No logs are sent to an AI service.</small>
  </section>;
  const validation=validateNamedLogs(groups);
  const edit=(id:string,update:Partial<NamedLogType>)=>{
    setFileError('');
    onChange(groups.map(group=>group.id===id?{...group,...update}:group));
  };
  const upload=async(id:string,file?:File)=>{
    if(!file)return;
    if(file.size>MAX_NAMED_LOG_BYTES){
      setFileError('That file exceeds 64 KiB. Choose a smaller text sample.');return;
    }
    try{
      const sample=new TextDecoder('utf-8',{fatal:true}).decode(await file.arrayBuffer());
      edit(id,{sample});
    }catch{
      setFileError('Could not read this log as UTF-8. Existing samples were preserved.');
    }
  };
  const add=()=>{
    if(groups.length>=MAX_NAMED_LOG_TYPES)return;
    onChange([...groups,newNamedLogType(crypto.randomUUID(),
      'Log Type '+(groups.length+1))]);
  };
  return <section className="named-log-panel" aria-label="Named log type samples">
    <div className="named-log-heading">
      <div>
        <h3>Log types from this product
          {' '}<HelpTip label="Named log types"
            text="Enter different log types separately. The names organize samples for review; they are not injected into logs and do not automatically become parser routing rules."/></h3>
        <p>Add up to 10 log types. Paste representative events or upload one file per type.
          Each type remains editable until you create a parser.</p>
      </div>
      <span>{groups.length} type{groups.length===1?'':'s'} · {validation.bytes.toLocaleString()} / 65,536 UTF-8 bytes</span>
    </div>
    <div className="named-log-list">
      {groups.map((group,index)=>{
        const result=analysis?.groups.find(row=>row.id===group.id);
        return <section className="named-log-card" aria-label={'Log type entry '+(index+1)} key={group.id}>
          <div className="named-log-card-heading">
            <label>Log Type {index+1} name
              <input aria-label={'Log type name '+(index+1)}
                value={group.name} maxLength={64}
                onChange={event=>edit(group.id,{name:event.target.value})}
                placeholder="Threat / Traffic / User / Asset"/>
            </label>
            <button type="button" className="named-log-remove" disabled={groups.length===1}
              aria-label={'Remove log type '+(index+1)}
              onClick={()=>onChange(groups.filter(item=>item.id!==group.id))}>
              <Trash2 size={15}/> Remove
            </button>
          </div>
          <label className="named-log-sample-label">Sample logs for {group.name||'Log Type '+(index+1)}
            <textarea aria-label={'Log type sample '+(index+1)} rows={4}
              spellCheck={false} value={group.sample} onChange={event=>edit(group.id,{sample:event.target.value})}
              placeholder="Paste one or more original log events here. Keep values and event boundaries intact."/>
          </label>
          <div className="named-log-card-bottom">
            <label>Upload for this type (replaces only its sample)
              <input type="file" aria-label={'Upload log type '+(index+1)}
                accept=".log,.txt,.json,.csv,text/plain"
                onChange={event=>{const file=event.currentTarget.files?.[0];
                  event.currentTarget.value='';void upload(group.id,file);}}/>
            </label>
            <span>{bytes(group.sample).toLocaleString()} bytes</span>
          </div>
          {result&&<p className={result.partial||result.rawOnly||result.boundaryWarning?'named-log-warning':'named-log-success'}
            role="status">
            {group.name}: {result.events} event{result.events===1?'':'s'} ·
            {' '}{result.parsed} parsed · {result.partial} partial ·
            {' '}{result.rawOnly} raw-only
            {result.boundaryWarning?' · An event crossed a group boundary; review the record framing.':''}
          </p>}
        </section>;
      })}
    </div>
    <div className="named-log-actions">
      <button type="button" className="named-log-add" onClick={add}
        disabled={groups.length>=MAX_NAMED_LOG_TYPES}>
        <Plus size={16}/> Add Another Log Type
      </button>
      <button type="button" onClick={onExit}>
        Use one combined text box
      </button>
    </div>
    {validation.issues.map((issue,index)=><p key={index} role="alert"
      className="named-log-warning">{issue}</p>)}
    {fileError&&<p role="alert" className="named-log-warning">{fileError}</p>}
    {analysis&&analysis.unassigned>0&&
      <p className="named-log-warning" role="alert">
        {analysis.unassigned} analyzed event(s) did not fit wholly within a named sample.
        Review the sample boundaries before creating a parser.
      </p>}
    <p role="note">These names are review labels only. To create one conditional parser for
      multiple event types, the source events must contain a verified discriminator
      such as event_type, or the backend must support the reviewed mixed-format grammar.
      Parser Studio will not invent a discriminator or combine incompatible parsers.</p>
  </section>;
}
