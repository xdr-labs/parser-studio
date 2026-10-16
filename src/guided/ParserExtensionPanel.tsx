import {useEffect,useState} from 'react';
import type {ParserDraft} from '../model';
import {buildMappingExtension,type ParserExtensionBuildResult} from './parserExtension';

interface Props{
  baseDraft:ParserDraft;
  currentDraft:ParserDraft;
  baseLabel:string;
}

function downloadJson(filename:string,value:unknown){
  const blob=new Blob([JSON.stringify(value,null,2)+'\n'],{type:'application/json'});
  const url=URL.createObjectURL(blob);
  const anchor=document.createElement('a');
  anchor.href=url;anchor.download=filename;document.body.append(anchor);anchor.click();anchor.remove();
  window.setTimeout(()=>URL.revokeObjectURL(url),1000);
}

export default function ParserExtensionPanel({baseDraft,currentDraft,baseLabel}:Props){
  const [result,setResult]=useState<ParserExtensionBuildResult|null>(null);
  const [busy,setBusy]=useState(false);
  useEffect(()=>{setResult(null);},[baseDraft,currentDraft]);
  const review=async()=>{
    if(busy)return;
    setBusy(true);
    try{setResult(await buildMappingExtension(baseDraft,currentDraft));}
    finally{setBusy(false);}
  };
  const safe=result?.ok?result.extension:null;
  const filename='customized_'+(baseDraft.guided?.slug??'parser')+'.mapping-extension.json';
  return <section className="parser-extension-panel" aria-label="Mapping-only parser extension">
    <div>
      <strong>Keep the base parser stable</strong>
      <p>You opened {baseLabel}. If you only changed field mappings, Parser Studio can package those
        changes as a small reviewable extension instead of replacing the parser extraction logic.</p>
    </div>
    <button type="button" onClick={()=>void review()} disabled={busy}>
      {busy?'Checking changes…':'Review mapping-only extension'}
    </button>
    {result&&!result.ok&&<p role="status">
      {result.reason==='NO_CHANGES'
        ?'No mapping changes exist relative to the opened parser.'
        :result.reason==='UNSAFE_BASE_CHANGE'
          ?'This draft also changes parser structure or removes/rebinds an existing source field. Create and test a full parser revision instead of an extension.'
          :'The mapping set is not safe to package as an extension.'}
    </p>}
    {safe&&<div className="auto-parser-result" role="status" aria-label="Mapping extension ready">
      <strong>{safe.changes.length} mapping change{safe.changes.length===1?'':'s'} isolated from the base parser</strong>
      <span>Base extraction unchanged · raw/source values excluded · exact base draft SHA-256 bound.</span>
      {safe.changes.map(change=><span key={change.mappingId}>
        {change.source} → {change.target} · {change.type} · {change.group}
      </span>)}
      <button type="button" onClick={()=>downloadJson(filename,safe)}>
        Download Mapping Extension JSON
      </button>
      <small>This extension is a Parser Studio review artifact. Native Fluentd and Stellar target application are not verified by this file.</small>
    </div>}
  </section>;
}
