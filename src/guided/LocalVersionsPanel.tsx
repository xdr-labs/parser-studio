import {useCallback,useEffect,useMemo,useState} from 'react';
import './localVersions.css';
import {GitCompareArrows,RotateCcw,Save,Trash2} from 'lucide-react';
import type {LocalWorkingCopy,LocalVersion} from './localWorkspaceHistory';
import {compareLocalVersions,deleteLocalVersion,listLocalVersions,readLocalVersion,
  sameLocalWorking,saveLocalVersion} from './localWorkspaceHistory';

interface Props{
  working:LocalWorkingCopy;
  onRestore:(snapshot:LocalVersion)=>void;
  onClose:()=>void;
}
const currentId='__current__';
const identity=(value:LocalVersion):LocalWorkingCopy=>({
  datasetName:value.datasetName,source:value.source,draft:value.draft,
});
function description(error:unknown):string{
  // Browser quota/permission diagnostics, never raw sensitive contents.
  return error instanceof Error?error.message:'Browser-only version operation failed.';
}
export default function LocalVersionsPanel({working,onRestore,onClose}:Props){
  const [items,setItems]=useState<LocalVersion[]>([]);
  const [label,setLabel]=useState('');
  const [left,setLeft]=useState('');
  const [right,setRight]=useState(currentId);
  const [busy,setBusy]=useState(false);
  const [status,setStatus]=useState('');
  const [invalid,setInvalid]=useState(0);
  const refresh=useCallback(async()=>{
    const list=await listLocalVersions();
    setItems(list.versions);setInvalid(list.rejected);
    setLeft(previous=>list.versions.some(v=>v.id===previous)?
      previous:list.versions[0]?.id??'');
    setRight(previous=>previous===currentId||list.versions.some(v=>v.id===previous)?
      previous:currentId);
  },[]);
  useEffect(()=>{
    let alive=true;
    void listLocalVersions().then(list=>{
      if(!alive)return;
      setItems(list.versions);setInvalid(list.rejected);
      setLeft(list.versions[0]?.id??'');
    }).catch(error=>{if(alive)setStatus(description(error));});
    return ()=>{alive=false;};
  },[]);
  const selected=items.find(item=>item.id===left);
  const compared=right===currentId?working:items.find(item=>item.id===right);
  const diff=useMemo(()=>selected&&compared?
    compareLocalVersions(identity(selected),
      right===currentId?working:identity(compared as LocalVersion)):null,
    [selected,compared,right,working]);
  const run=async(action:()=>Promise<void>)=>{
    if(busy)return;
    setBusy(true);setStatus('');
    try{await action();await refresh();}
    catch(error){setStatus(description(error));}
    finally{setBusy(false);}
  };
  const save=()=>void run(async()=>{
    const title=label.trim()||
      'Checkpoint · '+new Date().toLocaleString();
    const saved=await saveLocalVersion(working,title);
    setLabel('');setLeft(saved.id);
    setStatus('Saved in this browser only. No log or version was sent to a server.');
  });
  const restore=(item:LocalVersion)=>void run(async()=>{
    const retrieved=await readLocalVersion(item.id);
    const target=identity(retrieved);
    if(sameLocalWorking(working,target)){
      setStatus('This version already matches the current workspace.');return;
    }
    const agreed=window.confirm('Restore "'+retrieved.label+'"? Parser Studio will first save your current working copy as another local checkpoint. Generated files must be tested again.');
    if(!agreed)return;
    const safeTitle='Before restore · '+new Date().toLocaleString();
    await saveLocalVersion(working,safeTitle);
    onRestore(retrieved);
    setRight(currentId);
    setStatus('Restored "'+retrieved.label+'". Your previous working copy was saved locally. Re-run Analyze Logs before generating parser files.');
  });
  const remove=(item:LocalVersion)=>void run(async()=>{
    if(!window.confirm('Delete the local version "'+item.label+'"? This cannot be undone.'))return;
    await deleteLocalVersion(item.id);
    setStatus('Deleted the selected local version. Other versions and your current work are unchanged.');
  });
  const countBytes=new TextEncoder().encode(working.source).length;
  return <section className="local-versions-panel" aria-label="Local Versions workspace">
    <div className="local-versions-heading">
      <div>
        <h2>Local Versions · Try, compare and restore</h2>
        <p>Save your current sample logs, parsing rules, CSV settings and field mappings as separate checkpoints. Every version stays in this browser profile and website origin. No version is stored on the Parser Studio server.</p>
      </div>
      <button type="button" className="button secondary" onClick={onClose}>Close Versions</button>
    </div>
    <p className="local-versions-warning" role="note">
      Saved logs may contain sensitive data and are stored by this browser, not encrypted by Parser Studio.
      Anyone using the same browser profile may access them. Clearing site data, private-browsing cleanup,
      or switching to another browser or temporary tunnel URL can make these versions unavailable.
    </p>
    <div className="local-version-actions">
      <label>Version name
        <input aria-label="Local version name" maxLength={80} value={label}
          onChange={e=>setLabel(e.target.value)}
          placeholder="Before mapping changes · V1"/>
      </label>
      <button type="button" className="button primary" disabled={busy} onClick={save}>
        <Save size={16}/> Save Version
      </button>
      <span>{countBytes.toLocaleString()} source bytes · {items.length}/30 saved</span>
    </div>
    {invalid>0&&<p role="alert">{invalid} corrupt or unverified local version(s) were excluded from restore. The current workspace was not altered.</p>}
    {status&&<p role="status" className="local-versions-status">{status}</p>}
    <div className="local-version-list" aria-label="Saved local versions">
      {items.length===0?<p>No versions saved yet. Try a mapping, save V1, change the mapping, and save V2.</p>:
        items.map(item=><div className="local-version-row" key={item.id}>
          <div>
            <strong>{item.label}</strong>
            <small>{new Date(item.createdAt).toLocaleString()} · {item.draft.format} · {item.draft.mappings.length} mappings · {new TextEncoder().encode(item.source).length.toLocaleString()} bytes</small>
          </div>
          <div className="local-version-row-actions">
            <button type="button" disabled={busy} onClick={()=>restore(item)}><RotateCcw size={14}/> Restore</button>
            <button type="button" disabled={busy} onClick={()=>remove(item)} aria-label={'Delete local version '+item.label}><Trash2 size={14}/> Delete</button>
          </div>
        </div>)}
    </div>
    {items.length>0&&<div className="local-version-comparison" aria-label="Compare local versions">
      <h3><GitCompareArrows size={17}/> Compare Versions</h3>
      <div className="local-version-compare-selects">
        <label>Version A
          <select aria-label="Compare version A" value={left} onChange={e=>setLeft(e.target.value)}>
            {items.map(item=><option key={item.id} value={item.id}>{item.label}</option>)}
          </select>
        </label>
        <label>Version B
          <select aria-label="Compare version B" value={right} onChange={e=>setRight(e.target.value)}>
            <option value={currentId}>Current working copy (unsaved)</option>
            {items.map(item=><option key={item.id} value={item.id}>{item.label}</option>)}
          </select>
        </label>
      </div>
      {diff&&<div aria-label="Local version differences">
        <p>{diff.sourceChanged?'Log sample changed':'Log sample unchanged'} · {diff.changedLines} differing line positions · {diff.draftChanged?'Parser settings changed':'Parser settings unchanged'}</p>
        <p>{diff.changes.length?diff.changes.join(' · '):'No parser configuration differences detected.'}</p>
        <p>Mappings added: {diff.addedMappings.length} · removed: {diff.removedMappings.length} · edited: {diff.editedMappings.length}</p>
        {!!(diff.addedMappings.length||diff.removedMappings.length||diff.editedMappings.length)&&
          <details><summary>Mapping change IDs</summary>
            <ul>{[
              ...diff.addedMappings.map(k=>'Added: '+k),
              ...diff.removedMappings.map(k=>'Removed: '+k),
              ...diff.editedMappings.map(k=>'Edited: '+k)
            ].map((line,i)=><li key={i}>{line}</li>)}</ul>
          </details>}
        {diff.sourceChanged&&<details>
          <summary>Review local source previews (first 2,000 characters per version)</summary>
          <div className="local-version-source-comparison">
            <div><strong>Version A</strong><pre>{selected?.source.slice(0,2000)}</pre></div>
            <div><strong>Version B</strong><pre>{compared?.source.slice(0,2000)}</pre></div>
          </div>
        </details>}
      </div>}
    </div>}
  </section>;
}
