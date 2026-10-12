import {useEffect,useRef,useState} from 'react';
import {Download,FileArchive,GitCompare,History,RotateCcw,ShieldCheck} from 'lucide-react';
import type {GeneratedPair} from './backendClient';
import MockTargetApplyPanel from './MockTargetApplyPanel';
import {registerArtifactRevision,listArtifactRevisions,compareArtifactRevisions,
  retrieveRevisionZip,type RevisionSummary,type RevisionDiff,type VerifiedRevisionZip,
} from './artifactRevisionClient';

interface Props {
  projectId:string|undefined;
  draftKey:string;
  pair:GeneratedPair|null;
  listenerPort:number|null;
  onDownload:(filename:string,bytes:ArrayBuffer)=>void;
}

const VERSION=/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
export default function ArtifactRevisionHistoryPanel({
  projectId,draftKey,pair,listenerPort,onDownload,
}:Props){
  const [version,setVersion]=useState('1.0.0');
  const [revisions,setRevisions]=useState<RevisionSummary[]>([]);
  const [fromId,setFromId]=useState('');
  const [toId,setToId]=useState('');
  const [diff,setDiff]=useState<RevisionDiff|null>(null);
  const [preview,setPreview]=useState<VerifiedRevisionZip|null>(null);
  const [busy,setBusy]=useState(false);
  const [error,setError]=useState('');
  const [status,setStatus]=useState('');
  const epoch=useRef(0);
  useEffect(()=>{
    epoch.current++;
    setRevisions([]);setFromId('');setToId('');
    setDiff(null);setPreview(null);setBusy(false);setError('');setStatus('');
  },[projectId,draftKey]);
  const from=revisions.find(r=>r.artifactRevisionId===fromId);
  const to=revisions.find(r=>r.artifactRevisionId===toId);
  const current=revisions.at(-1);
  const safeProject=!!projectId&&/^[A-Za-z0-9_.-]{1,128}$/.test(projectId);
  const canRegister=!!pair&&!!projectId&&pair.manifest.projectId===projectId&&
    Number.isSafeInteger(listenerPort)&&Number(listenerPort)>=1024&&
    Number(listenerPort)<=65535&&VERSION.test(version);

  const start=()=>{
    setBusy(true);setError('');setStatus('');setDiff(null);setPreview(null);
    return epoch.current;
  };
  const failed=(token:number,e:unknown)=>{
    if(token!==epoch.current)return;
    // Client errors contain only bounded, authored codes; never raw server text.
    setError(e instanceof Error?e.message:'Offline revision request failed.');
  };
  const load=async()=>{
    if(!safeProject||!projectId||busy)return;
    const token=start();
    try{
      const rows=await listArtifactRevisions(projectId);
      if(token!==epoch.current)return;
      setRevisions(rows);setFromId(rows.at(-2)?.artifactRevisionId??rows.at(-1)?.artifactRevisionId??'');
      setToId(rows.at(-1)?.artifactRevisionId??'');
      setStatus(rows.length
        ?'Verified owner-scoped temporary history metadata. No target changes.'
        :'No revisions available for this authenticated project.');
    }catch(e){failed(token,e);}
    finally{if(token===epoch.current)setBusy(false);}
  };
  const register=async()=>{
    if(!canRegister||!pair||!projectId||listenerPort===null||busy)return;
    const token=start();
    try{
      const revision=await registerArtifactRevision(pair,version,listenerPort);
      if(token!==epoch.current)return;
      const next=[...revisions.filter(r=>r.artifactRevisionId!==revision.artifactRevisionId),revision];
      setRevisions(next);
      setFromId(next.at(-2)?.artifactRevisionId??revision.artifactRevisionId);
      setToId(revision.artifactRevisionId);
      setStatus('Registered an immutable DRAFT snapshot in the temporary owner-scoped store.');
    }catch(e){failed(token,e);}
    finally{if(token===epoch.current)setBusy(false);}
  };
  const compare=async()=>{
    if(!from||!to||from.artifactRevisionId===to.artifactRevisionId||busy)return;
    const token=start();
    try{
      const result=await compareArtifactRevisions(from,to);
      if(token!==epoch.current)return;
      setDiff(result);
      setStatus('SHA-256 metadata compared. No parser source, credentials or log data retrieved.');
    }catch(e){failed(token,e);}
    finally{if(token===epoch.current)setBusy(false);}
  };
  const getZip=async(asPreview:boolean)=>{
    if(!from||busy||asPreview&&
      (!current||current.artifactRevisionId===from.artifactRevisionId))return;
    const token=start();
    try{
      const result=await retrieveRevisionZip(from,asPreview?current!:null);
      if(token!==epoch.current)return;
      if(asPreview){
        setPreview(result);
        setStatus('Read-only restore preview verified. The current draft and DP remain unchanged.');
      }else{
        onDownload(result.filename,result.bytes);
        setStatus('Downloaded the original immutable ZIP after SHA-256 verification.');
      }
    }catch(e){failed(token,e);}
    finally{if(token===epoch.current)setBusy(false);}
  };
  return <details className="guided-revision-history" aria-label="Offline parser revision history">
    <summary><History size={16}/> Offline Version History (Owner Scoped · Opt In)</summary>
    <p>Optional temporary server-side history of exact DRAFT Ruby + CONF packages.
      Every operation requires the backend to authorize the current owner and tenant.
      Nothing is saved or queried automatically. Never enter an API key or customer logs.</p>
    <small className="guided-revision-boundary">Not persistent storage, production rollback, DP deployment, live verification, or automatic activation. Revisions can expire or disappear when the backend restarts.</small>
    <div className="guided-revision-toolbar">
      <label className="guided-field"><span>Immutable Snapshot Version</span>
        <input aria-label="Offline revision version" value={version}
          maxLength={64} autoComplete="off" onChange={event=>setVersion(event.target.value)}/>
      </label>
      <button className="guided-cta-secondary" type="button"
        disabled={!canRegister||busy} onClick={()=>{void register();}}>
        <ShieldCheck size={14}/> Register Current DRAFT (Opt In)
      </button>
      <button className="guided-cta-secondary" type="button"
        disabled={!safeProject||busy} onClick={()=>{void load();}}>
        <History size={14}/> {busy?'Checking…':'Load My Revision List'}
      </button>
    </div>
    {!pair&&<small>Generate and verify a parser pair to register a new snapshot.
      Loading a previously registered project's metadata does not require regeneration.</small>}
    {error&&<p className="guided-error" role="alert">{error}</p>}
    {status&&<p className="guided-note" role="status">{status}</p>}
    {revisions.length>0&&<div className="guided-revision-workspace" aria-label="Verified offline revision list">
      <div className="guided-section-title"><span>HISTORY</span> Verified Metadata Only · {revisions.length} Snapshots</div>
      <ul className="guided-revision-list">{revisions.map((r,index)=>
        <li key={r.artifactRevisionId}><strong>{r.version} · r{r.projectRevision}</strong>
          <span>{index===revisions.length-1?'Current stored snapshot':'Previous snapshot'} · Port {r.selectedParserPort} · {r.receiverProtocols.join('/')}</span>
          <code>ZIP SHA-256: {r.zipSha256}</code>
          <small>Revision: {r.artifactRevisionId} · {r.createdAt}</small>
        </li>)}</ul>
      <div className="guided-revision-toolbar">
        <label className="guided-field"><span>Selected Revision</span>
          <select aria-label="Offline revision from" value={fromId} onChange={event=>{
            setFromId(event.target.value);setDiff(null);setPreview(null);setStatus('');setError('');
          }}>{revisions.map(r=><option key={r.artifactRevisionId} value={r.artifactRevisionId}>{r.version} · r{r.projectRevision} · {r.artifactRevisionId.slice(0,12)}</option>)}</select>
        </label>
        <label className="guided-field"><span>Compare Against</span>
          <select aria-label="Offline revision to" value={toId} onChange={event=>{
            setToId(event.target.value);setDiff(null);setStatus('');setError('');
          }}>{revisions.map(r=><option key={r.artifactRevisionId} value={r.artifactRevisionId}>{r.version} · r{r.projectRevision} · {r.artifactRevisionId.slice(0,12)}</option>)}</select>
        </label>
      </div>
      <div className="guided-revision-actions">
        <button className="guided-cta-secondary" type="button" onClick={()=>{void compare();}}
          disabled={busy||!from||!to||from.artifactRevisionId===to.artifactRevisionId}>
          <GitCompare size={14}/> Compare SHA-256 Only
        </button>
        <button className="guided-cta-secondary" type="button" onClick={()=>{void getZip(false);}}
          disabled={busy||!from}><Download size={14}/> Re-download Verified ZIP</button>
        <button className="guided-cta-secondary" type="button" onClick={()=>{void getZip(true);}}
          disabled={busy||!from||!current||current.artifactRevisionId===from.artifactRevisionId}>
          <RotateCcw size={14}/> Preview Previous ZIP (No Restore)
        </button>
      </div>
      {diff&&<div className="guided-revision-diff" aria-label="Offline SHA revision comparison">
        <strong>Verified SHA-256 Difference · No Source Values</strong>
        <p>Version changed: {diff.version.changed?'Yes':'No'} · Listener port changed: {diff.selectedParserPort.changed?'Yes':'No'}</p>
        {diff.files.map(file=><div key={file.name}><strong>{file.name} · {file.changed?'Changed':'Unchanged'}</strong>
          <code>Before: {file.fromSha256}</code><code>After: {file.toSha256}</code></div>)}
        <small>Native parsing, DP installation and runtime rollback are not verified.</small>
      </div>}
      {current&&<MockTargetApplyPanel revision={current}/>}
      {preview&&<div className="guided-revision-preview" aria-label="Verified offline restore preview">
        <strong><FileArchive size={15}/> Verified Preview Only · No Mutation</strong>
        <p>{preview.filename} · SHA-256 {preview.sha256}</p>
        <button type="button" className="guided-cta-secondary"
          onClick={()=>{onDownload(preview.filename,preview.bytes);setStatus('Downloaded the verified old DRAFT ZIP. No restore or deployment occurred.');}}>
          <Download size={14}/> Download Verified Preview ZIP
        </button>
      </div>}
    </div>}
    <small>Access denied (403) is expected when the offline revision service is disabled.
      This workspace cannot configure owner identity or enable server access.</small>
  </details>;
}
