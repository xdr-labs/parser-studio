import {useEffect,useRef,useState} from 'react';
import {Download,FileCheck2,ShieldCheck} from 'lucide-react';
import {downloadTestLabEvidence,loadTestLabEvidenceSummary,
  type EvidenceSummary,type VerifiedEvidenceDownload,
} from './testLabEvidenceClient';

interface Props{
  runId:string;
  onDownload:(filename:string,content:string,mediaType:string)=>void;
}
export default function TestLabEvidencePanel({runId,onDownload}:Props){
  const [summary,setSummary]=useState<EvidenceSummary|null>(null);
  const [receipt,setReceipt]=useState<Pick<VerifiedEvidenceDownload,'sha256'|'filename'>|null>(null);
  const [error,setError]=useState('');
  const [busy,setBusy]=useState(false);
  const token=useRef(0);
  useEffect(()=>{
    token.current++;
    setSummary(null);setReceipt(null);setError('');setBusy(false);
  },[runId]);
  const inspect=async()=>{
    if(busy)return;
    const current=++token.current;
    setBusy(true);setError('');setSummary(null);setReceipt(null);
    try{
      const result=await loadTestLabEvidenceSummary(runId);
      if(current===token.current)setSummary(result);
    }catch(e){
      if(current===token.current)setError(e instanceof Error?e.message:
        'The offline evidence summary is unavailable.');
    }finally{if(current===token.current)setBusy(false);}
  };
  const download=async()=>{
    if(busy||!summary||summary.runId!==runId)return;
    const current=++token.current;
    setBusy(true);setError('');setReceipt(null);
    try{
      // Immutable identity across explicit summary/read requests. Live runs
      // may advance counts between requests; never assume they are frozen.
      const artifact=await downloadTestLabEvidence(runId,fetch,summary.artifactRevisionId);
      if(current!==token.current)return;
      onDownload(artifact.filename,artifact.content,'application/json;charset=utf-8');
      setReceipt({filename:artifact.filename,sha256:artifact.sha256});
    }catch(e){
      if(current===token.current)setError(e instanceof Error?e.message:
        'The evidence export is unavailable or failed validation.');
    }finally{if(current===token.current)setBusy(false);}
  };
  return <details className="guided-testlab-evidence" aria-label="Redacted Test Lab evidence review">
    <summary><FileCheck2 size={16}/> Review Offline Evidence · Owner-only, Redacted</summary>
    <p>Inspect the server's bounded, temporary metadata-only Test Lab report
      for this authenticated run. The backend independently authorizes every
      request. A run ID does not grant ownership and this screen makes no
      automatic requests.</p>
    <button type="button" className="guided-cta-secondary" disabled={busy}
      onClick={()=>{void inspect();}}>
      <ShieldCheck size={15}/> {busy?'Checking Evidence…':'Load My Redacted Evidence Summary'}
    </button>
    {error&&<p role="alert" className="guided-error">{error}</p>}
    {summary&&<div className="guided-testlab-summary" aria-label="Verified Test Lab evidence summary">
      <strong>{summary.comparisonStatus==='NOT_VERIFIED'
        ?'NOT VERIFIED · No Indexed Evidence'
        :'OFFLINE EVIDENCE ONLY · No Real E2E Proof'}</strong>
      <p>Run <code>{summary.runId}</code> · Evidence expires {summary.expiresAt}</p>
      <div className="guided-testlab-evidence-counts" aria-label="Offline evidence stage counts">
        <span>Generated <b>{summary.counts.generated}</b></span>
        <span>Send attempted <b>{summary.counts.sendAttempted}</b></span>
        <span>Sink accepted <b>{summary.counts.sinkAccepted}</b></span>
        <span>Offline sensor callbacks <b>{summary.counts.sensorObserved}</b></span>
        <span>Offline indexed callbacks <b>{summary.counts.dpIndexed}</b></span>
        <span>Events with field comparisons <b>{summary.counts.fieldCompared}</b></span>
      </div>
      <div className="guided-section-title"><span>FIELDS</span> Redacted Field Coverage</div>
      {summary.fieldCoverage.length>0
        ? <div className="guided-testlab-field-list" aria-label="Offline field coverage">
          {summary.fieldCoverage.map(field=><div key={field.field} className="guided-testlab-field-row">
            <strong>{field.field}</strong>
            <span>{field.matched} match · {field.mismatched} mismatch · {field.missing} missing</span>
            <small>Coverage {field.coveragePercent}% · Match {field.matchPercent}%
              {' · '} Compared {field.comparedEvents} events</small>
          </div>)}
        </div>
        : <p>No approved offline field comparisons are available. This is not
          evidence of parsed DP data.</p>}
      <div className="guided-section-title"><span>FAILURES</span> Safe Transport Status Codes</div>
      {summary.failureGroups.length>0
        ? <ul className="guided-testlab-failures" aria-label="Grouped Test Lab send failures">
          {summary.failureGroups.map(group=><li key={group.errorCode}>
            <code>{group.errorCode}</code> · {group.events} event(s)
          </li>)}
        </ul>
        : <p>No categorized transport errors were reported.</p>}
      <button type="button" className="guided-cta-secondary" disabled={busy}
        onClick={()=>{void download();}}>
        <Download size={15}/> {busy?'Verifying JSON…':'Download Verified Redacted Evidence JSON'}
      </button>
      {receipt&&<p className="guided-testlab-receipt" role="status">
        Verified JSON: {receipt.filename} · SHA-256 {receipt.sha256}
      </p>}
      <small>JSON includes only per-event sequence, stage flags, reviewed field names,
        comparison status and safe error codes; never raw values, log bodies,
        credentials, destinations or parser source. SHA-256 validates file bytes,
        not trust in an operator or real sensor/DP verification.</small>
    </div>}
    <small>Offline contract only · Real sensor reception, native runtime parsing
      and Full User E2E remain unverified. The backend may deny access with HTTP
      403 or expire evidence; neither implies a running sensor or target.</small>
  </details>;
}
