import {useEffect,useRef,useState} from 'react';
import {FlaskConical,ShieldCheck} from 'lucide-react';
import type {RevisionSummary} from './artifactRevisionClient';
import {getMockApplyStatus,submitMockApply,
  type MockApplyStatusResult,type MockApplyProof} from './mockTargetApplyClient';

interface Props {revision:RevisionSummary;}
const APPROVAL=/^[A-Za-z0-9._-]{8,96}$/;

export default function MockTargetApplyPanel({revision}:Props){
  const [approvalId,setApprovalId]=useState('');
  const [acknowledged,setAcknowledged]=useState(false);
  const [busy,setBusy]=useState(false);
  const [result,setResult]=useState<MockApplyStatusResult|null>(null);
  const [proof,setProof]=useState<MockApplyProof|null>(null);
  const [error,setError]=useState('');
  const requestEpoch=useRef(0);
  useEffect(()=>{
    requestEpoch.current++;
    setApprovalId('');setAcknowledged(false);setBusy(false);
    setResult(null);setProof(null);setError('');
  },[revision.artifactRevisionId]);
  const check=async()=>{
    if(busy)return;
    const epoch=requestEpoch.current;
    setBusy(true);setError('');setResult(null);setProof(null);
    try{
      const reply=await getMockApplyStatus(revision);
      if(epoch===requestEpoch.current)setResult(reply);
    }catch(err){
      if(epoch===requestEpoch.current)
        setError(err instanceof Error?err.message:'Mock Apply status is unavailable.');
    }finally{if(epoch===requestEpoch.current)setBusy(false);}
  };
  const simulate=async()=>{
    if(busy||!acknowledged||!APPROVAL.test(approvalId))return;
    const epoch=requestEpoch.current;
    setBusy(true);setError('');setProof(null);setResult(null);
    try{
      const reply=await submitMockApply(revision,approvalId,true);
      if(epoch===requestEpoch.current){
        setProof(reply);setApprovalId('');setAcknowledged(false);
      }
    }catch(err){
      if(epoch===requestEpoch.current)
        setError(err instanceof Error?err.message:'Mock-only simulation was denied.');
    }finally{if(epoch===requestEpoch.current)setBusy(false);}
  };
  return <details className="guided-mock-target" aria-label="Mock-only Apply simulation">
    <summary><FlaskConical size={15}/> Backend MOCK_ONLY Apply Test · Not a Real DP</summary>
    <p>This optional development test can verify registered DRAFT metadata against
      a server-owned <code>.invalid</code> mock destination only. It cannot accept a DP URL,
      API key or sensor address. Backend owner authentication, approval, port-inventory
      checks and audit are mandatory. Real target Apply is unavailable in this UI.</p>
    <button type="button" className="guided-cta-secondary" disabled={busy}
      onClick={()=>{void check();}}>
      <ShieldCheck size={14}/>{busy?'Verifying…':'Check My Mock Apply Status'}
    </button>
    {result&&<p className="guided-note" role="status">
      Mock-only status: {result.status} · Ephemeral · Real target unverified
    </p>}
    <label className="guided-field"><span>Operator Mock Approval ID (not an API key)</span>
      <input aria-label="Mock Apply approval ID" type="password" autoComplete="off"
        maxLength={96} value={approvalId} onChange={e=>{
          setApprovalId(e.target.value);setAcknowledged(false);
          setProof(null);setError('');
        }} placeholder="Enter approved mock-only reference"/>
    </label>
    <label className="guided-owner-check">
      <input type="checkbox" aria-label="Acknowledge mock-only Apply" checked={acknowledged}
        onChange={e=>setAcknowledged(e.target.checked)}/>
      I authorize this MOCK_ONLY test for the selected immutable revision;
      no actual DP registration, sensor send or parser activation is authorized.
    </label>
    <button type="button" className="guided-cta-secondary"
      disabled={busy||!acknowledged||!APPROVAL.test(approvalId)}
      onClick={()=>{void simulate();}}>
      <FlaskConical size={14}/> {busy?'Submitting…':'Run Approved Mock-only Apply'}
    </button>
    {error&&<p role="alert" className="guided-error">{error}</p>}
    {proof&&<div className="guided-zip-receipt" aria-label="Verified mock-only Apply result">
      <strong>MOCK_READBACK_VERIFIED · No Real Deployment</strong>
      <p>Parser {proof.name} · Version {proof.version} · Receiving port {proof.selectedParserPort}</p>
      <small>Revision: {proof.artifactRevisionId}</small>
      <small>This does not verify native parsing, a sensor listener, any real target,
        or Stellar Cyber import. The backend always owns authorization.</small>
    </div>}
    <small>Default server response is 403 until a trusted MOCK_ONLY gateway is explicitly enabled.
      Nothing is sent until you click an action.</small>
  </details>;
}
