import {useEffect,useRef,useState} from 'react';
import {Activity,ShieldCheck} from 'lucide-react';
import type {BackendCapabilities} from './backendCapabilities';
import {fetchBackendCapabilities} from './backendCapabilities';
import {fetchParserPortProposal,type ParserPortProposal} from './portProposalClient';
import {startApprovedSyntheticSession,fetchApprovedSessionStatus,controlApprovedSession,
  changeApprovedSessionRate,extendApprovedSessionQuota,
  assertApprovedSessionReady,type ApprovedTestLabStatus} from './approvedTestLabSession';
import {queryApprovedInterflowReadback,assertInterflowReadbackCapability,
  type InterflowReadbackResult,type InterflowIndex} from './approvedInterflowReadback';

interface Props {
  projectId:string;
  listenerPort:number;
  sourceFormat:string;
  activeSession:ApprovedTestLabStatus|null;
  onSessionUpdate:(next:ApprovedTestLabStatus|null)=>void;
}
const APPROVAL=/^[A-Za-z0-9_.-]{8,96}$/;
const RUN=/^test_run_[0-9a-f]{32}$/;

/** Source-safe only-after-generation result operations.
 * No real target/apply endpoint from this component, no automatic network action.
 * Session and Interflow calls are independently authorized by the backend.
 */
export default function AutoParserResultTools({
  projectId,listenerPort,sourceFormat,activeSession,onSessionUpdate,
}:Props){
  const [port,setPort]=useState<ParserPortProposal|null>(null);
  const [portBusy,setPortBusy]=useState(false);
  const [portError,setPortError]=useState('');
  const [cap,setCap]=useState<BackendCapabilities|null>(null);
  const [sessionReady,setSessionReady]=useState<'unchecked'|'available'|'disabled'>('unchecked');
  const session=activeSession;
  const latestSession=useRef(activeSession);
  latestSession.current=activeSession;
  const [runId,setRunId]=useState('');
  const [approval,setApproval]=useState('');
  const [approved,setApproved]=useState(false);
  const [rate,setRate]=useState<1|2|5>(1);
  const [sessionBusy,setSessionBusy]=useState(false);
  const [sessionError,setSessionError]=useState('');
  const [newQuotaApproval,setNewQuotaApproval]=useState('');
  const [newRateApproval,setNewRateApproval]=useState('');
  const [requestedRate,setRequestedRate]=useState<0.2|1|2|5>(2);
  const [limitNotice,setLimitNotice]=useState('');
  const allowedToAdjust=Boolean(session&&
    ['RUNNING','PAUSED'].includes(session.state)&&
    Date.parse(session.leaseExpiresAt)>Date.now()&&
    cap&&sessionReady==='available'&&!sessionBusy);
  const [readAllowed,setReadAllowed]=useState(false);
  const [readPending,setReadPending]=useState(false);
  const [readError,setReadError]=useState('');
  const [readResult,setReadResult]=useState<InterflowReadbackResult|null>(null);
  const [index,setIndex]=useState<InterflowIndex>('syslog');
  const [marker,setMarker]=useState('test.run_id');
  const [field,setField]=useState('action');
  const [value,setValue]=useState('allow');
  const [lookback,setLookback]=useState<1|5|10>(5);
  const epoch=useRef(0);
  useEffect(()=>{
    epoch.current++;
    setPort(null);setPortError('');setCap(null);
    setSessionReady('unchecked');setRunId('');
    setApproval('');setApproved(false);setSessionError('');
    setNewQuotaApproval('');setNewRateApproval('');setLimitNotice('');
    setReadAllowed(false);setReadError('');setReadResult(null);
  },[projectId,listenerPort,sourceFormat]);

  useEffect(()=>{
    setNewQuotaApproval('');setNewRateApproval('');setLimitNotice('');
  },[activeSession?.runId]);

  async function checkPort(){
    if(portBusy)return;
    const current=epoch.current;
    setPortBusy(true);setPortError('');setPort(null);
    try{
      const format=sourceFormat==='syslog_rfc3164'||sourceFormat==='syslog_rfc5424'?
        sourceFormat:undefined;
      const plan=await fetchParserPortProposal(listenerPort,fetch,format);
      if(current===epoch.current&&plan.sensorIngestPort===listenerPort)setPort(plan);
      else if(current===epoch.current)setPortError('Port inventory did not match the generated CONF listener.');
    }catch{
      if(current===epoch.current)setPortError('Authorized inventory unavailable. Port occupancy and sensor listener are NOT VERIFIED.');
    }finally{if(current===epoch.current)setPortBusy(false);}
  }
  async function checkSession(){
    if(sessionBusy)return;
    const current=epoch.current;
    setSessionBusy(true);setSessionError('');setSessionReady('unchecked');
    try{
      const capability=await fetchBackendCapabilities();
      if(current!==epoch.current)return;
      try{assertApprovedSessionReady(capability);}
      catch{
        setSessionReady('disabled');
        setCap(null);
        return;
      }
      setCap(capability);setSessionReady('available');
    }catch{
      if(current===epoch.current){
        setCap(null);setSessionReady('disabled');
        setSessionError('The backend did not verify the operator, destination and audit policy.');
      }
    }finally{if(current===epoch.current)setSessionBusy(false);}
  }
  async function start(){
    if(!cap||sessionBusy||!approved||!APPROVAL.test(approval)||sessionReady!=='available')return;
    const current=epoch.current;
    setSessionBusy(true);setSessionError('');
    try{
      assertApprovedSessionReady(cap);
      const result=await startApprovedSyntheticSession(approval,rate,cap);
      if(current!==epoch.current)return;
      onSessionUpdate(result);setRunId(result.runId);setApproved(false);setApproval('');
    }catch{
      if(current===epoch.current)setSessionError('Backend independently denied the synthetic session or audit/sink policy.');
    }finally{if(current===epoch.current)setSessionBusy(false);}
  }
  async function sessionAction(action:'status'|'pause'|'resume'|'stop'){
    if(sessionBusy||!session||!RUN.test(session.runId))return;
    const current=epoch.current;
    setSessionBusy(true);setSessionError('');
    try{
      const result=action==='status'?
        await fetchApprovedSessionStatus(session.runId):
        await controlApprovedSession(session.runId,action);
      if(current===epoch.current)onSessionUpdate(result);
    }catch{
      if(current===epoch.current)setSessionError('Session request denied or owner verification unavailable.');
    }finally{if(current===epoch.current)setSessionBusy(false);}
  }
  async function extendQuota(){
    if(!session||!allowedToAdjust||!APPROVAL.test(newQuotaApproval))return;
    const current=epoch.current,originalId=session.runId;
    setSessionBusy(true);setSessionError('');setLimitNotice('');
    try{
      const updated=await extendApprovedSessionQuota(session,newQuotaApproval);
      if(current!==epoch.current||updated.runId!==originalId||
         latestSession.current?.runId!==originalId||
         !['RUNNING','PAUSED'].includes(latestSession.current.state))return;
      onSessionUpdate(updated);setNewQuotaApproval('');
      setLimitNotice('Backend verified exactly 20 additional events and an extended lease. Real sensor ingestion remains NOT VERIFIED.');
    }catch{
      if(current===epoch.current){
        setSessionError('Quota extension denied or unverified. No additional time or events are claimed.');
        setNewQuotaApproval('');
      }
    }finally{if(current===epoch.current)setSessionBusy(false);}
  }
  async function adjustRate(){
    if(!session||!allowedToAdjust||!APPROVAL.test(newRateApproval)||
       requestedRate===session.ratePerSecond)return;
    const current=epoch.current,originalId=session.runId;
    setSessionBusy(true);setSessionError('');setLimitNotice('');
    try{
      const updated=await changeApprovedSessionRate(session,newRateApproval,requestedRate);
      if(current!==epoch.current||updated.runId!==originalId||
         latestSession.current?.runId!==originalId||
         !['RUNNING','PAUSED'].includes(latestSession.current.state))return;
      onSessionUpdate(updated);setNewRateApproval('');
      setLimitNotice('Backend verified the approved bounded replay rate. Quota and lease remain unchanged.');
    }catch{
      if(current===epoch.current){
        setSessionError('Replay rate adjustment denied or unverified. The previous approved rate is retained.');
        setNewRateApproval('');
      }
    }finally{if(current===epoch.current)setSessionBusy(false);}
  }
  async function recover(){
    if(sessionBusy||!RUN.test(runId))return;
    const current=epoch.current;
    setSessionBusy(true);setSessionError('');
    try{
      const result=await fetchApprovedSessionStatus(runId);
      if(current===epoch.current)onSessionUpdate(result);
    }catch{
      if(current===epoch.current)setSessionError('No authorized owned session could be found. A run ID does not grant access.');
    }finally{if(current===epoch.current)setSessionBusy(false);}
  }
  async function compare(){
    if(readPending||!session||!cap||!readAllowed)return;
    const current=epoch.current;
    setReadPending(true);setReadError('');setReadResult(null);
    try{
      assertInterflowReadbackCapability(cap);
      const result=await queryApprovedInterflowReadback(cap,{
        runId:session.runId,index,markerField:marker,expectedField:field,
        expectedValue:value,lookbackMinutes:lookback,
      });
      if(current===epoch.current)setReadResult(result);
    }catch{
      if(current===epoch.current)setReadError(
        'Interflow readback unavailable or not independently authorized. No E2E result is claimed.');
    }finally{if(current===epoch.current)setReadPending(false);}
  }
  return <details className="auto-parser-recipe" aria-label="Authorized test and Interflow verification">
    <summary><Activity size={16}/> Receiving Port, Sensor Test &amp; Interflow · Separate Approval</summary>
    <p>Only after both DRAFT parser files have passed backend schema and SHA checks.
      These checks do not install a parser or prove a real sensor. The shared sensor destination
      and generated CONF listener use port <strong>{listenerPort}</strong>.</p>
    <div aria-label="Read-only parser port review">
      <button type="button" disabled={portBusy} onClick={()=>{void checkPort();}}>
        <ShieldCheck size={15}/> {portBusy?'Checking…':'Check Receiving Port Inventory (Read-only)'}
      </button>
      {port&&<p role="status">Provisional port {port.recommendedPort} · {port.status} ·
        {port.occupiedPorts.length} inventoried occupied ports ·
        {port.missingEvidence.length} evidence sources missing. No reservation or live listener verified.</p>}
      {portError&&<p role="status">{portError}</p>}
    </div>
    <div aria-label="Approved synthetic Sensor Replay">
      <h3>Sensor Replay · Fixed Synthetic Example Only</h3>
      <p>The development backend does not enable a sensor sender. A separately audited,
        IP-allowlisted operator-approved sink is required. No customer logs or target
        addresses are transferred from this browser.</p>
      <button type="button" disabled={sessionBusy} onClick={()=>{void checkSession();}}>
        {sessionBusy?'Checking…':'Check Sensor Test Authorization'}
      </button>
      {sessionReady==='disabled'&&<p role="status">
        <strong>DISABLED · Missing independent operator/sink/audit authorization.</strong>
        No send has occurred.
      </p>}
      {sessionReady==='available'&&!session&&<div className="two-path-approval">
        <p>Eligible backend detected. Start is still a separate operator-approved action.
          The fixture is fixed synthetic JSON, maximum 60 seconds / 100 events.</p>
        <label>Operator approval reference (not an API key)
          <input aria-label="Sensor replay approval reference" autoComplete="off"
            maxLength={96} value={approval}
            onChange={e=>{setApproval(e.target.value);setApproved(false);}}/>
        </label>
        <label>Maximum synthetic replay rate
          <select aria-label="Sensor replay rate" value={rate}
            onChange={e=>setRate(Number(e.target.value) as 1|2|5)}>
            {[1,2,5].map(r=><option key={r} value={r}>{r} / second</option>)}
          </select>
        </label>
        <label><input type="checkbox" aria-label="Confirm independent sensor test approval"
          checked={approved} onChange={e=>setApproved(e.target.checked)}/>
          I have independent authorization for this specific audited synthetic test.</label>
        <button type="button" disabled={!APPROVAL.test(approval)||!approved||sessionBusy}
          onClick={()=>{void start();}}>Start Approved Synthetic Session</button>
      </div>}
      {!session&&<div>
        <label>Existing owned session run ID
          <input aria-label="Existing result session run ID" value={runId}
            onChange={e=>setRunId(e.target.value)} maxLength={41}
            placeholder="test_run_0123456789abcdef0123456789abcdef"/>
        </label>
        <button type="button" disabled={!RUN.test(runId)||sessionBusy}
          onClick={()=>{void recover();}}>Look Up My Authorized Session</button>
      </div>}
      {session&&<div role="status" aria-label="Verified synthetic session status">
        <strong>{session.state} · {session.sentCount}/{session.maxEvents} delivery callbacks</strong>
        <p>Run {session.runId} · Sensor ingest NOT VERIFIED · Interflow indexing NOT VERIFIED</p>
        <button type="button" disabled={sessionBusy}
          onClick={()=>{void sessionAction('status');}}>Refresh</button>
        {session.state==='RUNNING'&&<button type="button" disabled={sessionBusy}
          onClick={()=>{void sessionAction('pause');}}>Pause</button>}
        {session.state==='PAUSED'&&<button type="button" disabled={sessionBusy}
          onClick={()=>{void sessionAction('resume');}}>Resume</button>}
        {['RUNNING','PAUSED'].includes(session.state)&&<button type="button"
          disabled={sessionBusy} onClick={()=>{void sessionAction('stop');}}>Stop</button>}
      </div>}
      {session&&['RUNNING','PAUSED'].includes(session.state)&&
      <details aria-label="Approved Test Lab quota and rate controls">
        <summary>Adjust approved replay rate or request additional quota</summary>
        <p>Each action needs its own new operator approval reference. The backend
          checks session ownership, audit policy and limits independently.
          Nothing renews, sends, or changes rate automatically.</p>
        {sessionReady!=='available'&&<p role="status">
          Check Sensor Test Authorization above to verify current management capability
          before changing an existing run.
        </p>}
        {Date.parse(session.leaseExpiresAt)<=Date.now()&&<p role="status">
          The reported lease deadline has passed. Only Stop or authenticated status
          refresh is available until the backend reports a new valid state.
        </p>}
        <div className="two-path-mapping-editor">
          <label>New independent quota approval reference
            <input aria-label="Quota renewal approval reference" autoComplete="off"
              value={newQuotaApproval} maxLength={96}
              onChange={e=>setNewQuotaApproval(e.target.value)}/>
          </label>
          <button type="button"
            disabled={!allowedToAdjust||!APPROVAL.test(newQuotaApproval)}
            onClick={()=>{void extendQuota();}}>
            Request Approved 60s / 20 Events
          </button>
        </div>
        <div className="two-path-mapping-editor">
          <label>New independent rate approval reference
            <input aria-label="Replay rate change approval reference"
              autoComplete="off" value={newRateApproval} maxLength={96}
              onChange={e=>setNewRateApproval(e.target.value)}/>
          </label>
          <label>Requested approved replay rate
            <select aria-label="Requested approved replay rate" value={requestedRate}
              onChange={e=>setRequestedRate(Number(e.target.value) as 0.2|1|2|5)}>
              {([0.2,1,2,5] as const).map(value=>
                <option key={value} value={value}>{value} events/sec</option>)}
            </select>
          </label>
          <button type="button" disabled={!allowedToAdjust||
            requestedRate===session.ratePerSecond||!APPROVAL.test(newRateApproval)}
            onClick={()=>{void adjustRate();}}>Change Approved Replay Rate</button>
        </div>
        {limitNotice&&<p role="status" aria-label="Verified Test Lab limit change">
          {limitNotice}
        </p>}
      </details>}
      {session&&['STOPPED','EXPIRED','FAILED','COMPLETED'].includes(session.state)&&
        <button type="button" onClick={()=>onSessionUpdate(null)}>
          Dismiss Finished Session
        </button>}
      {sessionError&&<p role="alert">{sessionError}</p>}
      {session&&<p>Authorized offline evidence can be reviewed from the
        session status area above, including after navigating away or reloading.
        A run ID alone never provides evidence access.</p>}
    </div>
    {session&&<details aria-label="Interflow field comparison after approved replay">
      <summary>Interflow · Read-only Field Check (Independent Authorization)</summary>
      <p>A session run ID does not provide permission to read tenant data.
        All query authorization, audit and scope enforcement belong to the backend.
        A matching field is NOT proof of actual sensor receipt or end-to-end parsing.</p>
      <div className="two-path-mapping-editor">
        <label>Interflow index
          <select aria-label="Interflow index" value={index}
            onChange={e=>setIndex(e.target.value as InterflowIndex)}>
            {(['session','threat','syslog','winlogevent'] as const)
              .map(item=><option key={item} value={item}>{item}</option>)}
          </select>
        </label>
        <label>Run marker field
          <input aria-label="Interflow marker field" maxLength={96} value={marker}
            onChange={e=>setMarker(e.target.value)}/>
        </label>
        <label>Expected normalized field
          <input aria-label="Interflow expected field" maxLength={96} value={field}
            onChange={e=>setField(e.target.value)}/>
        </label>
        <label>Expected text value
          <input aria-label="Interflow expected value" maxLength={128} value={value}
            onChange={e=>setValue(e.target.value)}/>
        </label>
        <label>Read lookback
          <select aria-label="Interflow lookback" value={lookback}
            onChange={e=>setLookback(Number(e.target.value) as 1|5|10)}>
            {([1,5,10] as const).map(x=><option key={x} value={x}>Last {x} min</option>)}
          </select>
        </label>
      </div>
      <label><input type="checkbox" checked={readAllowed}
        aria-label="Confirm independent Interflow read authorization"
        onChange={e=>setReadAllowed(e.target.checked)}/>
        I have independent authorization for this specific tenant read. No secrets entered.</label>
      <button type="button" disabled={!readAllowed||readPending}
        onClick={()=>{void compare();}}>Read Authorized Interflow Comparison</button>
      {readError&&<p role="alert">{readError}</p>}
      {readResult&&<p role="status">{readResult.state} ·
        {readResult.matchCount} matching records · end-to-end NOT VERIFIED</p>}
    </details>}
  </details>;
}
