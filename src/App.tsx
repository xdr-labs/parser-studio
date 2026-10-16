import {useEffect,useMemo,useRef,useState} from 'react';
import {Bot,FileText,LockKeyhole,Plus,WandSparkles} from 'lucide-react';
import {createDraft,type ParserDraft,type SuiteResult} from './model';
import AutoParser from './guided/AutoParser';
import {controlApprovedSession,fetchApprovedSessionStatus,reconcileApprovedSession,
  type ApprovedTestLabStatus} from './guided/approvedTestLabSession';
import ChatGPTAssist from './guided/ChatGPTAssist';
import {HelpTip} from './guided/BeginnerHelp';
import TestLabEvidencePanel from './guided/TestLabEvidencePanel';
import {MAX_DATASET_BYTES} from './parser';

type Workspace='auto'|'chatgpt';
type PreviewState={key:string;suite?:SuiteResult;error?:string};

/** One isolated browser worker for both parser creation paths.
 * No backend calls, LLM egress or sensor delivery occur during live preview.
 */
function runInWorker(raw:string,draft:ParserDraft):Promise<SuiteResult>{
  if(new TextEncoder().encode(raw).byteLength>MAX_DATASET_BYTES)
    return Promise.reject(new Error('The local log sample is larger than 64 KiB.'));
  return new Promise((resolve,reject)=>{
    if(typeof Worker==='undefined'){
      reject(new Error('This browser cannot start the private parser preview.'));return;
    }
    const worker=new Worker(new URL('./preview.worker.ts',import.meta.url),{type:'module'});
    let finished=false;
    const end=()=>{finished=true;window.clearTimeout(deadline);worker.terminate();};
    const deadline=window.setTimeout(()=>{
      if(!finished){end();reject(new Error('The local parser preview timed out.'));}
    },15000);
    worker.onmessage=(event:MessageEvent<{suite?:SuiteResult;error?:string}>)=>{
      if(finished)return;
      end();
      if(event.data.suite)resolve(event.data.suite);
      else reject(new Error(event.data.error??'The preview could not be completed.'));
    };
    worker.onerror=()=>{
      if(!finished){end();reject(new Error('The browser preview worker failed.'));}
    };
    worker.postMessage({raw,draft});
  });
}
function useLivePreview(sample:string,draft:ParserDraft){
  const key=useMemo(()=>JSON.stringify([sample,draft]),[sample,draft]);
  const [latest,setLatest]=useState<PreviewState|null>(null);
  useEffect(()=>{
    let cancelled=false;
    const timer=window.setTimeout(()=>{
      void runInWorker(sample,draft).then(suite=>{
        if(!cancelled)setLatest({key,suite});
      }).catch(error=>{
        if(!cancelled)setLatest({key,error:error instanceof Error?error.message:'Preview unavailable'});
      });
    },120);
    return ()=>{cancelled=true;window.clearTimeout(timer);};
  },[sample,draft,key]);
  return {suite:latest?.key===key?latest.suite:undefined,
    pending:latest?.key!==key,error:latest?.key===key?latest.error:undefined};
}

/** Final v2.0 product navigation intentionally exposes exactly TWO paths.
 * The old Wizard and three-pane Workbench remain in version history, not UI.
 */
export default function App(){
  const [workspace,setWorkspace]=useState<Workspace>(()=>
    new URLSearchParams(window.location.search).get('workspace')==='chatgpt'?
      'chatgpt':'auto');
  const [draft,setDraft]=useState<ParserDraft>(()=>createDraft());
  const [sample,setSample]=useState('');
  const [advanced,setAdvanced]=useState(false);
  // Owned run state survives switching either parser authoring method.
  // An active audited backend sender NEVER stops merely by changing screens.
  const [activeSession,setActiveSession]=useState<ApprovedTestLabStatus|null>(null);
  const updateSessionSafely=(next:ApprovedTestLabStatus|null)=>
    setActiveSession(previous=>reconcileApprovedSession(previous,next));
  const [stopBusy,setStopBusy]=useState(false);
  const [stopError,setStopError]=useState('');
  const [recoveryId,setRecoveryId]=useState('');
  const [recoverBusy,setRecoverBusy]=useState(false);
  const [recoverError,setRecoverError]=useState('');
  const [recoverNotice,setRecoverNotice]=useState('');
  const runIdSafe=/^test_run_[0-9a-f]{32}$/.test(recoveryId);
  const recoveryEpoch=useRef(0);
  const latestRun=useRef(activeSession);
  latestRun.current=activeSession;
  const sessionRunning=activeSession&&
    (activeSession.state==='RUNNING'||activeSession.state==='PAUSED');
  useEffect(()=>()=>{recoveryEpoch.current++;},[]);

  // Refresh deliberately never resumes or queries a session automatically.
  // An ID is a locator, not a grant: the backend must reauthorize this GET.
  const recoverApprovedSession=async()=>{
    if(!runIdSafe||recoverBusy||sessionRunning)return;
    const requestedId=recoveryId, ticket=++recoveryEpoch.current;
    setRecoverBusy(true);setRecoverError('');setRecoverNotice('');
    try{
      const status=await fetchApprovedSessionStatus(requestedId);
      const current=latestRun.current;
      if(ticket!==recoveryEpoch.current||
         (current&&['RUNNING','PAUSED'].includes(current.state)))return;
      if((status.state==='RUNNING'||status.state==='PAUSED')&&
        Date.parse(status.leaseExpiresAt)<=Date.now())
        setRecoverNotice('The reported lease deadline has passed. Stop remains available until the backend confirms termination.');
      else if(['EXPIRED','STOPPED','FAILED','COMPLETED'].includes(status.state))
        setRecoverNotice('The backend reports a finished run. No active delivery is verified; there is no Stop action to issue.');
      else setRecoverNotice('Owned run verified for this browser session. Real sensor ingestion remains NOT VERIFIED.');
      setActiveSession(status);
    }catch{
      if(ticket===recoveryEpoch.current)
        setRecoverError('Run lookup denied, expired, or returned untrusted metadata. Ownership was not verified and no session was recovered.');
    }finally{if(ticket===recoveryEpoch.current)setRecoverBusy(false);}
  };
  useEffect(()=>setStopError(''),[activeSession?.runId]);

  const stopApprovedSession=async()=>{
    if(!sessionRunning||stopBusy)return;
    const expectedRunId=activeSession.runId;
    setStopBusy(true);setStopError('');
    try{
      const result=await controlApprovedSession(expectedRunId,'stop');
      setActiveSession(prev=>prev?.runId===expectedRunId?result:prev);
      if(!['RUNNING','PAUSED'].includes(result.state))
        setRecoverNotice('The backend confirmed a finished session. No active delivery is verified.');
      if(result.state==='RUNNING'||result.state==='PAUSED')
        setStopError('Stop is not yet confirmed by the backend. The session may still be active.');
    }catch{
      setStopError('Backend Stop is unconfirmed. Check session ownership and retry before leaving the test.');
    }finally{setStopBusy(false);}
  };
  const [datasetName,setDatasetName]=useState('No sample selected');
  const live=useLivePreview(sample,draft);
  const reset=()=>{
    if(sample.trim()&&!window.confirm('Clear the current sample and create a new parser?'))return;
    setDraft(createDraft());setSample('');setDatasetName('No sample selected');
    setWorkspace('auto');setAdvanced(false);
  };
  const preview=(candidate:ParserDraft,source?:string)=>runInWorker(source??sample,candidate);
  const downloadSafeEvidence=(filename:string,content:string,mediaType:string)=>{
    if(!/^testlab-evidence-test_run_[0-9a-f]{32}\.json$/.test(filename)||
       mediaType!=='application/json;charset=utf-8'||
       new TextEncoder().encode(content).byteLength>1024*1024)
      throw new Error('The approved evidence download contract is invalid.');
    const blob=new Blob([content],{type:mediaType});
    const url=URL.createObjectURL(blob);
    const link=document.createElement('a');
    link.href=url;link.download=filename;document.body.append(link);
    link.click();link.remove();
    window.setTimeout(()=>URL.revokeObjectURL(url),1000);
  };
  return <div className="app-shell two-path-shell">
    <aside className="nav-rail two-path-nav" aria-label="Parser Studio navigation">
      <div className="brand-symbol" aria-label="Parser Studio"><FileText size={23}/></div>
      <div className="rail-group" aria-label="Parser creation menu and help">
        <div className="rail-item-with-help">
          <button type="button" className={'rail-link '+(workspace==='auto'?'selected':'')}
            aria-current={workspace==='auto'?'page':undefined}
            onClick={()=>setWorkspace('auto')}>
            <WandSparkles size={20}/><span>Auto Parser</span>
          </button>
          <HelpTip label="Automatic parsing help"
            text="Use this for almost every new parser. Paste representative logs and follow the four guided steps. Parser Studio will ask for help only when a log cannot be handled safely."/>
        </div>
        <div className="rail-item-with-help">
          <button type="button" className={'rail-link '+(workspace==='chatgpt'?'selected':'')}
            aria-current={workspace==='chatgpt'?'page':undefined}
            onClick={()=>setWorkspace('chatgpt')}>
            <Bot size={20}/><span>ChatGPT Assisted Parser</span>
          </button>
          <HelpTip label="AI-assisted parsing help"
            text="Use this when Auto Parser says a log still needs a parsing rule or when you want help understanding an unfamiliar format. You copy and paste the proposed fix; nothing is sent automatically."/>
        </div>
      </div>
      <div className="rail-footer"><LockKeyhole size={17}/><span>LOCAL WORKSPACE</span></div>
    </aside>
    <div className="app-main">
      <header className="topbar two-path-header">
        <div className="topbar-identity">
          <div className="crumb-icon"><WandSparkles size={19}/></div>
          <div>
            <span className="eyebrow">XDR LABS / PARSER STUDIO</span>
            <div className="header-title">Create a custom parser. <span>No coding required.</span></div>
          </div>
        </div>
        <div className="topbar-actions">
          <span className="context-flag"><span className="status-dot"/> Logs stay in this browser by default
            <HelpTip label="Local workspace privacy"
              text="Auto Parser analysis happens locally unless you explicitly choose a feature that says it will send data elsewhere. ChatGPT Assisted uses manual copy and paste."/></span>
          <span className="topbar-help-action">
            <button type="button" className="button secondary"
              aria-label={advanced?'Return to Beginner Mode – hide Tools & Diagnostics':'Advanced Tools & Diagnostics'}
              aria-pressed={advanced} onClick={()=>setAdvanced(value=>!value)}>
              {advanced?'Hide Tools':'Tools & Diagnostics'}
            </button>
            <HelpTip label="When should I open Tools & Diagnostics?"
              text="Open this only when normal Auto Parser guidance is not enough, or when you need to inspect an existing parser, multi-line boundaries, repeated text patterns, or technical evidence."/>
          </span>
          <span className="topbar-help-action">
            <button type="button" className="button secondary" onClick={reset}>
              <Plus size={16}/> New Parser
            </button>
            <HelpTip label="What does New Parser do?"
              text="Starts over with a clean parser draft. If you already pasted logs, Parser Studio asks before clearing them."/>
          </span>
        </div>
      </header>
      {advanced&&<details className="two-path-recovery" aria-label="Authorized Test Lab session recovery">
        <summary>Recover a previous parser test session
          <HelpTip label="Recover a previous test session"
            text="Use this only if you started a test session earlier, refreshed the page, and need to see that same session again. It does not start a new parser test."/></summary>
        <p>A page refresh can hide a test session that is still running on the local Parser Studio service.
          Enter its run ID to check that same session again. Parser Studio does not search for sessions automatically.</p>
        <div className="two-path-recovery-controls">
          <label>Previous test run ID
            <input type="text" aria-label="Existing authorized Test Lab run ID"
              value={recoveryId} maxLength={41} autoComplete="off" spellCheck={false}
              placeholder="test_run_0123456789abcdef0123456789abcdef"
              onChange={event=>{
                recoveryEpoch.current++;setRecoverBusy(false);
                setRecoveryId(event.target.value);setRecoverError('');setRecoverNotice('');
              }}/>
          </label>
          <button type="button" className="button secondary"
            disabled={!runIdSafe||recoverBusy||Boolean(sessionRunning)}
            onClick={()=>{void recoverApprovedSession();}}>
            {recoverBusy?'Checking previous run…':'Check Previous Run'}
          </button>
        </div>
        {sessionRunning&&<p role="status">
          An active session is already displayed above. Stop it before looking up another run.
        </p>}
        {recoverError&&<p role="alert">{recoverError}</p>}
        {recoverNotice&&<p role="status" aria-label="Recovered Test Lab result">
          {recoverNotice}
        </p>}
        {activeSession&&!sessionRunning&&<p role="status"
          aria-label="Authorized terminal Test Lab session">
          Backend status: {activeSession.state} · No verified sensor ingestion.
          A terminal run cannot be resumed by this screen.
        </p>}
      </details>}
      {sessionRunning&&<div role="status" className="two-path-session-banner"
        aria-label="Active Test Lab session indicator">
        <div>
          <strong>Approved synthetic Test Lab · {activeSession.state}</strong>
          <p>Changing screens does not stop server delivery.
            Run {activeSession.runId} · Sensor ingest NOT VERIFIED.</p>
          {stopError&&<p role="alert">{stopError}</p>}
        </div>
        <button type="button" className="button secondary"
          disabled={stopBusy} onClick={()=>{void stopApprovedSession();}}>
          {stopBusy?'Confirming Stop…':'Stop Server Session Now'}
        </button>
      </div>}
      {activeSession&&<section className="two-path-session-evidence"
        aria-label="Authorized Test Lab offline evidence">
        <TestLabEvidencePanel runId={activeSession.runId}
          onDownload={downloadSafeEvidence}/>
      </section>}
      {live.error&&<p role="alert" className="auto-parser-warning">
        Local preview: {live.error}. Check the sample before generating a parser.
      </p>}
      {workspace==='auto'?<AutoParser
        draft={draft} setDraft={setDraft} sample={sample} setSample={setSample}
        datasetName={datasetName} setDatasetName={setDatasetName}
        suite={live.suite} pending={live.pending}
        runPreview={preview}
        activeSession={activeSession} onSessionUpdate={updateSessionSafely}
        onChatGPT={()=>setWorkspace('chatgpt')}
        advanced={advanced}
      />:<ChatGPTAssist
        draft={draft} setDraft={setDraft} sample={sample} setSample={value=>{
          setSample(value);setDatasetName('ChatGPT local samples');
        }}
        suite={live.suite} pending={live.pending}
        runPreview={preview}
        onAutoParser={()=>setWorkspace('auto')}
      />}
    </div>
  </div>;
}
