import {useEffect,useMemo,useState} from 'react';
import {Bot,FileText,History,LockKeyhole,Plus,WandSparkles} from 'lucide-react';
import {createDraft,type ParserDraft,type SuiteResult} from './model';
import AutoParser from './guided/AutoParser';
import ChatGPTAssist from './guided/ChatGPTAssist';
import LocalVersionsPanel from './guided/LocalVersionsPanel';
import type {LocalVersion} from './guided/localWorkspaceHistory';
import {HelpTip} from './guided/BeginnerHelp';
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
  const [versionsOpen,setVersionsOpen]=useState(false);
  const [restoredEpoch,setRestoredEpoch]=useState(0);
  const [datasetName,setDatasetName]=useState('No sample selected');
  const workingCopy=useMemo(()=>({datasetName,source:sample,draft}),
    [datasetName,sample,draft]);
  const restoreLocalVersion=(version:LocalVersion)=>{
    // All derivable previews/approvals must be rerun after restoring a snapshot.
    setSample(version.source);setDraft(structuredClone(version.draft));
    setDatasetName(version.datasetName);setWorkspace('auto');
    setAdvanced(false);setRestoredEpoch(old=>old+1);
  };
  const live=useLivePreview(sample,draft);
  const reset=()=>{
    if(sample.trim()&&!window.confirm('Clear the current sample and create a new parser?'))return;
    setDraft(createDraft());setSample('');setDatasetName('No sample selected');
    setWorkspace('auto');setAdvanced(false);
  };
  const preview=(candidate:ParserDraft,source?:string)=>runInWorker(source??sample,candidate);
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
            <button type="button" className="button secondary" aria-expanded={versionsOpen}
              aria-controls="local-version-workspace"
              onClick={()=>setVersionsOpen(value=>!value)}>
              <History size={16}/> Local Versions
            </button>
            <HelpTip label="Local Versions"
              text="Save logs, parser settings and field mappings only inside this browser. Compare multiple experiments or restore any saved version. No server storage or automatic external transfer."/>
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
      {versionsOpen&&<div id="local-version-workspace">
        <LocalVersionsPanel working={workingCopy}
          onRestore={restoreLocalVersion} onClose={()=>setVersionsOpen(false)}/>
      </div>}
      {live.error&&<p role="alert" className="auto-parser-warning">
        Local preview: {live.error}. Check the sample before generating a parser.
      </p>}
      {workspace==='auto'?<AutoParser key={restoredEpoch}
        draft={draft} setDraft={setDraft} sample={sample} setSample={setSample}
        datasetName={datasetName} setDatasetName={setDatasetName}
        suite={live.suite} pending={live.pending}
        runPreview={preview}
        onChatGPT={()=>setWorkspace('chatgpt')}
        advanced={advanced}
      />:<ChatGPTAssist key={restoredEpoch}
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
