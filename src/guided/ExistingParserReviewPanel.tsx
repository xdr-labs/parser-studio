import {useState} from 'react';
import type {ParserDraft} from '../model';
import {MAX_PROJECT_JSON_BYTES,reviewLocalProjectJson} from './localProjectImport';
import {inspectParserPair,type PairInspectionSummary} from './pairInspection';
import {buildPairImportReview,type PairImportReview} from './pairImportReview';
import {HelpTip} from './BeginnerHelp';

interface Props{onRestore:(draft:ParserDraft,label:string)=>void}
const PAIR_LIMIT=2*1024*1024;

async function strictText(file:File):Promise<string>{
 if(file.size===0||file.size>PAIR_LIMIT)throw new Error('Selected parser file is empty or exceeds 2 MiB.');
 return new TextDecoder('utf-8',{fatal:true}).decode(await file.arrayBuffer());
}

export default function ExistingParserReviewPanel({onRestore}:Props){
 const [projectName,setProjectName]=useState('');
 const [projectDraft,setProjectDraft]=useState<ParserDraft|null>(null);
 const [projectError,setProjectError]=useState('');
 const [fragment,setFragment]=useState<File|null>(null);
 const [conf,setConf]=useState<File|null>(null);
 const [pairBusy,setPairBusy]=useState(false);
 const [pairError,setPairError]=useState('');
 const [inspection,setInspection]=useState<PairInspectionSummary|null>(null);
 const [review,setReview]=useState<PairImportReview|null>(null);
 const [pairDraft,setPairDraft]=useState<ParserDraft|null>(null);

 async function reviewProject(file:File|undefined){
  setProjectDraft(null);setProjectError('');setProjectName(file?.name??'');
  if(!file)return;
  if(file.size===0||file.size>MAX_PROJECT_JSON_BYTES){
   setProjectError('Project JSON must be a non-empty file at most 256 KiB.');return;
  }
  try{
   const draft=reviewLocalProjectJson(new Uint8Array(await file.arrayBuffer()));
   setProjectDraft(draft);
  }catch(error){setProjectError(error instanceof Error?error.message:'Project JSON review failed.');}
 }
 function resetPair(){setInspection(null);setReview(null);setPairDraft(null);setPairError('');}
 async function inspectPair(){
  if(!fragment||!conf||pairBusy)return;
  resetPair();
  if(fragment.name.endsWith('.conf')||conf.name!==fragment.name+'.conf'){
   setPairError('Choose the extensionless customized_<slug> Ruby fragment and its matching .conf file.');return;
  }
  if(fragment.size+conf.size>PAIR_LIMIT){setPairError('Combined pair exceeds the 2 MiB inspection limit.');return;}
  setPairBusy(true);
  try{
   const [fragmentContent,confContent]=await Promise.all([strictText(fragment),strictText(conf)]);
   const checked=await inspectParserPair({name:fragment.name,fragmentContent,confContent});
   const report=buildPairImportReview(checked);
   let restored:ParserDraft|null=null;
   if(report.guidedImportAvailable&&checked.portableProject){
    restored=reviewLocalProjectJson(new TextEncoder().encode(JSON.stringify(checked.portableProject)));
   }
   setInspection(checked);setReview(report);setPairDraft(restored);
  }catch(error){setPairError(error instanceof Error?error.message:'Parser pair inspection failed.');}
  finally{setPairBusy(false);}
 }

 return <details className="auto-parser-recipe" aria-label="Existing parser review and import">
  <summary className="beginner-tool-summary">Open or inspect an existing parser
    <HelpTip label="Open or inspect an existing parser"
      text="Use this only when you already have a Parser Studio project or existing parser files. It is not needed when creating a new parser from logs."/>
  </summary>
  <span className="beginner-tool-when">Use when: you want to continue work from an existing parser instead of starting from raw logs.</span>
  <p>Parser Studio can reopen its own project file or inspect an existing parser pair without running it.
    Importing here never deploys, activates, or saves anything automatically. If the files cannot be safely edited,
    Parser Studio keeps them read-only and explains why.</p>
  <div className="two-path-mapping-editor" aria-label="Offline Project JSON review">
   <label>Parser Studio Project JSON
    <input type="file" accept=".json,application/json" aria-label="Existing Parser Project JSON"
     onChange={e=>{const file=e.currentTarget.files?.[0];e.currentTarget.value='';void reviewProject(file);}}/>
   </label>
   {projectDraft&&<div role="status" className="auto-parser-result">
    <strong>Project file checked · Ready to reopen</strong>
    <span>{projectName} · {projectDraft.name} · {projectDraft.mappings.length} field mapping{projectDraft.mappings.length===1?'':'s'}</span>
    <span>The project structure was checked locally. No sample logs were imported and nothing was tested against a live Stellar system.</span>
    <button type="button" aria-label="Restore Reviewed Project into Auto Parser"
      onClick={()=>onRestore(projectDraft,'Imported Project JSON · samples cleared')}>
      Open This Project in Auto Parser
    </button>
   </div>}
   {projectError&&<p role="alert">{projectError}</p>}
  </div>
  <div className="two-path-mapping-editor" aria-label="Existing parser file inspection">
   <label>Parser logic file <HelpTip label="Parser logic file"
     text="This is the extensionless customized_<name> file from an existing Stellar custom parser. Choose it only when you already have these parser files."/>
    <input type="file" aria-label="Existing parser logic file"
     onChange={e=>{setFragment(e.currentTarget.files?.[0]??null);resetPair();}}/>
   </label>
   <label>Matching listener configuration (.conf) <HelpTip label="Listener configuration"
     text="Choose the .conf file that belongs to the parser logic file above. Parser Studio checks the pair without executing it."/>
    <input type="file" accept=".conf,text/plain" aria-label="Existing parser listener configuration"
     onChange={e=>{setConf(e.currentTarget.files?.[0]??null);resetPair();}}/>
   </label>
   <button type="button" aria-label="Inspect Pair Read-only"
    disabled={!fragment||!conf||pairBusy} onClick={()=>void inspectPair()}>
    {pairBusy?'Checking files…':'Inspect files without running them'}
   </button>
   {review&&inspection&&<div role="status" className="auto-parser-result" aria-label="Existing parser pair review">
    <strong>{pairDraft?'Existing parser can be reopened safely':'Existing parser is available for inspection only'}</strong>
    <span>{inspection.sourceCount} input section{inspection.sourceCount===1?'':'s'} · listener port{inspection.ports.length===1?'':'s'} {inspection.ports.join(', ')||'not found'}</span>
    {review.findings.map(item=><span key={item.code}>{item.explanation}</span>)}
    <span>{review.advice}</span>
    <span>The files were inspected, not executed. Nothing was deployed or tested against a live Stellar system.</span>
    <details><summary>Technical file checks</summary>
      <span>Classification: {review.classification}</span>
      <span>Configuration SHA-256 {inspection.confSha256.slice(0,16)}… · Parser logic SHA-256 {inspection.fragmentSha256.slice(0,16)}…</span>
    </details>
    {pairDraft&&<button type="button" aria-label="Restore Exact Pair into Auto Parser"
      onClick={()=>onRestore(pairDraft,'Imported exact Ruby/CONF project · samples cleared')}>
      Open This Parser in Auto Parser
    </button>}
   </div>}
   {pairError&&<p role="alert">{pairError}</p>}
  </div>
 </details>;
}
