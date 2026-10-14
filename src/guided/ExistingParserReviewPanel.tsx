import {useState} from 'react';
import type {ParserDraft} from '../model';
import {MAX_PROJECT_JSON_BYTES,reviewLocalProjectJson} from './localProjectImport';
import {inspectParserPair,type PairInspectionSummary} from './pairInspection';
import {buildPairImportReview,type PairImportReview} from './pairImportReview';

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
  <summary>Advanced · Review Existing Parser or Project</summary>
  <p>This does not add another creation method. Exact Parser Studio Project JSON can be reviewed locally.
    Ruby/CONF inspection is explicit, same-origin and read-only: the backend never executes imported Ruby and
    opaque legacy pairs remain read-only. Restoring always clears current raw samples and never saves automatically.</p>
  <div className="two-path-mapping-editor" aria-label="Offline Project JSON review">
   <label>Parser Studio Project JSON
    <input type="file" accept=".json,application/json" aria-label="Existing Parser Project JSON"
     onChange={e=>{const file=e.currentTarget.files?.[0];e.currentTarget.value='';void reviewProject(file);}}/>
   </label>
   {projectDraft&&<div role="status" className="auto-parser-result">
    <strong>EXACT PROJECT JSON · LOCAL REVIEW PASS</strong>
    <span>{projectName} · {projectDraft.name} · {projectDraft.format.toUpperCase()} · {projectDraft.mappings.length} mappings</span>
    <span>No raw samples were imported · Native and Stellar target NOT VERIFIED</span>
    <button type="button" onClick={()=>onRestore(projectDraft,'Imported Project JSON · samples cleared')}>
      Restore Reviewed Project into Auto Parser
    </button>
   </div>}
   {projectError&&<p role="alert">{projectError}</p>}
  </div>
  <div className="two-path-mapping-editor" aria-label="Ruby and CONF pair inspection">
   <label>Extensionless Ruby fragment
    <input type="file" aria-label="Existing Parser Ruby fragment"
     onChange={e=>{setFragment(e.currentTarget.files?.[0]??null);resetPair();}}/>
   </label>
   <label>Matching CONF file
    <input type="file" accept=".conf,text/plain" aria-label="Existing Parser CONF file"
     onChange={e=>{setConf(e.currentTarget.files?.[0]??null);resetPair();}}/>
   </label>
   <button type="button" disabled={!fragment||!conf||pairBusy} onClick={()=>void inspectPair()}>
    {pairBusy?'Inspecting Read-only…':'Inspect Pair Read-only'}
   </button>
   {review&&inspection&&<div role="status" className="auto-parser-result" aria-label="Existing parser pair review">
    <strong>{review.classification} · {review.guidedImportAvailable?'EXACT RESTORE AVAILABLE':'READ-ONLY'}</strong>
    <span>{inspection.protocols.join(' + ')||'No supported receiver'} · ports {inspection.ports.join(', ')||'none'} · {inspection.sourceCount} sources</span>
    <span>CONF SHA-256 {inspection.confSha256.slice(0,16)}… · Ruby SHA-256 {inspection.fragmentSha256.slice(0,16)}…</span>
    {review.findings.map(item=><span key={item.code}>{item.code} · {item.explanation}</span>)}
    <span>{review.advice}</span>
    <span>Imported Ruby is never executed · Native parser / sensor / Stellar target NOT VERIFIED</span>
    {pairDraft&&<button type="button" onClick={()=>onRestore(pairDraft,'Imported exact Ruby/CONF project · samples cleared')}>
      Restore Exact Pair into Auto Parser
    </button>}
   </div>}
   {pairError&&<p role="alert">{pairError}</p>}
  </div>
 </details>;
}
