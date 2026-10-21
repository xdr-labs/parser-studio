import {useEffect,useMemo,useState} from 'react';
import type {Dispatch,SetStateAction} from 'react';
import {ArrowRight,ClipboardCopy,FileText,ShieldAlert} from 'lucide-react';
import type {ParserDraft,SuiteResult} from '../model';
import {createPrivacySafeAIPrompt,importRecoveryAIRecipe,importReviewOnlyAIRecipe,
  proposeV01EnrichmentFromAI,proposeV01FieldMappingFromAI,proposeV01MappingCorrectionFromAI,
  proposeV01RecoveryParserFromAI,type AIImportResult} from './aiRecipeExchange';
import {compareCandidate,compareMappingCorrectionCandidate,type CandidateComparison} from './autoParserRegression';
import {analyzeLogEnvelopes,assessEnvelopeCompilation} from './autoParserEnvelope';
import {prepareAutoParserDraft} from './autoParserDraft';
import {buildReviewableRecipe} from './parserRecipeV2';
import {toBackendProject} from './backendAdapter';
import {fetchBackendCapabilities,assertBackendProjectSupported} from './backendCapabilities';
import {validateBackendProject,generateBackendPair,type GeneratedPair} from './backendClient';
import {verifyGeneratedPair} from './artifactPackageClient';
import {compileReviewedRecipeV02} from './recipeV2BackendClient';
import {HelpTip,StageGuide} from './BeginnerHelp';
import ParserListenerPortInput from './ParserListenerPortInput';
import {composeChatGPTPrompt} from './chatGptPromptBuilder';

interface Props {
  draft:ParserDraft;
  setDraft:Dispatch<SetStateAction<ParserDraft>>;
  sample:string;
  setSample:(text:string)=>void;
  suite?:SuiteResult;
  pending:boolean;
  runPreview:(draft:ParserDraft,source?:string)=>Promise<SuiteResult>;
  onAutoParser:()=>void;
}

const MAX_SAMPLE=64*1024;
const MAX_RECIPE=32768;

const completeSuite=(value:SuiteResult)=>value.counts.total>0&&
  value.counts.matched===value.counts.total&&value.counts.extracted===value.counts.total&&
  value.counts.normalized===value.counts.total&&value.counts.failures===0;

/** Prompt construction includes original logs only in browser memory.
 * Copying to the clipboard is the user's explicit action, never an API egress.
 */
export default function ChatGPTAssist({draft,setDraft,sample,setSample,suite,
  pending,runPreview,onAutoParser}:Props){
  const [goal,setGoal]=useState('Extract event time, action, source and destination IP, user and URL when present.');
  const [prompt,setPrompt]=useState('');
  const [promptError,setPromptError]=useState('');
  const [copied,setCopied]=useState(false);
  const [response,setResponse]=useState('');
  const [review,setReview]=useState<AIImportResult|null>(null);
  const [holdout,setHoldout]=useState('');
  const [holdoutAttested,setHoldoutAttested]=useState(false);
  const [candidateApproval,setCandidateApproval]=useState(false);
  const [comparison,setComparison]=useState<{candidate:ParserDraft;value:CandidateComparison;qualified:boolean}|null>(null);
  const [notice,setNotice]=useState('');
  const [busy,setBusy]=useState(false);
  const [context,setContext]=useState<{
    sample:string;draft:ParserDraft;suite:SuiteResult;
  }|null>(null);
  const [generated,setGenerated]=useState<{pair:GeneratedPair;draft:ParserDraft}|null>(null);
  const sourceKey=useMemo(()=>JSON.stringify([sample,draft]),[sample,draft]);
  useEffect(()=>{
    setPrompt('');setPromptError('');setCopied(false);setReview(null);
    setComparison(null);setNotice('');setContext(null);setGenerated(null);
    setHoldoutAttested(false);setCandidateApproval(false);
  },[sourceKey]);
  useEffect(()=>{
    setPrompt('');setCopied(false);setReview(null);setComparison(null);
    setNotice('');setContext(null);setGenerated(null);setHoldoutAttested(false);setCandidateApproval(false);
  },[goal]);

  async function prepare(){
    if(!suite||pending||busy||!sample.trim())return;
    setBusy(true);setPromptError('');setContext(null);setGenerated(null);
    try {
      let next=draft;
      let local=suite;
      if(!toBackendProject(draft).ok){
        // Format discovery is opportunistic. Even with a disconnected backend,
        // the user may prepare a manually copied prompt with an explicit raw-data warning.
        try{
          const ledger=analyzeLogEnvelopes(sample,'single-line');
          const capabilities=await fetchBackendCapabilities();
          const compilation=assessEnvelopeCompilation(ledger,capabilities);
          const reviewed=prepareAutoParserDraft(sample,draft,suite,ledger,compilation);
          if(reviewed.ok){
            next=reviewed.draft;
            local=await runPreview(next,sample);
          }
        }catch{
          // No provider call, no network egress and no guessed parser readiness.
        }
      }
      const prepared=await createPrivacySafeAIPrompt(sample,next,local);
      if(!prepared.ok){
        setPromptError('The local source needs review before preparing a prompt: '+prepared.reason);
        return;
      }
      const baseline=await buildReviewableRecipe(sample,next,local);
      setContext({sample,draft:next,suite:local});
      const projectId=baseline.ok?baseline.recipe.projectId:
        'draft-'+(next.guided??draft.guided)?.slug;
      setPrompt(composeChatGPTPrompt({
        goal,source:sample,sourceHash:prepared.sampleSha256,
        sourceCount:prepared.sourceCount,projectId,baseline,
      }));
    }catch{
      setPromptError('Could not prepare the reviewed AI prompt. No log data was transmitted.');
    }finally{setBusy(false);}
  }
  async function copyPrompt(){
    if(!prompt)return;
    try{await navigator.clipboard.writeText(prompt);setCopied(true);}
    catch{setPromptError('Clipboard unavailable. Select and copy the visible prompt manually.');}
  }
  async function validate(){
    if(!context||context.sample!==sample||pending||busy||!response.trim())return;
    setBusy(true);setReview(null);setComparison(null);setGenerated(null);setNotice('');
    try{
      const text=response.trim().replace(/^```(?:json)?\s*\n([\s\S]*?)\n```$/i,'$1').trim();
      if(!text.startsWith('{')){
        setNotice('ChatGPT returned a diagnosis, not a parser recipe. No rules were applied. Review the explanation, fix any malformed source logs and analyze again. Parser Studio will not invent a working parser.');
        return;
      }
      let result=await importReviewOnlyAIRecipe(text,sample,context.draft,context.suite);
      if(!result.ok&&result.reason==='CURRENT_RECIPE_UNAVAILABLE')
        result=await importRecoveryAIRecipe(text,sample,context.draft,context.suite);
      setReview(result);setHoldoutAttested(false);setCandidateApproval(false);
      if(!result.ok)setNotice('ChatGPT result rejected: '+result.reason+'. No parser rules changed.');
      else if(result.report.mode==='FULL_RECOVERY')
        setNotice('ChatGPT result is ready for testing. No parser changes have been applied yet.');
    }catch{setNotice('The AI response could not be validated. No rules changed.');}
    finally{setBusy(false);}
  }
  async function compareMapping(){
    if(!context||context.sample!==sample||!review||!review.ok||!holdout.trim()||busy||pending)return;
    if(!holdoutAttested){
      setNotice('Confirm that these additional test logs are different from the examples used to create the fix.');return;
    }
    if(new TextEncoder().encode(holdout).byteLength>MAX_SAMPLE){
      setNotice('The additional test logs exceed the local 64 KiB limit.');return;
    }
    let proposal:{ok:true;candidate:ParserDraft}|{ok:false;reason:string};
    let correctionScope:{oldTarget:string;newTarget:string}|undefined;
    if(review.report.mode==='FULL_RECOVERY')proposal=proposeV01RecoveryParserFromAI(review,context.draft);
    else{
      const additive=proposeV01FieldMappingFromAI(review,sample,context.draft,context.suite);
      if(additive.ok)proposal=additive;
      else{
        const correction=proposeV01MappingCorrectionFromAI(review,sample,context.draft,context.suite);
        if(correction.ok){proposal=correction;correctionScope={oldTarget:correction.oldTarget,newTarget:correction.newTarget};}
        else proposal=proposeV01EnrichmentFromAI(review,sample,context.draft,context.suite);
      }
    }
    if(!proposal.ok){
      setNotice('The proposed grammar cannot be translated into a supported parser: '+proposal.reason);
      return;
    }
    setBusy(true);setComparison(null);setCandidateApproval(false);setNotice('');
    try{
      const [candidate,baselineHoldout,candidateHoldout]=await Promise.all([
        runPreview(proposal.candidate,sample),
        runPreview(context.draft,holdout),
        runPreview(proposal.candidate,holdout),
      ]);
      const comparisonInput={source:sample,baseline:context.suite,candidate,
        holdout:{source:holdout,baseline:baselineHoldout,candidate:candidateHoldout}};
      const result=correctionScope?
        compareMappingCorrectionCandidate(comparisonInput,correctionScope):compareCandidate(comparisonInput);
      const qualified=result.acceptedWithoutRegression&&result.holdoutStatus==='TESTED'&&
        completeSuite(candidate)&&completeSuite(candidateHoldout);
      setComparison({candidate:proposal.candidate,value:result,qualified});
      if(!qualified)setNotice('The proposed fix did not pass both the original logs and the additional test logs. Existing parser rules are unchanged.');
      else setNotice('The proposed fix passed the original logs and the additional test logs. Review and approve it before applying.');
    }catch{setNotice('The additional-log test could not be completed. Existing parser rules remain unchanged.');}
    finally{setBusy(false);}
  }
  async function generateVerifiedDraft(){
    if(!context||context.sample!==sample||!review?.ok||pending||busy)return;
    const recovery=review.report.mode==='FULL_RECOVERY';
    const baseline=recovery?null:await buildReviewableRecipe(sample,context.draft,context.suite);
    if(!recovery&&(!baseline||!baseline.ok)){setNotice('No validated baseline is available. No files generated.');return;}
    const unchanged=!recovery&&baseline?.ok&&JSON.stringify(baseline.recipe)===JSON.stringify(review.candidate);
    if(!unchanged&&(!comparison?.qualified||comparison.value.holdoutStatus!=='TESTED'||!candidateApproval)){
      setNotice('Test the proposed fix with different log examples and approve the result before applying it.');
      return;
    }
    const candidate=unchanged?context.draft:comparison!.candidate;
    setBusy(true);setGenerated(null);setNotice('');
    try{
      const local=await runPreview(candidate,sample);
      if(!completeSuite(local))
        throw new Error('The complete sample did not pass local parsing and normalization.');
      const adapted=toBackendProject(candidate);
      if(!adapted.ok)throw new Error('The proposed parser cannot be represented by the current backend.');
      const cap=await fetchBackendCapabilities();
      assertBackendProjectSupported(adapted.project,cap);
      const validated=await validateBackendProject(adapted.project);
      if(!validated.ok)throw new Error('Backend schema rejected the reviewed parser.');
      const pair=await generateBackendPair(adapted.project);
      await verifyGeneratedPair(pair);
      const exact=await buildReviewableRecipe(sample,candidate,local);
      if(!exact.ok||JSON.stringify(exact.recipe)!==JSON.stringify(review.candidate))
        throw new Error('The AI proposal differs from the compiler-owned validated recipe.');
      await compileReviewedRecipeV02({
        recipe:review.candidate,legacyProject:adapted.project,
      },pair);
      setGenerated({pair,draft:candidate});
      setNotice('Parser files created after the local sample checks passed. Nothing was installed automatically.');
    }catch{
      setNotice('Parser Studio could not safely create files from this ChatGPT result. No files were released and no parser rules were changed.');
    }finally{setBusy(false);}
  }
  const download=(filename:string,content:string)=>{
    const url=URL.createObjectURL(new Blob([content],{type:'application/octet-stream'}));
    const anchor=document.createElement('a');
    anchor.href=url;anchor.download=filename;document.body.append(anchor);anchor.click();anchor.remove();
    window.setTimeout(()=>URL.revokeObjectURL(url),1000);
  };
  const baselineUnchanged=Boolean(review?.ok&&context&&
    review.report.addedMappings===0&&review.report.removedMappings===0&&
    review.report.changedStageCount===0);
  return <main className="auto-parser-workspace" aria-label="ChatGPT Assisted Parser">
    <header className="auto-parser-intro">
      <span className="pane-index">CHATGPT ASSISTED PARSER · MANUAL COPY & PASTE</span>
      <h1>Use ChatGPT for unfamiliar logs.</h1>
      <p>Paste logs locally, copy the prepared prompt into ChatGPT, then paste the JSON result here.
        Parser Studio tests the result before it can change or create any parser files.</p>
    </header>
    <div className="auto-parser-body">
      <section aria-label="ChatGPT preparation">
        <h2>1. Prepare your logs</h2>
        <StageGuide title="Use ChatGPT when Auto Parser needs help">
          Paste the original log records below. Parser Studio will put these exact records in
          the ChatGPT prompt so it can analyze the real format, not a substitute example.
        </StageGuide>
        <ParserListenerPortInput draft={draft} setDraft={setDraft}/>
        <label>Original local logs
          <textarea aria-label="ChatGPT local sample logs" rows={6} spellCheck={false}
            maxLength={MAX_SAMPLE} value={sample}
            placeholder="Paste the logs you want to parse."
            onChange={e=>setSample(e.target.value)}/>
        </label>
        <label>What do you want Parser Studio to find? <HelpTip label="What should be extracted?"
          text="Describe the values you care about in plain language, for example: source IP, destination IP, username, action, URL, process name, or event ID. You do not need to know Stellar field names yet."/>
          <input aria-label="ChatGPT desired fields" maxLength={512} type="text"
            value={goal} onChange={e=>setGoal(e.target.value)}/>
        </label>
        <p className="auto-parser-warning" role="alert">
          <ShieldAlert size={17}/> The prepared prompt will include your original log text,
          potentially including IP addresses, account names, identifiers or other sensitive
          information. Review your logs before copying the prompt into ChatGPT.
          No data is sent to ChatGPT automatically.
        </p>
        <button type="button" className="auto-parser-primary"
          disabled={!sample.trim()||!suite||pending||busy}
          onClick={()=>{void prepare();}}>Prepare ChatGPT Prompt</button>
        {promptError&&<p role="alert" className="auto-parser-warning">{promptError}</p>}
        {prompt&&<div className="auto-parser-recipe" aria-label="ChatGPT prepared prompt">
          <h3>2. Copy to ChatGPT</h3>
          <textarea aria-label="ChatGPT copyable prompt" rows={10} value={prompt}
            onChange={e=>{setPrompt(e.target.value);setCopied(false);}}/>
          <button type="button" onClick={()=>{void copyPrompt();}}>
            <ClipboardCopy size={15}/> Copy Prompt</button>
          {copied&&<p role="status">Prompt copied by your action. Paste it into ChatGPT.</p>}
          <p><a href="https://chatgpt.com/" target="_blank" rel="noopener noreferrer">
            Open ChatGPT in a new tab</a></p>
        </div>}
      </section>
      <section aria-label="ChatGPT result review">
        <h2>3. Paste the ChatGPT result</h2>
        <p>Paste the JSON result from ChatGPT. Parser Studio checks it before any parser rule can change.</p>
        <textarea aria-label="ChatGPT result JSON" rows={8} maxLength={MAX_RECIPE}
          spellCheck={false} value={response} onChange={e=>{
            setResponse(e.target.value);setReview(null);setComparison(null);setGenerated(null);setNotice('');setHoldoutAttested(false);setCandidateApproval(false);
          }} placeholder="Paste the JSON result from ChatGPT here."/>
        <button type="button" disabled={!response.trim()||!context||pending||busy}
          onClick={()=>{void validate();}}>Check ChatGPT Result</button>
        {notice&&<p role="status" className="auto-parser-note">{notice}</p>}
        {review?.ok&&<div aria-label="ChatGPT result ready for testing" className="auto-parser-result">
          <strong>ChatGPT result accepted for testing · {review.report.sampleEvents} source event{review.report.sampleEvents===1?'':'s'}</strong>
          <span>No parser rules have changed yet.</span>
          <details className="auto-parser-recipe">
            <summary>Technical change details</summary>
            <span>{review.report.addedMappings} suggested mappings · {review.report.changedStageCount} changed stages ·
              {review.report.mode==='FULL_RECOVERY'?' full parser recovery':' baseline-safe edit'}</span>
          </details>
          <label>Different examples to test the fix <HelpTip label="Different test examples"
            text="Use logs from the same product and event type that were not used in the ChatGPT prompt. Parser Studio checks whether the proposed fix works beyond the examples that created it."/>
            <textarea aria-label="Additional ChatGPT test logs" rows={4}
              maxLength={MAX_SAMPLE} value={holdout} onChange={e=>{
                setHoldout(e.target.value);setHoldoutAttested(false);setCandidateApproval(false);setComparison(null);setGenerated(null);
              }}/>
          </label>
          {!baselineUnchanged&&<label className="auto-parser-persist-label">
            <input type="checkbox" aria-label="Confirm test examples are different"
              checked={holdoutAttested} onChange={e=>{setHoldoutAttested(e.target.checked);setCandidateApproval(false);setComparison(null);}}/>
            These are different log examples from the ones used to create this fix.
          </label>}
          {!baselineUnchanged&&<button type="button" disabled={!holdout.trim()||!holdoutAttested||busy||pending}
            onClick={()=>{void compareMapping();}}>Test Proposed Fix</button>}
          {comparison&&<div role="status" aria-label="ChatGPT fix test result">
            <span>Original logs still pass: {comparison.value.acceptedWithoutRegression?'YES':'NO'}</span>
            <span>Additional logs tested: {comparison.value.holdoutStatus==='TESTED'?'YES':'NO'}</span>
            <span>Overall test: {comparison.qualified?'PASS':'FAILED'}</span>
          </div>}
          {!baselineUnchanged&&comparison?.qualified&&<label className="auto-parser-persist-label">
            <input type="checkbox" aria-label="Approve tested ChatGPT fix"
              checked={candidateApproval} onChange={e=>setCandidateApproval(e.target.checked)}/>
            I reviewed the test result and approve applying this fix.
          </label>}
          <button type="button" className="auto-parser-primary"
            disabled={busy||pending||(!baselineUnchanged&&(!comparison?.qualified||!candidateApproval))}
            onClick={()=>{void generateVerifiedDraft();}}>
            {busy?'Creating parser files…':'Apply Fix & Create Parser Files'} <ArrowRight size={15}/>
          </button>
          {generated&&<div className="auto-parser-download"
             aria-label="ChatGPT created parser files">
            <strong>Parser files created successfully</strong>
            <span>The current logs and additional examples passed the Parser Studio checks. Nothing was installed automatically.</span>
            <details className="auto-parser-recipe">
              <summary>Technical verification details</summary>
              <span>Two parser files passed integrity checks before download.</span>
            </details>
            {generated.pair.files.map(file=><button type="button" key={file.name}
              onClick={()=>download(file.name,file.content)}>
              <FileText size={15}/> Download {file.name}</button>)}
            <button type="button" onClick={()=>{
              setDraft(generated.draft);
              onAutoParser();
            }}>Review Fields in Auto Parser</button>
          </div>}
        </div>}
      </section>
      <p className="auto-parser-note"><ShieldAlert size={16}/>
        If ChatGPT returns something Parser Studio cannot safely use, no parser changes are made.
        Revise the result or return to Auto Parser.</p>
      <button type="button" onClick={onAutoParser}>
        <FileText size={15}/> Return to Auto Parser
      </button>
    </div>
  </main>;
}
