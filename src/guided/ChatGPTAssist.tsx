import {useEffect,useMemo,useState} from 'react';
import {extractRecipeJson} from './aiReplyExtract';
import {describeNonJsonReply,describeRejectedReply,describeFailedCheck,COPY_DAMAGE_HINT} from './chatGptResultNotice';
import type {Dispatch,SetStateAction} from 'react';
import {ArrowRight,ClipboardCopy,FileText,ShieldAlert} from 'lucide-react';
import type {ParserDraft,SuiteResult} from '../model';
import {createPrivacySafeAIPrompt,describeEnrichmentDenial,importRecoveryAIRecipe,importReviewOnlyAIRecipe,
  proposeV01EnrichmentFromAI,proposeV01FieldMappingFromAI,proposeV01MappingCorrectionFromAI,
  proposeV01RecoveryParserFromAI,type AIImportResult} from './aiRecipeExchange';
import {compareCandidate,compareMappingCorrectionCandidate,describeScopedTypeChange,normalizedMappingOutputPath,typeChangeWording,type CandidateComparison} from './autoParserRegression';
import {explainRejectedChatGPTFix,originalLogsStillPass} from './chatGptFailureExplanation';
import {analyzeLogEnvelopes,assessEnvelopeCompilation} from './autoParserEnvelope';
import {prepareAutoParserDraft} from './autoParserDraft';
import {buildReviewableRecipe} from './parserRecipeV2';
import {toBackendProject} from './backendAdapter';
import {fetchBackendCapabilities,assertBackendProjectSupported} from './backendCapabilities';
import {validateBackendProject,generateBackendPair,type GeneratedPair} from './backendClient';
import {verifyGeneratedPair} from './artifactPackageClient';
import {compileReviewedRecipeV02,canonicalJson} from './recipeV2BackendClient';
import {HelpTip,StageGuide} from './BeginnerHelp';
import ParserIdentityCard from './ParserIdentityCard';
import NamedLogTypesPanel from './NamedLogTypesPanel';
import ChatGPTConditionalDraft from './ChatGPTConditionalDraft';
import {validateNamedLogs,type NamedLogType} from './namedLogTypes';
import {buildPromptSourceEvidence} from './chatGptSourceEvidence';
import {buildEventCoverageEvidence} from './chatGptEventCoverage';
import {reviewedSourcePromptContext,checkNamedParserCoverage,
  type AssistedSolutionInfo} from './chatGptSourceContext';
import {composeChatGPTPrompt} from './chatGptPromptBuilder';
import {buildAdaptiveRetryPrompt,summarizeHoldoutFailures,type AdaptiveRepairFailure,type RetryEvidence} from './chatGptAdaptiveRepair';
import {buildSingleSampleVariation,hasExtractedVariationTarget,
  verifySingleSampleVariation} from './singleSampleVariation';

interface Props {
  draft:ParserDraft;
  setDraft:Dispatch<SetStateAction<ParserDraft>>;
  sample:string;
  setSample:(text:string)=>void;
  namedLogTypes?:NamedLogType[]|null;
  onEnableNamedLogTypes?:()=>void;
  onChangeNamedLogTypes?:(groups:NamedLogType[])=>void;
  onExitNamedLogTypes?:()=>void;
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

/** The raw source is put in a prompt only in browser memory.
 * Sending the generated prompt to an external AI remains a manual copy action.
 */
export default function ChatGPTAssist({draft,setDraft,sample,setSample,suite,
  pending,runPreview,onAutoParser,namedLogTypes=null,onEnableNamedLogTypes,
  onChangeNamedLogTypes,onExitNamedLogTypes}:Props){
  const [goal,setGoal]=useState('Extract event time, action, source and destination IP, user and URL when present.');
  const [prompt,setPrompt]=useState('');
  const [promptError,setPromptError]=useState('');
  const [copied,setCopied]=useState(false);
  const [response,setResponse]=useState('');
  const [attempt,setAttempt]=useState<1|2|3>(1);
  const [retryFailure,setRetryFailure]=useState<{
    failure:AdaptiveRepairFailure;diagnostic?:string;evidence?:RetryEvidence;
  }|null>(null);
  const [review,setReview]=useState<AIImportResult|null>(null);
  const [holdout,setHoldout]=useState('');
  const [holdoutAttested,setHoldoutAttested]=useState(false);
  const [candidateApproval,setCandidateApproval]=useState(false);
  const [comparison,setComparison]=useState<{
    candidate:ParserDraft;value:CandidateComparison;qualified:boolean;
    evidence:'SAMPLE_ONLY'|'INDEPENDENT';fieldsPreview:string;
    variation:'PASS'|'FAIL'|'NOT_APPLICABLE';
  }|null>(null);
  const [notice,setNotice]=useState('');
  const [busy,setBusy]=useState(false);
  const [context,setContext]=useState<{
    sample:string;draft:ParserDraft;suite:SuiteResult;basePrompt:string;
  }|null>(null);
  const [generated,setGenerated]=useState<{
    pair:GeneratedPair;draft:ParserDraft;evidence:'SAMPLE_ONLY'|'INDEPENDENT'|'UNCHANGED';
  }|null>(null);
  const sourceKey=useMemo(()=>JSON.stringify([sample,draft,namedLogTypes]),
    [sample,draft,namedLogTypes]);
  const namedValidation=namedLogTypes?validateNamedLogs(namedLogTypes):null;
  const namedReady=!namedValidation||(namedValidation.ok&&namedLogTypes!.length>=2);
  // One source of truth across both creation methods. Untouched demo metadata
  // is not falsely presented to ChatGPT as a real security-product identity.
  const declaredInfo:AssistedSolutionInfo={
    vendor:draft.vendor==='Demo Local Draft'?'':draft.vendor,
    product:draft.name==='Untitled parser'?'':draft.name,
    version:draft.version==='1.0.0'?'':draft.version??'',
    delivery:'',
  };
  const reviewedContext=reviewedSourcePromptContext(declaredInfo,null);
  const namedSummary=namedLogTypes&&namedLogTypes.length>=2
    ?'User-declared log type names and original event-group sizes (not independent parser evidence):\n'+
      JSON.stringify(namedLogTypes.map(group=>({
        name:group.name.replace(/[\u0000-\u001f\u007f]/g,' ').slice(0,120),
        byteLength:new TextEncoder().encode(group.sample).byteLength,
      })))+
      '\nGroup names are NOT discriminators. Require explicit source event-type values and reject-unknown behavior before a shared parser is approved.'
    :'';
  useEffect(()=>{
    setPrompt('');setPromptError('');setCopied(false);setReview(null);
    setComparison(null);setNotice('');setContext(null);setGenerated(null);
    setHoldoutAttested(false);setCandidateApproval(false);
    setAttempt(1);setRetryFailure(null);setResponse('');
  },[sourceKey]);
  useEffect(()=>{
    setPrompt('');setCopied(false);setReview(null);setComparison(null);
    setNotice('');setContext(null);setGenerated(null);setHoldoutAttested(false);setCandidateApproval(false);
    setAttempt(1);setRetryFailure(null);setResponse('');
  },[goal]);

  async function prepare(){
    if(!suite||pending||busy||!sample.trim()||draft.eventProfiles)return;
    if(!namedReady){
      setPromptError('Complete at least two valid named log types before preparing one combined parser.');
      return;
    }
    if(!reviewedContext.ok){setPromptError(reviewedContext.reason);return;}
    setBusy(true);setPromptError('');setContext(null);setGenerated(null);
    try {
      let next=draft;
      let local=suite;
      if(!toBackendProject(draft).ok){
        // Format discovery is opportunistic. Even with a disconnected backend,
        // the user may prepare a manually copied source prompt with a privacy warning.
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
      const projectId=baseline.ok?baseline.recipe.projectId:
        'draft-'+(next.guided??draft.guided)?.slug;
      const basePrompt=composeChatGPTPrompt({
        goal,source:sample,sourceHash:prepared.sampleSha256,
        sourceCount:prepared.sourceCount,projectId,baseline,
        extraContext:reviewedContext.text+(namedSummary?'\n'+namedSummary:''),
        sourceEvidence:buildPromptSourceEvidence(sample).text,
        eventCoverageEvidence:buildEventCoverageEvidence(sample,next,local).text,
      });
      setContext({sample,draft:next,suite:local,basePrompt});
      setPrompt(basePrompt);setAttempt(1);setRetryFailure(null);
    }catch{
      setPromptError('Could not prepare the reviewed AI prompt. No log data was transmitted.');
    }finally{setBusy(false);}
  }
  async function copyPrompt(){
    if(!prompt)return;
    try{await navigator.clipboard.writeText(prompt);setCopied(true);}
    catch{setPromptError('Clipboard unavailable. Select and copy the visible prompt manually.');}
  }
  async function copyImprovedPrompt(){
    if(!context||!retryFailure||!response.trim()||pending||busy||attempt>=3)return;
    const nextAttempt=(attempt+1) as 2|3;
    try{
      const updated=buildAdaptiveRetryPrompt({
        basePrompt:context.basePrompt,previousResponse:response,
        attempt:nextAttempt,...retryFailure,
      });
      setPrompt(updated);setAttempt(nextAttempt);setRetryFailure(null);
      setResponse('');setReview(null);setComparison(null);setGenerated(null);
      setCandidateApproval(false);setHoldoutAttested(false);setCopied(false);
      try{
        await navigator.clipboard.writeText(updated);
        setCopied(true);
        setNotice('Improved attempt '+nextAttempt+' prompt copied. Paste it into ChatGPT, then bring back the complete JSON.');
      }catch{
        setNotice('Improved attempt '+nextAttempt+' prompt prepared. Clipboard unavailable: copy the visible prompt manually.');
      }
    }catch{
      setNotice('Could not prepare a safe retry. Original parser rules remain unchanged.');
    }
  }

  async function validate(){
    if(!context||context.sample!==sample||pending||busy||!response.trim())return;
    setBusy(true);setReview(null);setComparison(null);setGenerated(null);setNotice('');setRetryFailure(null);
    try{
      // ChatGPT often wraps the recipe in explanation. Pick out the one JSON recipe and
      // ignore the surrounding prose; the recipe itself is still fully validated below.
      const extracted=extractRecipeJson(response);
      if(!extracted){
        const nonJson=describeNonJsonReply(response.trim());
        setRetryFailure({failure:'NON_JSON_RESPONSE',diagnostic:nonJson.diagnostic});
        setNotice(nonJson.notice);
        return;
      }
      const text=extracted.text;
      let result=await importReviewOnlyAIRecipe(text,sample,context.draft,context.suite);
      if(!result.ok&&result.reason==='CURRENT_RECIPE_UNAVAILABLE')
        result=await importRecoveryAIRecipe(text,sample,context.draft,context.suite);
      setReview(result);setHoldoutAttested(false);setCandidateApproval(false);
      if(!result.ok){
        const failure:AdaptiveRepairFailure=result.reason==='SOURCE_IDENTITY_MISMATCH'
          ?'SOURCE_IDENTITY_MISMATCH':
          (result.reason==='INVALID_JSON'||result.reason==='UNTRUSTED_RECIPE')
            ?'SCHEMA_REJECTED':'RECIPE_UNSUPPORTED';
        setRetryFailure({failure,diagnostic:result.reason});
        setNotice(describeRejectedReply(result.reason));
      }else if(result.report.mode==='FULL_RECOVERY')
        setNotice('ChatGPT result is ready for testing. No parser changes have been applied yet.'+
          (extracted.ignoredText?' Text around the JSON recipe was ignored.':''));
      else if(extracted.ignoredText)setNotice('Text around the JSON recipe was ignored.');
    }catch{
      setRetryFailure({failure:'SCHEMA_REJECTED',diagnostic:'INVALID_JSON'});
      setNotice('The AI response could not be validated. No rules changed. '+COPY_DAMAGE_HINT);
    }finally{setBusy(false);}
  }
  async function compareMapping(sourceOnly=false){
    if(!context||context.sample!==sample||!review||!review.ok||busy||pending)return;
    if(sourceOnly&&holdout.trim()){
      setNotice('To use the source-only path, clear the additional test examples.');return;
    }
    if(!sourceOnly&&!holdout.trim())return;
    if(!sourceOnly&&!holdoutAttested){
      setNotice('Confirm that the additional examples are different from the original logs.');return;
    }
    if(!sourceOnly&&new TextEncoder().encode(holdout).byteLength>MAX_SAMPLE){
      setNotice('The additional test logs exceed the local 64 KiB limit.');return;
    }
    let proposal:{ok:true;candidate:ParserDraft}|{ok:false;reason:string;field?:string};
    let correctionScope:{oldTarget:string;newTarget:string}|undefined;
    if(review.report.mode==='FULL_RECOVERY')
      proposal=proposeV01RecoveryParserFromAI(review,context.draft);
    else{
      const additive=proposeV01FieldMappingFromAI(review,sample,context.draft,context.suite);
      if(additive.ok)proposal=additive;
      else{
        const correction=proposeV01MappingCorrectionFromAI(
          review,sample,context.draft,context.suite);
        if(correction.ok){
          proposal=correction;
          correctionScope={
            oldTarget:normalizedMappingOutputPath(context.draft,correction.mappingId),
            newTarget:normalizedMappingOutputPath(correction.candidate,correction.mappingId),
          };
        }else proposal=proposeV01EnrichmentFromAI(
          review,sample,context.draft,context.suite);
      }
    }
    if(!proposal.ok){
      setRetryFailure({failure:'RECIPE_UNSUPPORTED',diagnostic:proposal.reason});
      setNotice(describeEnrichmentDenial(proposal.reason,proposal.field)??
        'The proposed grammar cannot be translated into a supported parser: '+proposal.reason);
      return;
    }
    setBusy(true);setComparison(null);setCandidateApproval(false);setNotice('');
    setRetryFailure(null);
    try{
      const candidate=await runPreview(proposal.candidate,sample);
      const variationCandidate=sourceOnly
        ?buildSingleSampleVariation(sample,proposal.candidate.format):null;
      const changed=variationCandidate&&hasExtractedVariationTarget(variationCandidate,candidate)
        ?variationCandidate:null;
      const changedSuite=changed?await runPreview(proposal.candidate,changed.mutatedSource):null;
      const changedOk=!changed||Boolean(changedSuite&&
        verifySingleSampleVariation(changed,candidate,changedSuite));
      const variation=changed?(changedOk?'PASS' as const:'FAIL' as const):'NOT_APPLICABLE' as const;
      const baselineHoldout=sourceOnly?null:await runPreview(context.draft,holdout);
      const candidateHoldout=sourceOnly?null:await runPreview(proposal.candidate,holdout);
      const input=baselineHoldout&&candidateHoldout
        ?{source:sample,baseline:context.suite,candidate,
            holdout:{source:holdout,baseline:baselineHoldout,candidate:candidateHoldout}}
        :{source:sample,baseline:context.suite,candidate};
      const result=correctionScope
        ?compareMappingCorrectionCandidate(input,correctionScope)
        :compareCandidate(input);
      const typeChange=correctionScope?describeScopedTypeChange(input,correctionScope):null;
      const typeSuites=namedLogTypes
        ?await Promise.all(namedLogTypes.map(group=>runPreview(proposal.candidate,group.sample)))
        :[];
      const typeCoverage=namedLogTypes
        ?checkNamedParserCoverage(proposal.candidate,namedLogTypes,typeSuites)
        :{ok:true as const};
      const qualified=result.acceptedWithoutRegression&&
        result.holdoutStatus===(sourceOnly?'NOT_SUPPLIED':'TESTED')&&
        completeSuite(candidate)&&changedOk&&
        (sourceOnly||Boolean(candidateHoldout&&completeSuite(candidateHoldout)))&&
        typeCoverage.ok;
      const evidence=sourceOnly?'SAMPLE_ONLY' as const:'INDEPENDENT' as const;
      const fieldsPreview=JSON.stringify(candidate.events.slice(0,10).map(event=>({
        sourceLine:event.line,extracted:event.fields,normalized:event.normalized,
        status:event.status,
      })),null,2).slice(0,12000);
      setComparison({candidate:proposal.candidate,value:result,qualified,evidence,fieldsPreview,variation});
      if(!typeCoverage.ok)
        setNotice('Log type review required: '+typeCoverage.reason+' No rules changed.');
      else if(result.holdoutStatus==='REJECTED'&&result.holdoutIndependence&&!result.holdoutIndependence.ok){
        setRetryFailure(null);
        setNotice('The additional examples were not accepted, so they were not used to test this fix. No rules changed. See the reason below.');
      }else if(!qualified){
        setRetryFailure({
          failure:sourceOnly
            ?(variation==='FAIL'?'SYNTHETIC_VALUE_FAILURE':'SAMPLE_REGRESSION')
            :'HOLDOUT_REGRESSION',
          diagnostic:sourceOnly
            ?(variation==='FAIL'?'SYNTHETIC_VARIANT_FAILED':'SOURCE_TEST_FAILED')
            :'HOLDOUT_FAILED',
          evidence:{
            sourceEvents:result.baseline.sourceCount,
            sourcePassed:result.baseline.positiveAfter,
            regressions:result.baseline.regressions,
            removedFields:result.baseline.fieldRemovals,
            typeChanges:result.baseline.typeChanges,
            holdoutStatus:result.holdoutStatus,
            observedOutput:fieldsPreview.slice(0,4096),
            ...(variation==='FAIL'&&changed?{syntheticProbe:JSON.stringify({
              originalValue:changed.previousValue,
              substitutedValue:changed.replacementValue,
              result:'FAILED_NOT_INDEPENDENT',
            })}:{}),
            ...(candidateHoldout?{observedHoldout:summarizeHoldoutFailures(
              candidateHoldout.events.filter(e=>e.status!=='pass'||!e.extracted||!e.normalizedOk)
                .map(e=>({line:e.line,raw:e.raw,fields:e.fields,normalized:e.normalized,diagnostics:e.diagnostics})))}:{}),
          },
        });
        setNotice(sourceOnly
          ?(variation==='FAIL'&&completeSuite(candidate)
            ?'The original sample passed, but the controlled value variation failed. The parser may overfit the exact input value. No rules changed.'
            :'The original sample failed parser validation; no rules changed.')
          :(typeChange
            ?'Fix not applied: the proposed fix would change the type of the corrected field ('+typeChangeWording(typeChange)+'), and a fix that only changes a type is not applied here. To change a field\'s type, use Map Fields. No rules changed.'
            :'The original and independent examples did not both pass; no rules changed.'));
      }else setNotice(sourceOnly
        ?'The original sample passed. Review its extracted fields before accepting a sample-only DRAFT; generalization was not tested.'
        :'Original and independent examples passed. Review and approve the fix.');
    }catch{
      setRetryFailure({failure:'SAMPLE_REGRESSION',diagnostic:'SOURCE_TEST_FAILED'});
      setNotice('Candidate validation failed. Existing rules remain unchanged.');
    }finally{setBusy(false);}
  }
  async function generateVerifiedDraft(){
    if(!context||context.sample!==sample||!review?.ok||pending||busy||draft.eventProfiles)return;
    if(review.candidate.sourceFormat==='regex'||review.candidate.bodyFormat==='regex'){
      setGenerated(null);setRetryFailure(null);
      setNotice('Browser parsing may pass, but native Regex parser export is blocked for the current Stellar Cyber 7.0 target (Ruby 2.4.9). This runtime has no bounded Regexp timeout. No files were generated; use a supported non-Regex source format.');
      return;
    }
    const recovery=review.report.mode==='FULL_RECOVERY';
    const baseline=recovery?null:await buildReviewableRecipe(sample,context.draft,context.suite);
    if(!recovery&&(!baseline||!baseline.ok)){setNotice('No validated baseline is available. No files generated.');return;}
    const unchanged=!recovery&&baseline?.ok&&canonicalJson(baseline.recipe)===canonicalJson(review.candidate);
    const acceptable=Boolean(comparison?.qualified&&(
      comparison.evidence==='INDEPENDENT'&&comparison.value.holdoutStatus==='TESTED'||
      comparison.evidence==='SAMPLE_ONLY'&&comparison.value.holdoutStatus==='NOT_SUPPLIED'));
    if(!unchanged&&(!acceptable||!candidateApproval)){
      setNotice('Validate the proposal on your original sample (and any independent examples) and explicitly approve the evidence level before creating a DRAFT.');
      return;
    }
    const candidate=unchanged?context.draft:comparison!.candidate;
    setBusy(true);setGenerated(null);setNotice('');
    try{
      const local=await runPreview(candidate,sample);
      if(!completeSuite(local))
        throw new Error('The complete sample did not pass local parsing and normalization.');
      if(namedLogTypes){
        const perType=await Promise.all(namedLogTypes.map(group=>
          runPreview(candidate,group.sample)));
        const groupCoverage=checkNamedParserCoverage(candidate,namedLogTypes,perType);
        if(!groupCoverage.ok){
          setNotice('Cannot create one parser yet: '+groupCoverage.reason+' No files were generated.');
          return;
        }
      }
      const adapted=toBackendProject(candidate);
      if(!adapted.ok)throw new Error('The proposed parser cannot be represented by the current backend.');
      const cap=await fetchBackendCapabilities();
      assertBackendProjectSupported(adapted.project,cap);
      const validated=await validateBackendProject(adapted.project);
      if(!validated.ok)throw new Error('Backend schema rejected the reviewed parser.');
      const pair=await generateBackendPair(adapted.project);
      await verifyGeneratedPair(pair);
      const exact=await buildReviewableRecipe(sample,candidate,local);
      if(!exact.ok||canonicalJson(exact.recipe)!==canonicalJson(review.candidate))
        throw new Error('The AI proposal differs from the compiler-owned validated recipe.');
      // Restricted Recipe v0.2 excludes conditional event routing.
      // Those DRAFTs must use the separately reviewed conditional builder.
      if(candidate.eventProfiles)
        throw new Error('Conditional recipes cannot be compiled through v0.2.');
      await compileReviewedRecipeV02({
        recipe:review.candidate,legacyProject:adapted.project,
      },pair);
      setGenerated({pair,draft:candidate,
        evidence:unchanged?'UNCHANGED':comparison!.evidence});
      setNotice('DRAFT parser files created after local checks. No deployment or target compatibility is implied.');
    }catch{
      setRetryFailure({failure:'NATIVE_VALIDATION_FAILED',
        diagnostic:'NATIVE_VALIDATION_FAILED'});
      setNotice('Parser Studio could not safely create files from this ChatGPT result. No files were released and no parser rules were changed.');
    }finally{setBusy(false);}
  }
  const download=(filename:string,content:string)=>{
    const url=URL.createObjectURL(new Blob([content],{type:'application/octet-stream'}));
    const anchor=document.createElement('a');
    anchor.href=url;anchor.download=filename;document.body.append(anchor);anchor.click();anchor.remove();
    window.setTimeout(()=>URL.revokeObjectURL(url),1000);
  };
  // A reviewed Regex can pass local and independent holdout examples,
  // but it cannot produce a safe parser on the observed Ruby 2.4.9 target.
  // This is a target/runtime limitation, never a request to try another
  // Regex prompt or a claim that the browser preview was wrong.
  const regexTargetBlocked=Boolean(review?.ok&&(
    review.candidate.sourceFormat==='regex'||review.candidate.bodyFormat==='regex'));
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
          Paste actual logs from each event type your security product emits:
          for example traffic, IPS, antivirus, VPN, authentication or system events.
          The copied prompt keeps your original examples; it cannot prove parsing
          of an event type that you did not provide.
        </StageGuide>
        {onEnableNamedLogTypes&&onChangeNamedLogTypes&&onExitNamedLogTypes&&
          <div className="chatgpt-named-source" aria-label="Combine multiple log types">
            <NamedLogTypesPanel groups={namedLogTypes}
              onEnable={onEnableNamedLogTypes}
              onChange={onChangeNamedLogTypes} onExit={onExitNamedLogTypes}/>
          </div>}
        <label>{namedLogTypes?'Combined original logs (local preview, read only)':'Original local logs'}
          <textarea aria-label="ChatGPT local sample logs" rows={6} spellCheck={false}
            maxLength={MAX_SAMPLE} value={sample} readOnly={Boolean(namedLogTypes)}
            placeholder="Paste the logs you want to parse."
            onChange={e=>{if(!namedLogTypes)setSample(e.target.value);}}/>
        </label>
        <ParserIdentityCard draft={draft} setDraft={setDraft} assisted/>
        {namedLogTypes&&namedLogTypes.length>=2&&
          <section className="auto-parser-recipe" aria-label="Combined parser routing review">
            <ChatGPTConditionalDraft draft={draft} setDraft={setDraft} sample={sample}
              suite={suite} pending={pending} runPreview={runPreview}
              namedLogTypes={namedLogTypes} onAutoParser={onAutoParser}/>
            <p>If the review requests a supported source format, select it in Auto Parser,
              then return here with your combined logs preserved.</p>
            <button type="button" className="auto-parser-secondary" onClick={onAutoParser}>Review shared extraction format in Auto Parser</button>
          </section>}
        {draft.eventProfiles&&<p role="note" className="auto-parser-warning">
          A reviewed conditional parser is configured. Use the separate
          Validate &amp; Generate One Multi-Type Parser control above.
          ParserRecipe v0.2 does not represent type-specific mappings.
        </p>}
        <label>What do you want Parser Studio to find? <HelpTip label="What should be extracted?"
          text="Describe the values you care about in plain language, for example: source IP, destination IP, username, action, URL, process name, or event ID. You do not need to know Stellar field names yet."/>
          <input aria-label="ChatGPT desired fields" maxLength={512} type="text"
            value={goal} onChange={e=>setGoal(e.target.value)}/>
        </label>
        <p className="auto-parser-warning" role="alert">
          <ShieldAlert size={17}/> The ChatGPT prompt includes your original log text,
          which may contain IP addresses, account names and other sensitive information.
          Review your logs before copying. Nothing is sent to ChatGPT automatically.
        </p>
        {!namedReady&&<p role="alert" className="auto-parser-warning">
          Complete two or more valid named log types before preparing a combined parser.</p>}
        {!reviewedContext.ok&&<p role="alert" className="auto-parser-warning">
          {reviewedContext.reason}</p>}
        <button type="button" className="auto-parser-primary"
          disabled={!sample.trim()||!namedReady||!reviewedContext.ok||!suite||pending||busy||
            Boolean(draft.eventProfiles)}
          onClick={()=>{void prepare();}}>Prepare ChatGPT Prompt</button>
        {promptError&&<p role="alert" className="auto-parser-warning">{promptError}</p>}
        {prompt&&<div className="auto-parser-recipe" aria-label="ChatGPT prepared prompt">
          <h3>2. Copy to ChatGPT{attempt>1?' · Attempt '+attempt+' of 3':''}</h3>
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
        <h2>{prompt?'3. Paste the ChatGPT result':'After preparing the prompt: paste ChatGPT’s JSON result'}</h2>
        <p>Paste the JSON result from ChatGPT. Parser Studio checks it before any parser rule can change.</p>
        <textarea aria-label="ChatGPT result JSON" rows={8} maxLength={MAX_RECIPE}
          spellCheck={false} value={response} onChange={e=>{
            setResponse(e.target.value);setReview(null);setComparison(null);setGenerated(null);setRetryFailure(null);setNotice('');setHoldoutAttested(false);setCandidateApproval(false);
          }} placeholder="Paste the JSON result from ChatGPT here."/>
        <button type="button" disabled={!response.trim()||!context||pending||busy}
          className="auto-parser-secondary" onClick={()=>{void validate();}}>Check ChatGPT Result</button>
        {notice&&<p role="status" className="auto-parser-note">{notice}</p>}
        {retryFailure&&attempt<3&&context&&<div className="auto-parser-recipe" aria-label="ChatGPT adaptive repair">
          <p>Parser Studio found a problem: {describeFailedCheck(retryFailure.failure)}. The next prompt includes original logs, the previous response and local failure evidence. If additional test logs were supplied, relevant excerpts may be included. Review sensitive information before copying.</p>
          <button type="button" disabled={busy||pending}
            onClick={()=>{void copyImprovedPrompt();}}>
            <ClipboardCopy size={15}/> Copy Improved Prompt · Attempt {attempt+1} of 3
          </button>
        </div>}
        {retryFailure&&attempt===3&&<p role="status">
          Three attempts reached. Preserve the original logs and review the unresolved fields; no rule was changed automatically.
        </p>}
        {review?.ok&&<div aria-label="ChatGPT result ready for testing" className="auto-parser-result">
          <strong>ChatGPT result accepted for testing · {review.report.sampleEvents} source event{review.report.sampleEvents===1?'':'s'}</strong>
          <span>No parser rules have changed yet.</span>
          <details className="auto-parser-recipe">
            <summary>Technical change details</summary>
            <span>{review.report.addedMappings} suggested mappings · {review.report.changedStageCount} changed stages ·
              {review.report.mode==='FULL_RECOVERY'?' full parser recovery':' baseline-safe edit'}</span>
          </details>
          <label>Different examples to test the fix <HelpTip label="Different test examples"
            text="Use new, independently collected examples from every relevant event type. Parser Studio tests the complete combined source and rechecks each named type separately."/>
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
          {!baselineUnchanged&&!holdout.trim()&&<button type="button" className="auto-parser-secondary" disabled={busy||pending}
            onClick={()=>{void compareMapping(true);}}>Test Original Sample Only</button>}
          {!baselineUnchanged&&<button type="button" className="auto-parser-secondary" disabled={!holdout.trim()||!holdoutAttested||busy||pending}
            onClick={()=>{void compareMapping(false);}}>Test Proposed Fix</button>}
          {comparison&&<div role="status" aria-label="ChatGPT fix test result">
            <span>Original logs still pass: {originalLogsStillPass(comparison.value)?'YES':'NO'}</span>
            <span>Additional logs tested: {comparison.value.holdoutStatus==='TESTED'?'YES':'NO'}</span>
            <span>Evidence level: {comparison.evidence==='SAMPLE_ONLY'?'ORIGINAL SAMPLE ONLY':'INDEPENDENT EXAMPLES'}</span>
            {comparison.evidence==='SAMPLE_ONLY'&&<span>Controlled value variation: {comparison.variation} (synthetic check, not an independent log)</span>}
            <span>Overall test: {comparison.qualified?(comparison.evidence==='SAMPLE_ONLY'?'SAMPLE PASS (NOT GENERALIZED)':'PASS'):'FAILED'}</span>
            {!comparison.qualified&&<span aria-label="ChatGPT fix rejection details">
              {explainRejectedChatGPTFix({baseline:comparison.value.baseline,
                holdout:comparison.value.holdout,holdoutIndependence:comparison.value.holdoutIndependence})}
            </span>}
            {comparison.qualified&&<details>
              <summary>Review actual extracted fields before approval</summary>
              <pre className="auto-parser-recipe">{comparison.fieldsPreview}</pre>
            </details>}
          </div>}
          {!baselineUnchanged&&comparison?.qualified&&<label className="auto-parser-persist-label">
            <input type="checkbox" aria-label={comparison.evidence==='SAMPLE_ONLY'
              ?'Approve sample-only draft':'Approve tested ChatGPT fix'}
              checked={candidateApproval} onChange={e=>setCandidateApproval(e.target.checked)}/>
            {comparison.evidence==='SAMPLE_ONLY'
              ?'I reviewed the extracted fields and approve a sample-only DRAFT. No independent examples or target validation were performed.'
              :'I reviewed the test result and approve applying this fix.'}
          </label>}
          {regexTargetBlocked&&<p className="auto-parser-warning" role="alert">
            Regex passed only the browser-level review. Native parser files and
            ZIP export are blocked for the current Stellar Cyber 7.0 target
            (Ruby 2.4.9): bounded Regexp execution is unsupported.
            Use a supported non-Regex source format; retrying the same
            Regex through ChatGPT cannot enable this runtime capability.
          </p>}
          <button type="button" className="auto-parser-primary"
            disabled={regexTargetBlocked||busy||pending||
              (!baselineUnchanged&&(!comparison?.qualified||!candidateApproval))}
            onClick={()=>{void generateVerifiedDraft();}}>
            {busy?'Creating parser files…':'Apply Fix & Create Parser Files'} <ArrowRight size={15}/>
          </button>
          {generated&&<div className="auto-parser-download"
             aria-label="ChatGPT created parser files">
            <strong>Parser files created successfully</strong>
            <span>{generated.evidence==='UNCHANGED'
              ?'The unchanged previously reviewed parser passed local checks. No different holdout examples were tested in this step.'
              :generated.evidence==='SAMPLE_ONLY'
                ?'DRAFT qualified only against the original input sample. Generalization and Stellar Cyber target behavior remain NOT VERIFIED.'
                :'Original and independently supplied log examples passed local checks. Stellar Cyber target behavior remains NOT VERIFIED.'} Nothing was installed automatically.</span>
            <details className="auto-parser-recipe">
              <summary>Technical verification details</summary>
              <span>Two parser files passed integrity checks before download.</span>
            </details>
            {generated.pair.files.map(file=><button type="button" className="auto-parser-secondary" key={file.name}
              onClick={()=>download(file.name,file.content)}>
              <FileText size={15}/> Download {file.name}</button>)}
            <button type="button" className="auto-parser-secondary" onClick={()=>{
              setDraft(generated.draft);
              onAutoParser();
            }}>Review Fields in Auto Parser</button>
          </div>}
        </div>}
      </section>
      <p className="auto-parser-note"><ShieldAlert size={16}/>
        If ChatGPT returns something Parser Studio cannot safely use, no parser changes are made.
        Revise the result or return to Auto Parser.</p>
      <button type="button" className="auto-parser-secondary" onClick={onAutoParser}>
        <FileText size={15}/> Return to Auto Parser
      </button>
    </div>
  </main>;
}
