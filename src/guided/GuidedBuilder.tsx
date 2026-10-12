import { lazy, Suspense, useEffect, useMemo, useRef, useState } from 'react';
import type { ChangeEvent, Dispatch, SetStateAction } from 'react';
import {
  AlertCircle, AlertTriangle, ArrowRight, ArrowLeft, Check, CheckCircle2, ChevronRight,
  ClipboardCheck, Code2, Download, FileArchive, FileCheck2, FileDown,
  FileText, FileUp, FlaskConical, HelpCircle, Layers3, LockKeyhole, Plus, Play,
  RotateCcw, Settings2, ShieldAlert, ShieldCheck, Trash2, WandSparkles,
} from 'lucide-react';
import type { FieldType, MappingRule, ParserDraft, SuiteResult } from '../model';
import { DEMO_SAMPLES } from '../model';
import { formatLabel, MAX_DATASET_BYTES } from '../parser';
import { listSafeLeafPaths } from '../fieldPaths';
import { mappingCoverage } from './mappingCoverage';
import { suggestMappingType } from './typeSuggestions';
import { curatedOfficialMetadata, applyOfficialMetadataField, officialDictionaryUrl, officialDictionaryUrl65 } from './officialMetadata';
import { createFieldProposal } from '../pattern';
import { suggestClassification } from './classify';
import { toBackendProject, type BackendParserProject } from './backendAdapter';
import { fetchBackendCapabilities, assertBackendProjectSupported } from './backendCapabilities';
import { packageGeneratedPair, assertPackageCapability } from './artifactPackageClient';
import { fetchParserPortProposal, type ParserPortProposal } from './portProposalClient';
import { prepareLegacyUploadPlan, type LegacyPreflightResult } from './legacyPreflightClient';
import { requestAuthorizedSyntheticPreview, type AuthorizedSyntheticPreview } from './backendSyntheticPreview';
import {
  requestOfflineSyntheticScenarioPreview,
  type SyntheticScenarioSelection,type SyntheticScenarioMode,type SyntheticScenarioSequence,
} from './syntheticScenarioPreview';
import {
  assertApprovedSessionReady, startApprovedSyntheticSession,
  fetchApprovedSessionStatus, controlApprovedSession, renewApprovedSession,
  changeApprovedSessionRate,
  type ApprovedTestLabStatus,
} from './approvedTestLabSession';
import { queryApprovedInterflowReadback, type InterflowReadbackResult, type InterflowIndex } from './approvedInterflowReadback';
import { inspectParserPair, type PairInspectionSummary } from './pairInspection';
import { buildPairImportReview } from './pairImportReview';
import { reconstructExactBackendDraft } from './pairProjectImport';
import { reviewLocalProjectJson, MAX_PROJECT_JSON_BYTES } from './localProjectImport';
import { backendIssueTarget } from './backendIssueGuide';
import { fetchBackendSchemaGuide, type BackendSchemaGuide } from './backendSchemaGuide';
import { starterTemplateIds, starterTemplateInfo, loadStarterTemplate, type StarterTemplateId } from './sampleTemplates';
import { suggestUnmappedFields } from './fieldMappingSuggestions';
import { validateBackendProject, generateBackendPair, type BackendValidationResult, type GeneratedPair } from './backendClient';
import { highlightPreview, matchContext } from './fieldHighlights';
import { summarizeFamilyCoverage } from './familyCoverage';
import { recommendLocalFormat, type LocalFormatAdvice } from './localFormatAdvisor';
import AutoParserAnalyzePanel from './AutoParserAnalyzePanel';
import {
  ISOLATABLE_FAMILIES, planFamilyIsolation, summarizeIsolatedFamilyPreview,
  type FamilyIsolationReport, type IsolatableFamily,
} from './familyIsolation';
import {planAllFamilyAudit,summarizeAllFamilyAudit,type AllFamilyAuditReport} from './familyAudit';
import {createAllFamilyAuditEvidence} from './familyAuditEvidence';
import { createBrowserEvidence } from './browserEvidence';
import { compareBrowserEvidence, type BrowserEvidenceComparison } from './browserEvidenceComparison';
import { createLocalReplayPlan, synthesizeFromReplayPlan, type LocalReplayPlan, type ReplayMutation } from './replayPreview';
import {
  CLASSIFICATIONS, FIELD_GROUPS, compilerDraftContract, defaultGuidedOptions,
  plannedPairNames, type EventClass, type FieldGroup, type GuidedOptions, type GuidedEnrichmentRule, type Transport,
} from './contract';

const ArtifactRevisionHistoryPanel=lazy(()=>import('./ArtifactRevisionHistoryPanel'));
const TestLabEvidencePanel=lazy(()=>import('./TestLabEvidencePanel'));
const BrowserRuleTracePanel=lazy(()=>import('./BrowserRuleTracePanel'));

export interface GuidedBuilderProps {
  draft: ParserDraft;
  setDraft: Dispatch<SetStateAction<ParserDraft>>;
  sample: string;
  setSample: (value: string) => void;
  datasetName: string;
  setDatasetName: (value: string) => void;
  suite?: SuiteResult;
  pending: boolean;
  /** Optional isolated local-only sample passed exclusively to the Web Worker. */
  runPreview: (draft: ParserDraft, temporarySample?: string) => Promise<SuiteResult>;
  runState?: { suite: SuiteResult; timestamp: string } | null;
  onRunSuite: () => void;
  onExpert: () => void;
  onSave: () => void;
}

const STEPS = [
  { label: 'Import Logs', sub: 'Sample Input', icon: FileUp },
  { label: 'Extract Fields', sub: 'Create Fields', icon: WandSparkles },
  { label: 'Map Fields', sub: 'Types & Normalization', icon: Layers3 },
  { label: 'Receive & Classify', sub: 'Protocol & Events', icon: Settings2 },
  { label: 'Test & Fix', sub: 'Test All Samples', icon: FlaskConical },
  { label: 'Generate Files', sub: 'Results & Downloads', icon: FileDown },
] as const;

const TYPES: FieldType[] = ['string', 'ip', 'port', 'integer', 'boolean', 'timestamp', 'number'];
const GROUP_LABELS: Record<FieldGroup, string> = {
  top_fields: 'Common Fields',
  ns_fields: 'Network Fields',
  vendor_fields: 'Vendor Fields',
};
const TYPE_LABELS: Record<FieldType, string> = {
  string: 'Text', integer: 'Integer', number: 'Decimal (unsupported)', boolean: 'Boolean',
  ip: 'IP Address', port: 'Port', timestamp: 'Time (ISO/UTC)',
};
const CLASS_LABELS: Record<EventClass, string> = {
  Session: 'Session', Threat: 'Threat',
  Syslog: 'Syslog / General Log', Winlogevent: 'Winlogevent / Windows',
};

function localDownload(filename: string, source: string, mediaType = 'application/json;charset=utf-8') {
  const url = URL.createObjectURL(new Blob([source], { type: mediaType }));
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function localDownloadBinary(filename: string, bytes: ArrayBuffer) {
  const url = URL.createObjectURL(new Blob([bytes], { type: 'application/zip' }));
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function TypeSuggestionView(props: {
  suite?: SuiteResult;
  mapping: MappingRule;
  index: number;
  onApply: (type: FieldType) => void;
}) {
  const suggestion = suggestMappingType(props.suite, props.mapping);
  if (!suggestion || suggestion.type === props.mapping.type) return null;
  return <div className="guided-type-proposal" aria-label={'Mapping type suggestion ' + props.index}>
    <span>Browser samples {suggestion.evidence}/{suggestion.total} suggest {TYPE_LABELS[suggestion.type]} type; not official metadata or native validation</span>
    <button type="button" aria-label={'Apply type suggestion ' + props.index}
      onClick={() => props.onApply(suggestion.type)}>Apply Suggested Type</button>
  </div>;
}

function LocalFormatRecommendationView(props:{
  advice:LocalFormatAdvice;
  selected:ParserDraft['format'];
  pending:boolean;
  onApply:(format:NonNullable<LocalFormatAdvice['format']>)=>void;
}){
  const {advice,selected,pending,onApply}=props;
  const detected=advice.format!==null&&
    (advice.status==='RECOMMENDED'||advice.status==='CANDIDATE_UNTESTED');
  const status:Record<LocalFormatAdvice['status'],string>={
    NO_SAMPLES:'Add at least one log event to receive a format recommendation.',
    NO_PREVIEW:'Analyzing the current sample locally…',
    LIMIT_EXCEEDED:'This sample exceeds the 64 KiB / 500 event preview limit. Reduce it before format recommendation.',
    MULTILINE_UNVERIFIED:'Grouped multiline input needs manual review. Native multiline parser output is unsupported.',
    UNTRUSTED_PREVIEW:'Local preview metadata could not be verified. Rerun the preview before selecting a format.',
    SOURCE_MISMATCH:'The preview no longer matches every source event. No format will be selected.',
    MIXED_FORMATS:'Multiple log families were detected. Review each family separately; one parser format cannot cover them all.',
    UNKNOWN_EVENTS:'Unrecognized source events remain. No single format can be recommended safely.',
    MANUAL_REVIEW:'The detected format requires manual configuration or is not supported for generated native output.',
    PREVIEW_FAILED:'The detected format did not extract all current events. Choose Auto detect and retry the local preview.',
    CANDIDATE_UNTESTED:'A different extraction format is selected. The current source signatures suggest this candidate; switch and recheck the full browser preview.',
    RECOMMENDED:'Every bounded event has the same recognized extraction format.',
  };
  return <div className={'guided-format-advisor'+(detected?' recommended':'')}
    aria-label="Local sample format recommendation">
    <strong><WandSparkles size={15}/> Automatic Format Check · Browser Only</strong>
    <p>{status[advice.status]}</p>
    {advice.totalEvents>0&&<div className="guided-format-advisor-metrics">
      <span>{advice.reviewedEvents}/{advice.totalEvents} extracted in current browser preview</span>
      {detected&&<span>Signature confidence (minimum): {advice.confidencePercent}%</span>}
    </div>}
    {advice.families.length>0&&<div className="guided-format-advisor-families"
      aria-label="Detected format candidates">
      {advice.families.map(f=><span key={f.format}>{formatLabel(f.format)}: {f.count}</span>)}
    </div>}
    {detected&&<div className="guided-format-advisor-action">
      <strong>Suggested: {formatLabel(advice.format!)}</strong>
      <button type="button" className="guided-cta-secondary"
        disabled={pending||selected===advice.format} aria-label="Apply recommended log format"
        onClick={()=>{if(advice.format)onApply(advice.format);}}>
        <Check size={15}/>{selected===advice.format?'Already Selected':
          advice.status==='CANDIDATE_UNTESTED'?'Try Detected Format':'Use Detected Format'}
      </button>
    </div>}
    <small>No log contents or credentials leave the browser. This changes only the selected draft extraction format after a click; mappings and sample logs are not changed. Backend support, native runtime and Stellar import remain unverified.</small>
  </div>;
}

function MappingCoverageView(props: {
  suite?: SuiteResult;
  mapping: MappingRule;
  index: number;
  onInspect: (eventId: string) => void;
}) {
  const counts = mappingCoverage(props.suite, props.mapping);
  return <div className={'guided-map-coverage ' + (counts.typeFailures || counts.missing ? 'attention' : '')}
    aria-label={'Mapping coverage ' + props.index}>
    {counts.total ? <>
      <span>Samples {counts.total} total; source {counts.sourcePresent}/{counts.total}; normalized {counts.normalized}/{counts.total}</span>
      {counts.missing > 0 && <span>Missing {counts.missing}</span>}
      {counts.typeFailures > 0 && <span>Type Errors {counts.typeFailures}</span>}
      {counts.firstProblemEventId && <button type="button"
        aria-label={'Inspect mapping issue ' + props.index}
        onClick={() => props.onInspect(counts.firstProblemEventId!)}>View Problem Event</button>}
    </> : <span>Mapping coverage appears after extracting sample fields.</span>}
    <small>Browser preview only. Fluentd and target ingestion are unverified.</small>
  </div>;
}

export default function GuidedBuilder(props: GuidedBuilderProps) {
  const {
    draft, setDraft, sample, setSample, datasetName, setDatasetName,
    suite, pending, runPreview, runState, onRunSuite, onExpert, onSave,
  } = props;
  const [step, setStep] = useState(0);
  const stageHeadingRef = useRef<HTMLHeadingElement>(null);
  const lastFocusedStage = useRef(step);
  useEffect(() => {
    // Step navigation unmounts the previous keyboard control. Move focus to
    // the new section heading, but never steal focus on initial render.
    if (lastFocusedStage.current !== step) {
      lastFocusedStage.current = step;
      stageHeadingRef.current?.focus();
    }
  }, [step]);
  const [selectedId, setSelectedId] = useState('event-1');
  const [selectedMappingId,setSelectedMappingId]=useState<string|null>(null);
  const [isolatedFamilyChoice, setIsolatedFamilyChoice] = useState<IsolatableFamily|null>(null);
  const [isolatedPending,setIsolatedPending] = useState(false);
  const [isolatedAttempt,setIsolatedAttempt] = useState<{key:string;report:FamilyIsolationReport}|null>(null);
  const [isolatedError,setIsolatedError] = useState('');
  const isolatedRequestToken=useRef(0);
  const [allFamilyAuditPending,setAllFamilyAuditPending]=useState(false);
  const [allFamilyAuditError,setAllFamilyAuditError]=useState('');
  const [allFamilyAuditAttempt,setAllFamilyAuditAttempt]=useState<{key:string;report:AllFamilyAuditReport}|null>(null);
  const allFamilyAuditToken=useRef(0);
  const [allFamilyEvidenceBusy,setAllFamilyEvidenceBusy]=useState(false);
  const [allFamilyEvidenceError,setAllFamilyEvidenceError]=useState('');
  const [selectedValue, setSelectedValue] = useState('');
  const [keyboardValue,setKeyboardValue] = useState('');
  const [fieldName, setFieldName] = useState('new_field');
  const [proposalTesting, setProposalTesting] = useState(false);
  const [proposalResult, setProposalResult] = useState<{ key: string; matched: number; total: number } | null>(null);
  const [message, setMessage] = useState('');
  const [errorFilter, setErrorFilter] = useState<'all' | 'fail' | 'warning'>('all');
  const [validatingBackend, setValidatingBackend] = useState(false);
  const [generatingPair, setGeneratingPair] = useState(false);
  const [backendAttempt, setBackendAttempt] = useState<{ key: string; project: BackendParserProject; result: BackendValidationResult } | null>(null);
  const [generatedPair, setGeneratedPair] = useState<{ key: string; pair: GeneratedPair } | null>(null);
  const [backendError, setBackendError] = useState<{ key: string; message: string } | null>(null);
  const [inspectConf, setInspectConf] = useState<File | null>(null);
  const [inspectFragment, setInspectFragment] = useState<File | null>(null);
  const [inspecting, setInspecting] = useState(false);
  const [inspectionResult, setInspectionResult] = useState<PairInspectionSummary | null>(null);
  const [inspectionError, setInspectionError] = useState('');
  const [importReplaceConfirmed,setImportReplaceConfirmed]=useState(false);
  const inspectRequestId=useRef(0);
  const [localProjectFile,setLocalProjectFile]=useState<File|null>(null);
  const [localProjectCandidate,setLocalProjectCandidate]=useState<ParserDraft|null>(null);
  const [localProjectReviewBusy,setLocalProjectReviewBusy]=useState(false);
  const [localProjectError,setLocalProjectError]=useState('');
  const [localProjectReplaceConfirmed,setLocalProjectReplaceConfirmed]=useState(false);
  const localProjectReviewId=useRef(0);
  const [schemaLoading, setSchemaLoading] = useState(false);
  const [schemaGuide, setSchemaGuide] = useState<BackendSchemaGuide | null>(null);
  const [schemaError, setSchemaError] = useState('');
  const [metadataError, setMetadataError] = useState<{mappingId:string;message:string} | null>(null);
  const [starterChoice, setStarterChoice] = useState<StarterTemplateId | ''>('');
  const [evidenceDownloading, setEvidenceDownloading] = useState(false);
  const [evidenceError, setEvidenceError] = useState('');
  const [baselineEvidenceFile, setBaselineEvidenceFile] = useState<File | null>(null);
  const [comparingEvidence, setComparingEvidence] = useState(false);
  const [comparisonResult, setComparisonResult] = useState<{ key: string; diff: BrowserEvidenceComparison } | null>(null);
  const [comparisonError, setComparisonError] = useState<{ key: string; message: string } | null>(null);
  const [localReplayRunning, setLocalReplayRunning] = useState(false);
  const [localReplayRate, setLocalReplayRate] = useState<1 | 2 | 5 | 10>(2);
  const [localReplayCount, setLocalReplayCount] = useState(0);
  const [localReplayText, setLocalReplayText] = useState('');
  const [localReplayMutations, setLocalReplayMutations] = useState<ReplayMutation[]>([]);
  const [portPlanLoading, setPortPlanLoading] = useState(false);
  const [portPlanAttempt, setPortPlanAttempt] = useState<{ key: string; plan: ParserPortProposal } | null>(null);
  const [portPlanError, setPortPlanError] = useState<{ key: string; message: string } | null>(null);
  const [legacyDryTenant, setLegacyDryTenant] = useState('');
  const [legacyDryVersion, setLegacyDryVersion] = useState('1.0.0');
  const [legacyDryPending, setLegacyDryPending] = useState(false);
  const [legacyDryProof, setLegacyDryProof] = useState<{key:string;tenant:string;version:string;proof:LegacyPreflightResult}|null>(null);
  const [legacyDryError, setLegacyDryError] = useState<{key:string;tenant:string;version:string;message:string}|null>(null);
  const legacyRequestToken = useRef(0);
  const [zipVersion, setZipVersion] = useState('1.0.0');
  const [zipDownloading, setZipDownloading] = useState(false);
  const [zipReceipt, setZipReceipt] = useState<{
    key: string; version: string; filename: string; sha256: string;
    artifactRevisionId: string; listenerPort: number;
  } | null>(null);
  const [zipError, setZipError] = useState<{ key: string; version: string; message: string } | null>(null);
  const [localReplayError, setLocalReplayError] = useState('');
  const [backendSyntheticPending, setBackendSyntheticPending] = useState(false);
  const [backendSyntheticData, setBackendSyntheticData] = useState<AuthorizedSyntheticPreview | null>(null);
  const [backendSyntheticError, setBackendSyntheticError] = useState('');
  const backendSyntheticRequestId = useRef(0);
  const [scenarioMode,setScenarioMode]=useState<SyntheticScenarioMode>('constant-rate');
  const [scenarioSequence,setScenarioSequence]=useState<SyntheticScenarioSequence>(0);
  const [scenarioPending,setScenarioPending]=useState(false);
  const [scenarioError,setScenarioError]=useState('');
  const [scenarioAttempt,setScenarioAttempt]=useState<{key:string;data:SyntheticScenarioSelection}|null>(null);
  const scenarioRequestToken=useRef(0);
  const [sessionReadiness, setSessionReadiness] = useState<'unchecked'|'checking'|'available'|'blocked'>('unchecked');
  const [sessionApproval, setSessionApproval] = useState('');
  const [sessionAcknowledged, setSessionAcknowledged] = useState(false);
  const [sessionRate, setSessionRate] = useState<1|2|5>(1);
  const [sessionNewRate,setSessionNewRate]=useState<0.2|1|2|5>(2);
  const [sessionRateApproval,setSessionRateApproval]=useState('');
  const [sessionRateConfirmed,setSessionRateConfirmed]=useState(false);
  const [sessionStatus, setSessionStatus] = useState<ApprovedTestLabStatus | null>(null);
  const [sessionBusy, setSessionBusy] = useState(false);
  const [sessionError, setSessionError] = useState('');
  const [sessionRenewApproval, setSessionRenewApproval] = useState('');
  const [sessionRecoveryRunId, setSessionRecoveryRunId] = useState('');
  const sessionActionToken = useRef(0);
  const [interflowIndex, setInterflowIndex] = useState<InterflowIndex>('syslog');
  const [interflowMarker, setInterflowMarker] = useState('test.run_id');
  const [interflowField, setInterflowField] = useState('action');
  const [interflowExpectedValue, setInterflowExpectedValue] = useState('allow');
  const [interflowWindow, setInterflowWindow] = useState<1|5|10>(5);
  const [interflowAcknowledged, setInterflowAcknowledged] = useState(false);
  const [interflowPending, setInterflowPending] = useState(false);
  const [interflowError, setInterflowError] = useState('');
  const [interflowAttempt, setInterflowAttempt] = useState<{key:string;result:InterflowReadbackResult}|null>(null);
  const interflowQueryToken = useRef(0);
  const [localReplaySource, setLocalReplaySource] = useState<{ index: number; line: number; total: number } | null>(null);
  // Source samples stay in memory only. Never serialize this plan into project
  // revisions, API calls or downloaded evidence.
  const localReplayPlanRef = useRef<LocalReplayPlan | null>(null);
  const localReplayCursorRef = useRef(0);


  const interflowKey=JSON.stringify([sessionStatus?.runId,interflowIndex,interflowMarker,
    interflowField,interflowExpectedValue,interflowWindow]);
  const currentInterflowResult=interflowAttempt?.key===interflowKey
    ? interflowAttempt.result : null;

  const scenarioKey=JSON.stringify([scenarioMode,scenarioSequence]);
  const currentScenarioResult=scenarioAttempt?.key===scenarioKey?scenarioAttempt.data:null;

  const options: GuidedOptions = draft.guided ?? defaultGuidedOptions();
  const activeEvent = suite?.events.find((event) => event.id === selectedId) ?? suite?.events[0];
  const activeFieldNames = useMemo(() => activeEvent ? listSafeLeafPaths(activeEvent.fields) : [], [activeEvent]);
  const keyboardCandidate=keyboardValue.trim();
  const keyboardCandidateValid=Boolean(activeEvent && keyboardCandidate &&
    keyboardCandidate.length<=80 && !keyboardCandidate.includes('\n') &&
    !keyboardCandidate.includes('\r') && activeEvent.raw.includes(keyboardCandidate));
  const proposal = useMemo(() => activeEvent && selectedValue
    ? createFieldProposal(activeEvent.raw, selectedValue, fieldName)
    : null, [activeEvent, selectedValue, fieldName]);
  const proposalKey = JSON.stringify([sample, draft, activeEvent?.id, selectedValue, fieldName]);
  const acceptedResult = proposalResult?.key === proposalKey ? proposalResult : null;
  const fieldHighlights = useMemo(() => (
    acceptedResult && proposal && !('error' in proposal) && suite
      ? highlightPreview(suite.events, proposal)
      : null
  ), [acceptedResult, proposal, suite]);
  const unmappedSuggestions = useMemo(() => suggestUnmappedFields(
    (suite?.events ?? []).map(event => event.fields), draft,
  ), [suite?.events, draft]);
  const familyCoverage = useMemo(
    () => summarizeFamilyCoverage(suite?.events ?? [], draft.format),
    [suite?.events, draft.format],
  );
  const localFormatAdvice=useMemo(
    ()=>recommendLocalFormat(sample,pending?undefined:suite,
      options.eventBoundary??'single-line'),
    [sample,pending,suite,options.eventBoundary],
  );
  const isolatableOptions=familyCoverage.groups
    .filter(group=>ISOLATABLE_FAMILIES.some(format=>format===group.format))
    .map(group=>group.format as IsolatableFamily);
  const activeIsolatedFamily=isolatedFamilyChoice &&
    isolatableOptions.includes(isolatedFamilyChoice)
      ? isolatedFamilyChoice : isolatableOptions[0]??null;
  const isolatedKey=JSON.stringify([draft,sample,activeIsolatedFamily]);
  const currentIsolatedReport=isolatedAttempt?.key===isolatedKey
    ? isolatedAttempt.report : null;
  const allFamilyAuditKey=JSON.stringify([draft,sample]);
  const currentAllFamilyAudit=allFamilyAuditAttempt?.key===allFamilyAuditKey
    ? allFamilyAuditAttempt.report : null;
  const artifactContract = compilerDraftContract(draft);
  const backendProject = toBackendProject(draft);
  // Bind validation, generated files and suite evidence to the exact draft AND fixture set.
  const draftKey = JSON.stringify([draft, sample]);
  const latestDraftKeyRef = useRef(draftKey);
  useEffect(() => { latestDraftKeyRef.current = draftKey; }, [draftKey]);
  const replayInputRef = useRef(draftKey);
  useEffect(() => {
    // Stop simulation if rules or sample change; never silently reuse stale
    // source events or continue after the Guided UI is unmounted.
    if (replayInputRef.current !== draftKey) {
      replayInputRef.current = draftKey;
      setLocalReplayRunning(false);
      setLocalReplayText('');
      setLocalReplayMutations([]);
      setLocalReplayCount(0);
      setLocalReplayError('');
      setLocalReplaySource(null);
      localReplayPlanRef.current = null;
      localReplayCursorRef.current = 0;
    }
  }, [draftKey]);
  const qualifiedBackend = backendAttempt?.key === draftKey ? backendAttempt : null;
  const currentComparison = comparisonResult?.key === draftKey ? comparisonResult.diff : null;
  const currentComparisonError = comparisonError?.key === draftKey ? comparisonError.message : '';
  const qualifiedPair = generatedPair?.key === draftKey ? generatedPair.pair : null;
  const currentBackendError = backendError?.key === draftKey ? backendError.message : '';
  const currentLegacyProof = legacyDryProof?.key === draftKey &&
    legacyDryProof.tenant === legacyDryTenant && legacyDryProof.version === legacyDryVersion
    ? legacyDryProof.proof : null;
  const currentLegacyError = legacyDryError?.key === draftKey &&
    legacyDryError.tenant === legacyDryTenant && legacyDryError.version === legacyDryVersion
    ? legacyDryError.message : '';
  const currentZipReceipt = zipReceipt?.key === draftKey && zipReceipt.version === zipVersion ? zipReceipt : null;
  const currentZipError = zipError?.key === draftKey && zipError.version === zipVersion ? zipError.message : '';
  const currentPortPlan = portPlanAttempt?.key === draftKey ? portPlanAttempt.plan : null;
  const currentPortPlanError = portPlanError?.key === draftKey ? portPlanError.message : '';
  const names = plannedPairNames(options.slug);
  const hasLogs = Boolean(suite?.counts.total);
  const hardFails = suite?.counts.failures ?? 0;

  const setGuided = (next: GuidedOptions) => {
    setDraft((old) => ({ ...old, guided: next }));
    setMessage('');
  };
  const changeDraft = <K extends keyof ParserDraft>(field: K, value: ParserDraft[K]) =>
    setDraft((old) => ({ ...old, [field]: value }));
  const notify = (text: string) => setMessage(text);

  const runLegacyDryRun = async () => {
    if (!qualifiedPair || !qualifiedBackend?.result.ok || legacyDryPending || pending) return;
    const key = draftKey;
    const tenant = legacyDryTenant, version = legacyDryVersion;
    const token = ++legacyRequestToken.current;
    setLegacyDryPending(true);
    setLegacyDryProof(null);
    setLegacyDryError(null);
    try {
      const proof = await prepareLegacyUploadPlan(
        qualifiedPair, tenant, version, qualifiedBackend.project.receiver.port,
      );
      if (latestDraftKeyRef.current !== key || legacyRequestToken.current !== token) return;
      setLegacyDryProof({key,tenant,version,proof});
      notify('Legacy pair structure and hash preflight completed. No DP upload or activation was performed.');
    } catch {
      if (latestDraftKeyRef.current === key && legacyRequestToken.current === token)
        setLegacyDryError({key,tenant,version,message:
          'Read-only Legacy preflight was denied. Check the tenant, version, and parser-pair contract. No upload was performed.'});
    } finally { setLegacyDryPending(false); }
  };

  const previewSelectedFamily = async () => {
    if(isolatedPending || pending || !suite || !activeIsolatedFamily) return;
    const key=isolatedKey,sourceKey=draftKey,token=++isolatedRequestToken.current;
    setIsolatedPending(true);setIsolatedError('');setIsolatedAttempt(null);
    try{
      const plan=planFamilyIsolation(sample,draft,suite,activeIsolatedFamily);
      const result=await runPreview({...draft,format:activeIsolatedFamily},plan.sample);
      if(token!==isolatedRequestToken.current ||
         sourceKey!==latestDraftKeyRef.current) return;
      setIsolatedAttempt({
        key,report:summarizeIsolatedFamilyPreview(plan,result),
      });
      notify('A separate local-only format-family preview finished. Original events, parser rules and backend deployment status were not changed.');
    }catch{
      if(token===isolatedRequestToken.current&&sourceKey===latestDraftKeyRef.current)
        setIsolatedError('This format family cannot be isolated safely from the current sample. Verify single-line records, review the full sample, and retry.');
    }finally {setIsolatedPending(false);}
  };

  const auditEveryDetectedFamily=async()=>{
    if(allFamilyAuditPending||isolatedPending||pending||!suite||!isolatableOptions.length)return;
    const sourceKey=draftKey;
    const token=++allFamilyAuditToken.current;
    setAllFamilyAuditPending(true);setAllFamilyAuditError('');setAllFamilyAuditAttempt(null);
    try{
      const plan=planAllFamilyAudit(sample,draft,suite);
      const reviewed:SuiteResult[]=[];
      // One bounded local Web Worker per family. Run sequentially so mixed
      // source content never goes to a backend or floods CPU workers.
      for(const item of plan.plans){
        const result=await runPreview({...draft,format:item.format},item.sample);
        if(token!==allFamilyAuditToken.current ||
           sourceKey!==latestDraftKeyRef.current)return;
        reviewed.push(result);
      }
      const report=summarizeAllFamilyAudit(plan,reviewed);
      if(token!==allFamilyAuditToken.current ||
         sourceKey!==latestDraftKeyRef.current)return;
      setAllFamilyAuditAttempt({key:sourceKey,report});
      notify('Local-only format-family audit finished. Unsupported events remain explicitly accounted for; no source bytes were uploaded or saved.');
    }catch{
      if(token===allFamilyAuditToken.current &&
         sourceKey===latestDraftKeyRef.current)
        setAllFamilyAuditError('The complete format-family audit could not be verified. Rerun the full source preview and check source boundaries and format detection. No family was silently omitted.');
    }finally{setAllFamilyAuditPending(false);}
  };

  const downloadAllFamilyAuditReport=async()=>{
    if(!currentAllFamilyAudit || !suite || pending ||
       allFamilyAuditPending || allFamilyEvidenceBusy)return;
    const key=allFamilyAuditKey;
    setAllFamilyEvidenceBusy(true);setAllFamilyEvidenceError('');
    try{
      const evidence=await createAllFamilyAuditEvidence({
        sample,draft,suite,report:currentAllFamilyAudit,
      });
      if(key!==latestDraftKeyRef.current)return;
      const slug=/^[a-z][a-z0-9_]{2,47}$/.test(options.slug)
        ? options.slug:'local_draft';
      localDownload('parser_studio_'+slug+'_family_audit.json',
        JSON.stringify(evidence,null,2)+'\n');
      notify('Downloaded source-SHA-bound browser family audit metadata. No raw logs, normalized values or vendor compatibility claims are included.');
    }catch{
      if(key===latestDraftKeyRef.current)
        setAllFamilyEvidenceError('The current browser family audit could not be verified for a safe, metadata-only download.');
    }finally{setAllFamilyEvidenceBusy(false);}
  };

  const checkParserListenerPort = async (override: boolean) => {
    if (portPlanLoading) return;
    const key = draftKey;
    setPortPlanLoading(true);
    setPortPlanError(null);
    setPortPlanAttempt(null);
    try {
      const plan = await fetchParserPortProposal(
        override ? options.receiver.port : undefined,
        fetch,
        draft.format==='syslog_rfc5424'?'syslog_rfc5424':undefined,
      );
      if (latestDraftKeyRef.current === key) setPortPlanAttempt({ key, plan });
    } catch (error) {
      if (latestDraftKeyRef.current === key) {
        setPortPlanError({ key,
          message: error instanceof Error ? error.message : 'Cannot retrieve the local backend port inventory.' });
      }
    } finally {
      setPortPlanLoading(false);
    }
  };
  const useSuggestedParserPort = () => {
    if (!currentPortPlan || currentPortPlan.source !== 'SUGGESTED' || currentPortPlan.deployableNow) return;
    setReceiver('port', currentPortPlan.recommendedPort);
    setPortPlanAttempt(null);
    setPortPlanError(null);
    notify('The suggested port was applied to the draft only. Regenerate CONF and recheck port conflicts before deployment.');
  };

  const downloadCheckedArtifactZip = async () => {
    if (!qualifiedPair || !qualifiedBackend?.result.ok || pending || zipDownloading) return;
    const key = draftKey;
    const version = zipVersion;
    setZipDownloading(true);
    setZipError(null);
    setZipReceipt(null);
    try {
      const capabilities = await fetchBackendCapabilities();
      assertPackageCapability(capabilities);
      const archive = await packageGeneratedPair(
        qualifiedPair, version, capabilities, qualifiedBackend.project.receiver.port,
      );
      // An in-flight packaging reply cannot download files for an edited draft.
      if (latestDraftKeyRef.current !== key) return;
      localDownloadBinary(archive.filename, archive.bytes);
      setZipReceipt({ key, version, filename: archive.filename, sha256: archive.sha256,
        artifactRevisionId: archive.artifactRevisionId, listenerPort: archive.listenerPort });
      notify('Downloaded a SHA-256-verified DRAFT ZIP. No DP deployment or engine verification was performed.');
    } catch {
      if (latestDraftKeyRef.current === key) setZipError({ key, version,
        message: 'DRAFT ZIP packaging is unavailable or failed integrity validation. Individual file downloads remain available.' });
    } finally {
      setZipDownloading(false);
    }
  };

  const checkApprovedTestLabSession = async () => {
    if (sessionReadiness==='checking' || sessionBusy) return;
    setSessionReadiness('checking');setSessionError('');
    try {
      const cap=await fetchBackendCapabilities();
      assertApprovedSessionReady(cap);
      setSessionReadiness('available');
    } catch {
      setSessionReadiness('blocked');
      setSessionError('The backend has not enabled an independently authorized sensor sink, access controls, destination allowlist, and delivery auditing. Starting a session is blocked.');
    }
  };
  const startApprovedTestLab = async () => {
    if (sessionReadiness!=='available' || !sessionAcknowledged ||
        !/^[A-Za-z0-9_.-]{8,96}$/.test(sessionApproval) || sessionBusy ||
        sessionStatus && ['RUNNING','PAUSED'].includes(sessionStatus.state)) return;
    const token=++sessionActionToken.current;
    setSessionBusy(true);setSessionError('');
    try {
      // Recheck *now*, not only the capability initially discovered.
      const cap=await fetchBackendCapabilities();
      const status=await startApprovedSyntheticSession(sessionApproval,sessionRate,cap);
      if (token!==sessionActionToken.current) return;
      setSessionStatus(status);
      setSessionApproval('');setSessionAcknowledged(false);
      setSessionRateApproval('');setSessionRateConfirmed(false);
      notify('The backend started an independently authorized Test Lab session. Delivery does not prove Stellar parsing or ingestion.');
    } catch {
      if(token===sessionActionToken.current)
        setSessionError('Test Lab start was denied. Verify operator approval, the trusted sink, and network allowlist policy.');
    } finally {setSessionBusy(false);}
  };
  const recoverApprovedTestLabStatus = async () => {
    if (!/^test_run_[0-9a-f]{32}$/.test(sessionRecoveryRunId) ||
        sessionBusy || sessionStatus) return;
    const token=++sessionActionToken.current;
    setSessionBusy(true);setSessionError('');
    try {
      // Run IDs are NOT authorization tokens: backend still validates the
      // authenticated session owner and does not echo source events.
      const recovered=await fetchApprovedSessionStatus(sessionRecoveryRunId);
      if (token!==sessionActionToken.current) return;
      setSessionStatus(recovered);setSessionRecoveryRunId('');
      setSessionRateApproval('');setSessionRateConfirmed(false);
      notify('An authenticated server returned the existing session status. No new Start request was sent.');
    } catch {
      if(token===sessionActionToken.current)
        setSessionError('Cannot retrieve the session using this run ID. Check server authentication, ownership, or session expiry. No delivery was started.');
    } finally {setSessionBusy(false);}
  };

  const actOnApprovedTestLab = async (action:'refresh'|'pause'|'resume'|'stop'|'renew'|'rate') => {
    const id=sessionStatus?.runId;
    if(!id || sessionBusy) return;
    const token=++sessionActionToken.current;
    setSessionBusy(true);setSessionError('');
    try {
      const status=action==='refresh'?await fetchApprovedSessionStatus(id):
        action==='renew'?await renewApprovedSession(id,sessionRenewApproval,60000,20):
        action==='rate'?await changeApprovedSessionRate(sessionStatus!,sessionRateApproval,sessionNewRate):
        await controlApprovedSession(id,action);
      if(token!==sessionActionToken.current)return;
      setSessionStatus(status);
      if(action==='renew')setSessionRenewApproval('');
      if(action==='rate'){
        setSessionRateApproval('');setSessionRateConfirmed(false);
        notify('Backend returned a newly approved synthetic session rate. The lease and event quota remain unchanged.');
      }
    }catch {
      if(token===sessionActionToken.current){
        if(action==='rate'){
          setSessionRateApproval('');setSessionRateConfirmed(false);
          setSessionError('The server did not authorize the requested session rate. Existing lease, quota and displayed rate are unchanged; refresh status before retrying.');
        }else setSessionError('The server denied the session action. The displayed status may be stale. Check ownership, run ID, and lease expiry.');
      }
    }finally{setSessionBusy(false);}
  };

  const readApprovedInterflow = async () => {
    const runId=sessionStatus?.runId;
    if(!runId || !interflowAcknowledged || interflowPending) return;
    const key=JSON.stringify([runId,interflowIndex,interflowMarker,interflowField,
      interflowExpectedValue,interflowWindow]);
    const token=++interflowQueryToken.current;
    setInterflowPending(true);
    setInterflowError('');
    setInterflowAttempt(null);
    try {
      // A capability flag is NOT a tenant data-read grant: the backend still
      // checks both authenticated session ownership and a separate audit sink.
      const cap=await fetchBackendCapabilities();
      const result=await queryApprovedInterflowReadback(cap,{
        runId,index:interflowIndex,markerField:interflowMarker,
        expectedField:interflowField,expectedValue:interflowExpectedValue,
        lookbackMinutes:interflowWindow,
      });
      if(interflowQueryToken.current===token) {
        setInterflowAttempt({key,result});
        notify('The audited Interflow field comparison completed. Native parsing, sensor receipt and target ingestion remain unverified.');
      }
    }catch {
      if(interflowQueryToken.current===token) setInterflowError(
        'Interflow readback was denied or unavailable. Check separate tenant read permission, session ownership, audit policy and the requested index. No target parsing success is claimed.'
      );
    }finally {setInterflowPending(false);}
  };

  const previewOfflineSyntheticScenario=async()=>{
    if(scenarioPending)return;
    const key=scenarioKey,token=++scenarioRequestToken.current;
    setScenarioPending(true);setScenarioError('');setScenarioAttempt(null);
    try{
      const cap=await fetchBackendCapabilities();
      const result=await requestOfflineSyntheticScenarioPreview(
        cap,scenarioMode,scenarioSequence,
      );
      if(scenarioRequestToken.current!==token)return;
      setScenarioAttempt({key,data:result});
      notify('An authorized offline synthetic scenario event was generated. No Test Lab session or sensor transport was started.');
    }catch{
      if(scenarioRequestToken.current===token)setScenarioError(
        'The backend denied or cannot verify the offline scenario preview. A preview authorization grant is required; no sensor data was sent.'
      );
    }finally{setScenarioPending(false);}
  };

  const requestBackendSyntheticSample = async () => {
    if (backendSyntheticPending) return;
    const id = ++backendSyntheticRequestId.current;
    setBackendSyntheticPending(true);
    setBackendSyntheticData(null);
    setBackendSyntheticError('');
    try {
      const cap = await fetchBackendCapabilities();
      const result = await requestAuthorizedSyntheticPreview(cap);
      if (backendSyntheticRequestId.current !== id) return;
      setBackendSyntheticData(result);
      notify('The backend authorized a public synthetic JSON sample. No customer logs or sensor traffic were sent.');
    } catch {
      if (backendSyntheticRequestId.current === id)
        setBackendSyntheticError('The synthetic JSON preview requires backend authorization. The server denied the request or its no-delivery status could not be verified.');
    } finally { setBackendSyntheticPending(false); }
  };

  const downloadBrowserTestEvidence = async () => {
    if (!runState || evidenceDownloading || pending) return;
    setEvidenceDownloading(true);
    setEvidenceError('');
    try {
      const report = await createBrowserEvidence({ sample, draft, suite: runState.suite });
      const slug = /^[a-z][a-z0-9_]{2,47}$/.test(options.slug) ? options.slug : 'local_draft';
      localDownload('parser_studio_' + slug + '_browser_test_evidence.json',
        JSON.stringify(report, null, 2) + '\n');
      notify('Downloaded browser test evidence without raw logs or normalized values. This does not establish native or Stellar compatibility.');
    } catch (error) {
      setEvidenceError(error instanceof Error ? error.message : 'Cannot generate local test evidence.');
    } finally {
      setEvidenceDownloading(false);
    }
  };

  const comparePreviousBrowserEvidence = async () => {
    if (!runState || !baselineEvidenceFile || comparingEvidence || pending) return;
    const key = draftKey;
    setComparingEvidence(true);
    setComparisonResult(null);
    setComparisonError(null);
    try {
      if (baselineEvidenceFile.size < 2 || baselineEvidenceFile.size > 512 * 1024) {
        throw new Error('Previous test evidence must be JSON no larger than 512 KiB.');
      }
      const content = new TextDecoder('utf-8', { fatal: true })
        .decode(await baselineEvidenceFile.arrayBuffer());
      const previous: unknown = JSON.parse(content);
      const current = await createBrowserEvidence({ sample, draft, suite: runState.suite });
      const diff = compareBrowserEvidence(previous, current);
      setComparisonResult({ key, diff });
      notify('Compared browser test evidence for the same source sample. Results remain in this session only.');
    } catch {
      // Do not echo arbitrary parsing errors or untrusted file bodies.
      setComparisonError({ key, message: 'Comparison failed. Verify the previous evidence format and source sample SHA-256. No data was transmitted.' });
    } finally {
      setComparingEvidence(false);
    }
  };

  const produceLocalReplay = (): boolean => {
    try {
      const plan = localReplayPlanRef.current;
      if (!plan) throw new Error('No reviewed local replay plan');
      const output = synthesizeFromReplayPlan(plan, draft, localReplayCursorRef.current);
      localReplayCursorRef.current++;
      setLocalReplayText(output.log);
      setLocalReplayMutations(output.mutations);
      setLocalReplaySource({ index: output.sourceEvent, line: output.sourceLine, total: output.sourceTotal });
      setLocalReplayCount((count) => Math.min(count + 1, Number.MAX_SAFE_INTEGER));
      return true;
    } catch {
      setLocalReplayRunning(false);
      localReplayPlanRef.current = null;
      setLocalReplayError('Synthetic log generation failed. Use supported single-record samples in a secure browser context.');
      return false;
    }
  };
  const stopLocalReplay = () => {
    setLocalReplayRunning(false);
    localReplayPlanRef.current = null;
  };
  const startLocalReplay = () => {
    setLocalReplayText('');
    setLocalReplayCount(0);
    setLocalReplayError('');
    setLocalReplayMutations([]);
    setLocalReplaySource(null);
    localReplayCursorRef.current = 0;
    try {
      // Entire sample is reviewed before starting the timer; one malformed
      // later record aborts rather than silently dropping it.
      localReplayPlanRef.current = createLocalReplayPlan(sample, draft);
      if (produceLocalReplay()) setLocalReplayRunning(true);
    } catch {
      localReplayPlanRef.current = null;
      setLocalReplayRunning(false);
      setLocalReplayError('Cannot start local replay. All samples must share a supported format and remain within 64 KiB / 500 single-line events.');
    }
  };
  useEffect(() => {
    if (!localReplayRunning) return;
    const interval = window.setInterval(() => {
      void produceLocalReplay();
    }, 1000 / localReplayRate);
    return () => window.clearInterval(interval);
  }, [localReplayRunning, localReplayRate, sample, draft]);
  useEffect(() => {
    if (step !== 5 && localReplayRunning) stopLocalReplay();
  }, [step, localReplayRunning]);

  const applyStarter = () => {
    if (!starterChoice) return;
    const template = loadStarterTemplate(starterChoice);
    setDraft(template.draft);
    setSample(template.sample);
    setDatasetName('Synthetic sample · ' + template.label);
    setSelectedValue('');
    setSelectedId('event-1');
    setProposalResult(null);
    setBackendAttempt(null);
    setGeneratedPair(null);
    setBackendError(null);
    setStarterChoice('');
    notify('Applied a new draft using the selected synthetic log and rules. This is not customer data; rerun browser tests.');
  };

  const readSampleFile = async (event: ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    event.target.value = '';
    if (!file) return;
    if (file.size > MAX_DATASET_BYTES) { notify('File exceeds the 64 KiB limit. Choose a smaller sample.'); return; }
    try {
      const content = new TextDecoder('utf-8', { fatal: true }).decode(await file.arrayBuffer());
      setSample(content);
      setDatasetName(file.name);
      setSelectedValue('');
      setSelectedId('event-1');
      notify('Sample loaded into browser memory only.');
    } catch {
      notify('Only UTF-8 text files can be uploaded.');
    }
  };

  useEffect(()=>{
    // Explicit keyboard alternative is transient and must not hold values
    // from a previous customer sample after the input has been edited.
    setKeyboardValue('');
  },[sample]);

  const captureValue = (text: string) => {
    const value = text.trim();
    if (!activeEvent || !value || value.includes('\n') || value.length > 80 || !activeEvent.raw.includes(value)) return;
    setSelectedValue(value);
    const before = activeEvent.raw.slice(0, activeEvent.raw.indexOf(value));
    const key = before.match(/["']?([A-Za-z_][\w.-]*)["']?\s*[:=]\s*["']?$/)?.[1];
    setFieldName(key ? key.replace(/[^a-zA-Z0-9_]/g, '_') : 'new_field');
    setProposalResult(null);
  };

  const checkProposal = async () => {
    if (!proposal || 'error' in proposal) return;
    setProposalTesting(true);
    setProposalResult(null);
    try {
      const result = await runPreview({ ...draft, format: 'regex', pattern: proposal.pattern });
      setProposalResult({ key: proposalKey, matched: result.counts.matched, total: result.counts.total });
    } catch (error) {
      notify(error instanceof Error ? error.message : 'Unable to validate the field proposal.');
    } finally { setProposalTesting(false); }
  };

  const addRule = () => {
    if (!proposal || 'error' in proposal || !acceptedResult?.matched) return;
    const source = proposal.field;
    const exists = draft.mappings.some((rule) => rule.source === source);
    const mapping: MappingRule = {
      id: crypto.randomUUID(),
      source, target: 'custom.' + source,
      type: /(^|_)ip$/i.test(source) ? 'ip' : /port/i.test(source) ? 'port' : 'string',
    };
    setDraft((old) => ({
      ...old,
      // JSON/KV already have structural extraction; never replace a working
      // source-family parser with a one-event regexp without asking the user.
      ...(old.format === 'regex' ? { pattern: proposal.pattern } : {}),
      mappings: exists ? old.mappings : [...old.mappings, mapping],
    }));
    setSelectedValue('');
    setProposalResult(null);
    notify('Added the field rule to the draft. Compound formats may require a separate routing rule.');
  };

  const openFieldMapping = (source: string) => {
    const existing=draft.mappings.find(mapping=>mapping.source===source);
    if(existing) {
      setSelectedMappingId(existing.id);
      setStep(2);
      notify('Opened the existing source-field mapping. Review the normalized destination and type before generation.');
      return;
    }
    // Only the reviewed name-based suggestion is allowed. Raw sample values
    // stay in the browser and never enter rules or outgoing API requests.
    const suggestion=unmappedSuggestions.find(candidate=>candidate.source===source);
    if(!suggestion) {
      setStep(2);
      notify('This extracted source field cannot be safely prefilled. Review the mapping manually.');
      return;
    }
    const id=crypto.randomUUID();
    setDraft(old=>{
      if(old.mappings.some(mapping=>mapping.source===source))return old;
      const options=old.guided??defaultGuidedOptions();
      return {...old,
        mappings:[...old.mappings,{
          id,source:suggestion.source,target:suggestion.target,type:suggestion.type,
        }],
        guided:{...options,groups:{...options.groups,[id]:suggestion.group}},
      };
    });
    setSelectedMappingId(id);
    setStep(2);
    notify('Added the selected source field as a conservative string DRAFT mapping. Review and test before generating files.');
  };

  const addMapping = (source = '') => {
    const next: MappingRule = {
      id: crypto.randomUUID(), source,
      target: source ? 'custom.' + source.replace(/[^\w]+/g, '_') : '',
      type: source.endsWith('ip') ? 'ip' : source.includes('port') ? 'port' : 'string',
    };
    setDraft((old) => ({ ...old, mappings: [...old.mappings, next] }));
  };

  const setMapping = (id: string, key: keyof MappingRule, value: string) =>
    setDraft((old) => ({
      ...old,
      mappings: old.mappings.map((rule) => rule.id === id ? { ...rule, [key]: value } : rule),
    }));

  const addEnrichment = () => setGuided({
    ...options, enrichment: [...(options.enrichment ?? []), {
      id: crypto.randomUUID(), operator: 'set_const', source: '', target: '', value: '',
    }],
  });
  const changeEnrichment = (id: string, key: keyof GuidedEnrichmentRule, value: string) => setGuided({
    ...options, enrichment: (options.enrichment ?? []).map((rule) => rule.id === id
      ? { ...rule, [key]: value } as GuidedEnrichmentRule : rule),
  });
  const removeEnrichment = (id: string) => setGuided({
    ...options, enrichment: (options.enrichment ?? []).filter((rule) => rule.id !== id),
  });

  const applyUnmappedSuggestions = () => {
    if (!unmappedSuggestions.length) return;
    const additions = unmappedSuggestions.map(({ source, target, type, group }) => ({
      rule: { id: crypto.randomUUID(), source, target, type } satisfies MappingRule,
      group,
    }));
    setDraft((old) => {
      const next = old.guided ?? defaultGuidedOptions();
      return {
        ...old,
        mappings: [...old.mappings, ...additions.map((entry) => entry.rule)],
        guided: {
          ...next,
          groups: { ...next.groups, ...Object.fromEntries(
            additions.map((entry) => [entry.rule.id, entry.group]),
          ) },
        },
      };
    });
    notify('Safely applied ' + additions.length + ' suggested sample fields as text. Review mapping types and destinations.');
  };

  const chooseOfficialMetadata = (mappingId: string, fieldName: string) => {
    const selection = applyOfficialMetadataField(draft, mappingId, fieldName);
    if (!selection.ok) {
      setMetadataError({ mappingId, message: selection.error });
      return;
    }
    setMetadataError(null);
    setDraft(selection.draft);
    notify('Applied the selected public metadata field and type to the draft. Target-version support still requires independent verification.');
  };

  const setReceiver = (key: keyof GuidedOptions['receiver'], value: unknown) =>
    setGuided({ ...options, receiver: { ...options.receiver, [key]: value } });

  const chooseProtocol = (protocol: Transport, checked: boolean) => {
    const protocols = checked ? [...new Set([...options.receiver.protocols, protocol])] : options.receiver.protocols.filter((value) => value !== protocol);
    setReceiver('protocols', protocols);
  };

  const addCondition = () => setGuided({
    ...options, classification: {
      ...options.classification,
      rules: [...options.classification.rules, { id: crypto.randomUUID(), sourceField: '', equals: '', index: 'Syslog' }],
    },
  });
  const changeCondition = (id: string, key: 'sourceField' | 'equals' | 'index', value: string) => setGuided({
    ...options, classification: {
      ...options.classification,
      rules: options.classification.rules.map((rule) => rule.id === id ? { ...rule, [key]: value } : rule),
    },
  });

  const checkBackend = async () => {
    setBackendAttempt(null);
    setGeneratedPair(null);
    setBackendError(null);
    if (!backendProject.ok) {
      setBackendError({ key: draftKey, message: 'Resolve field mapping and classification errors first.' });
      return;
    }
    setValidatingBackend(true);
    try {
      const capabilities = await fetchBackendCapabilities();
      assertBackendProjectSupported(backendProject.project, capabilities);
      const result = await validateBackendProject(backendProject.project);
      setBackendAttempt({ key: draftKey, project: backendProject.project, result });
      if (result.ok) notify('Backend input schema validation passed. Native execution still requires independent verification.');
    } catch (error) {
      setBackendError({ key: draftKey, message: error instanceof Error ? error.message : 'Cannot connect to the backend.' });
    } finally {
      setValidatingBackend(false);
    }
  };

  const loadAuthoringSchema = async () => {
    setSchemaLoading(true);
    setSchemaGuide(null);
    setSchemaError('');
    try {
      const guide = await fetchBackendSchemaGuide();
      setSchemaGuide(guide);
    } catch (error) {
      setSchemaError(error instanceof Error ? error.message : 'Cannot retrieve the backend schema.');
    } finally {
      setSchemaLoading(false);
    }
  };

  const inspectLocalProjectFile=async()=>{
    const file=localProjectFile;
    if(!file || localProjectReviewBusy)return;
    const token=++localProjectReviewId.current;
    setLocalProjectError('');setLocalProjectCandidate(null);
    setLocalProjectReplaceConfirmed(false);
    setLocalProjectReviewBusy(true);
    try{
      if(!/\.json$/i.test(file.name)||file.size>MAX_PROJECT_JSON_BYTES||file.size===0)
        throw new Error('Choose a Project JSON file up to 256 KiB.');
      const draft=reviewLocalProjectJson(new Uint8Array(await file.arrayBuffer()));
      if(token!==localProjectReviewId.current)return;
      setLocalProjectCandidate(draft);
    }catch(error){
      if(token===localProjectReviewId.current)setLocalProjectError(
        error instanceof Error?error.message:'Project JSON cannot be safely restored.');
    }finally {
      if(token===localProjectReviewId.current)setLocalProjectReviewBusy(false);
    }
  };
  const applyLocalProjectDraft=()=>{
    if(!localProjectReplaceConfirmed||!localProjectCandidate||
      localProjectReviewBusy)return;
    ++localProjectReviewId.current;
    setDraft(localProjectCandidate);
    setSample('');setDatasetName('Validated local Project JSON · No sample logs');
    setLocalProjectFile(null);setLocalProjectCandidate(null);
    setLocalProjectReplaceConfirmed(false);setLocalProjectError('');
    setStep(2);
    notify('Loaded a reviewed Project JSON into an unsaved Guided draft. Sample logs were cleared; no backend request or device action occurred.');
  };

  const inspectChosenPair = async () => {
    const requestId=++inspectRequestId.current;
    setImportReplaceConfirmed(false);
    setInspectionResult(null);
    setInspectionError('');
    if (!inspectConf || !inspectFragment) return;
    const name = inspectFragment.name;
    if (!/^customized_[a-z][a-z0-9_]{1,47}$/.test(name) || inspectConf.name !== name + '.conf') {
      setInspectionError('Select a matching customized_<slug>.conf and extensionless parser file.');
      return;
    }
    if (inspectConf.size + inspectFragment.size > 2 * 1024 * 1024) {
      setInspectionError('The combined input files exceed 2 MiB.');
      return;
    }
    setInspecting(true);
    try {
      const capabilities = await fetchBackendCapabilities();
      if (!capabilities.import.structuralInspectionOnly) throw new Error('This backend does not support read-only structural inspection.');
      const decoder = new TextDecoder('utf-8', { fatal: true });
      const [confBytes, fragmentBytes] = await Promise.all([inspectConf.arrayBuffer(), inspectFragment.arrayBuffer()]);
      const result = await inspectParserPair({
        name, confContent: decoder.decode(confBytes), fragmentContent: decoder.decode(fragmentBytes),
      });
      if(requestId===inspectRequestId.current)setInspectionResult(result);
    } catch (error) {
      if(requestId===inspectRequestId.current)
        setInspectionError(error instanceof Error ? error.message : 'File inspection failed.');
    } finally {
      if(requestId===inspectRequestId.current)setInspecting(false);
    }
  };

  const buildDraftPair = async () => {
    if (!qualifiedBackend?.result.ok || !runState?.suite.counts.total ||
        runState.suite.counts.matched !== runState.suite.counts.total ||
        runState.suite.counts.normalized !== runState.suite.counts.total ||
        runState.suite.counts.failures > 0) return;
    setGeneratingPair(true);
    setBackendError(null);
    setGeneratedPair(null);
    try {
      const pair = await generateBackendPair(qualifiedBackend.project);
      setGeneratedPair({ key: draftKey, pair });
      notify('Downloaded both files with valid SHA-256 hashes. Runtime and target ingestion remain unverified DRAFT outputs.');
    } catch (error) {
      setBackendError({ key: draftKey, message: error instanceof Error ? error.message : 'File generation failed.' });
    } finally {
      setGeneratingPair(false);
    }
  };

  const stageStatus = (number: number): 'complete' | 'attention' | 'future' => {
    if (number === 0) return hasLogs ? 'complete' : 'attention';
    if (number === 1) return hasLogs && draft.format !== 'auto' ? 'complete' : hasLogs ? 'attention' : 'future';
    if (number === 2) return draft.mappings.length > 0 ? 'complete' : 'attention';
    if (number === 3) return options.receiver.protocols.length && Number.isInteger(options.receiver.port) &&
      options.receiver.port >= (draft.format==='syslog_rfc5424'?6800:1024) && options.receiver.port <= 65535 ? 'complete' : 'attention';
    if (number === 4) return runState?.suite.counts.total && runState.suite.counts.failures === 0 ? 'complete' : 'attention';
    return 'future';
  };

  // Reconstruct only a byte-verified, semantically identical internal project.
  // Never import unknown Ruby files or unsupported project fields.
  const importableDraft=useMemo(()=>{
    if(!inspectionResult?.editable || !inspectionResult.portableProject)return null;
    return reconstructExactBackendDraft(
      inspectionResult.portableProject,inspectionResult.name,
    );
  },[inspectionResult]);
  const applyExactPairAsDraft=()=>{
    if(!importReplaceConfirmed || !importableDraft || inspecting)return;
    inspectRequestId.current++;
    setDraft(importableDraft);
    setSample('');
    setDatasetName('Imported backend-exact draft · No sample logs');
    setInspectConf(null);setInspectFragment(null);
    setInspectionResult(null);setInspectionError('');
    setImportReplaceConfirmed(false);
    setStep(2);
    notify('Imported an exact backend-reproducible project as an unsaved draft. Existing samples were cleared. Run browser/native tests separately; no real target import was performed.');
  };

  // Safe metadata only: no Ruby, CONF or customer data is retained in this report.
  const importReview=useMemo(()=>{
    if(!inspectionResult)return null;
    try{return buildPairImportReview(inspectionResult);}
    catch{return null;} // A malformed backend response must never crash the UI.
  },[inspectionResult]);

  const nextStep = () => setStep(Math.min(5, step + 1));
  const prevStep = () => setStep(Math.max(0, step - 1));

  return <main className="guided-shell" aria-label="No-code Parser Guided Builder">
    <div className="guided-intro">
      <div><div className="guided-breadcrumb">PARSER STUDIO / GET STARTED / <strong>Guided Builder</strong></div>
        <h1>Build a custom parser <span className="guided-crown">NO-CODE BUILDER</span></h1>
        <p>No Ruby or regex expertise required. Add logs, select fields, and validate safely.</p>
      </div>
      <div className="guided-intro-actions">
        <button type="button" className="guided-expert" onClick={onExpert}><Code2 size={15} /> Open Expert Workbench</button>
        <button type="button" className="guided-save" onClick={onSave}><FileCheck2 size={15} /> Save Draft</button>
      </div>
    </div>

    <div className="guided-columns">
      <aside className="guided-steps" aria-label="Creation steps">
        <div className="guided-step-caption">PARSER CREATION <span>0{step + 1} / 06</span></div>
        <div className="guided-progress-line"><div style={{ width: ((step + 1) / 6 * 100) + '%' }} /></div>
        <nav>{STEPS.map(({ label, sub, icon: Icon }, i) =>
          <button key={label} type="button" aria-current={step === i ? 'step' : undefined} className={'guided-step ' + (step === i ? 'active ' : '') + stageStatus(i)} onClick={() => { setStep(i); setMessage(''); }}>
            <span className="guided-step-icon">{stageStatus(i) === 'complete' && i < step ? <Check size={16} /> : <Icon size={17} />}</span>
            <span className="guided-step-copy"><strong>{i + 1}. {label}</strong><small>{sub}</small></span>
            {step === i && <ChevronRight size={15} className="guided-chevron" />}
          </button>,
        )}</nav>
        <div className="guided-side-note"><LockKeyhole size={17} /><strong>Local-first by design</strong><p>Raw samples stay in your browser unless you explicitly submit them to a permitted backend action. No automatic deployment or external AI transfer.</p></div>
      </aside>

      <section className="guided-workspace" aria-live="polite">
        <div className="guided-content-head">
          <div className="guided-content-eyebrow">STEP {String(step + 1).padStart(2, '0')} <span>/ 06</span></div>
          <h2 ref={stageHeadingRef} tabIndex={-1}>{[
            'Which logs are you parsing?', 'Which fields do you need to extract?',
            'How should the extracted fields be normalized?', 'How are logs received and classified?',
            'Do all your samples pass validation?', 'Which parser files will be generated?',
          ][step]}</h2>
          <p>{[
            'Paste device logs or choose a text file. Multiple event variants improve test coverage.',
            'Highlight a value in a raw event to propose a structural field extraction rule.',
            'Map extracted fields to normalized destinations and select their types.',
            'Configure UDP/TCP receiving and event classification. No device configuration is modified.',
            'Run local preview tests over every sample and review failures with explanations.',
            'Review both generated parser files and their contracts. Files remain DRAFT until native and target verification is established.',
          ][step]}</p>
        </div>

        <div className="guided-content-body">
          {step === 0 && <>
            <div className="guided-section-title"><span>01</span> Parser Details <span className="guided-required">Required</span></div>
            <div className="guided-two-fields">
              <label className="guided-field"><span>Parser Name</span><input aria-label="Guided parser name" value={draft.name} maxLength={90} onChange={(e) => changeDraft('name', e.target.value)} placeholder="e.g. Firewall Log Parser" /></label>
              <label className="guided-field"><span>Device Vendor</span><input aria-label="Guided vendor" value={draft.vendor} maxLength={80} onChange={(e) => changeDraft('vendor', e.target.value)} placeholder="e.g. Firewall Vendor" /></label>
            </div>
            <label className="guided-field"><span>Parser ID <small>(used to name output files)</small></span><input aria-label="Parser ID" value={options.slug} onChange={(e) => setGuided({ ...options, slug: e.target.value.toLowerCase() })} /><small>Use lowercase ASCII letters, digits, and underscores; start with a letter.</small></label>
            <label className="guided-field"><span>Log Source Category</span><select aria-label="Source category" value={options.sourceCategory ?? 'network'} onChange={(e) => setGuided({ ...options, sourceCategory: e.target.value as NonNullable<GuidedOptions['sourceCategory']> })}>
              <option value="network">Network Device</option><option value="endpoint">Endpoint</option><option value="cloud">Cloud</option><option value="application">Application</option><option value="other">Other</option>
            </select></label>
            <div className="guided-section-title"><span>02</span> Start with Synthetic Samples <span className="guided-inline-badge">Optional</span></div>
            <div className="guided-starter-choice">
              <label className="guided-field"><span>Parser Format Template</span>
                <select aria-label="Synthetic starter template" value={starterChoice} onChange={(event) => setStarterChoice(event.target.value as StarterTemplateId | '')}>
                  <option value="">Select a format</option>
                  {starterTemplateIds.map((id) => <option value={id} key={id}>{starterTemplateInfo(id).label}</option>)}
                </select>
              </label>
              <button className="guided-cta-secondary" type="button" disabled={!starterChoice} onClick={applyStarter}>
                <WandSparkles size={15} /> Apply Synthetic Template
              </button>
            </div>
            <div className="guided-hint"><AlertTriangle size={16} /> Applying a template replaces the current draft rules and sample with synthetic data. Selection alone makes no changes or requests. Templates do not prove device or engine compatibility.</div>
            <div className="guided-section-title"><span>03</span> Add Sample Logs</div>
            <div className="guided-upload"><FileUp size={21} /><span>Paste log text or upload a file.</span><label htmlFor="guided-upload-file" className="guided-upload-button">Choose File</label><input type="file" id="guided-upload-file" onChange={readSampleFile} accept=".txt,.log,.json,.csv,text/plain" hidden /><small>UTF-8 · Max 64 KiB · No automatic external upload</small></div>
            <label className="guided-field"><span>Raw Logs <small>{datasetName}</small></span><textarea aria-label="Guided raw sample logs" spellCheck={false} className="guided-raw-input" value={sample} onChange={(e) => { setSample(e.target.value); setDatasetName('User-provided sample · Session only'); }} placeholder="Paste raw device logs, one event per line" /></label>
            <AutoParserAnalyzePanel sample={sample}
              boundary={options.eventBoundary??'single-line'}
              selectedFormat={draft.format}
              selectedBody={draft.syslogBodyFormat??'raw'}
              onApply={(format,body)=>setDraft(old=>({
                ...old,format,
                ...(format==='syslog_rfc5424'&&body?{syslogBodyFormat:body}:{}),
              }))}/>
            <LocalFormatRecommendationView advice={localFormatAdvice}
              selected={draft.format} pending={pending}
              onApply={(format)=>changeDraft('format',format)}/>
            <div className="guided-section-title"><span>04</span> Event Boundaries</div>
            <div className="guided-boundary-options" role="group" aria-label="Event boundary selector">
              <button type="button" aria-pressed={(options.eventBoundary ?? 'single-line') === 'single-line'} className={(options.eventBoundary ?? 'single-line') === 'single-line' ? 'selected' : ''} onClick={() => setGuided({ ...options, eventBoundary: 'single-line' })}>
                <FileText size={18} /><span><strong>One line = one event</strong><small>Typical Syslog / JSON Lines / KV records</small></span>
              </button>
              <button type="button" aria-pressed={options.eventBoundary === 'blank-line'} className={options.eventBoundary === 'blank-line' ? 'selected' : ''} onClick={() => setGuided({ ...options, eventBoundary: 'blank-line' })}>
                <Layers3 size={18} /><span><strong>Separate events using blank lines</strong><small>Records containing line breaks, including multiline JSON</small></span>
              </button>
            </div>
            <div className="guided-boundary-count" role="status">
              <span>Nonempty source lines <strong>{sample.replace(/\r\n?/g, '\n').split('\n').filter((line) => line.trim()).length}</strong></span>
              <span>Logical events <strong>{pending ? 'Calculating…' : (suite?.counts.total ?? 0)}</strong></span>
            </div>
            {options.eventBoundary === 'blank-line' && <div className="guided-hint"><AlertTriangle size={16} /> Blank-line grouping applies to browser preview only. Parser output remains blocked until multiline engine support is verified.</div>}
            <div className="guided-inline-actions"><button className="guided-link" type="button" onClick={() => { setSample(DEMO_SAMPLES); setDatasetName('Synthetic demo events'); }}><RotateCcw size={14} /> Restore Demo Logs</button><button type="button" className="guided-link" onClick={() => { setSample(''); setDatasetName('Empty'); }}><Trash2 size={14} /> Clear Sample</button></div>
            <div className="guided-note"><ShieldCheck size={16} /> {hasLogs ? `Found ${suite?.counts.total} events. Check their format in the next step.` : 'No events yet. Add a real or synthetic sample.'}</div>
          </>}

          {step === 1 && <>
            <div className="guided-section-title"><span>01</span> Select Log Format <span className="guided-inline-badge">Select the correct format</span></div>
            <div className="guided-format-choices" role="group" aria-label="Guided format">
              {(['auto', 'json', 'kv', 'csv', 'syslog_rfc5424', 'cef', 'leef', 'syslog', 'regex'] as const).map((format) =>
                <button type="button" key={format} aria-pressed={draft.format === format} className={'guided-format ' + (draft.format === format ? 'active' : '')} onClick={() => changeDraft('format', format)}>
                  {draft.format === format ? <CheckCircle2 size={17} /> : <FileText size={17} />}
                  <strong>{formatLabel(format)}</strong>
                </button>)}
            </div>
            <LocalFormatRecommendationView advice={localFormatAdvice}
              selected={draft.format} pending={pending}
              onApply={(format)=>changeDraft('format',format)}/>
            {draft.format === 'csv' && <div className="guided-two-fields">
              <label className="guided-field"><span>CSV Column Names <small>(Always comma-separated · 1–100 columns)</small></span><input aria-label="Guided CSV columns" value={draft.csvColumns} onChange={(event) => changeDraft('csvColumns', event.target.value)} placeholder="action,src_ip,dst_port" /><small>Columns are assigned in the order provided.</small></label>
              <label className="guided-field"><span>CSV Data Delimiter</span><select aria-label="Guided CSV data delimiter" value={draft.csvDelimiter ?? ','} onChange={(event) => changeDraft('csvDelimiter', event.target.value as ',' | ';' | '\t')}>
                <option value=",">Comma (,)</option><option value=";">Semicolon (;)</option><option value={'\t'}>TAB</option>
              </select><small>One record per line. Delimiters inside quoted fields are treated as values.</small></label>
            </div>}
            {draft.format === 'syslog_rfc5424' && <label className="guided-field">
              <span>RFC5424 Message Body Format</span>
              <select aria-label="RFC5424 message body format" value={draft.syslogBodyFormat ?? 'raw'}
                onChange={(event) => changeDraft('syslogBodyFormat', event.target.value as 'raw' | 'json' | 'kv' | 'cef' | 'leef')}>
                <option value="raw">Raw Text (message)</option>
                <option value="json">JSON Object (body.*)</option>
                <option value="kv">Key/Value Fields (body.*)</option>
                <option value="cef">Standalone CEF within RFC5424 (body.*) · Backend support required</option>
                <option value="leef">Standalone LEEF within RFC5424 (body.*) · Backend support required</option>
              </select>
              <small>Only RFC5424 headers are supported. RFC3164, compound formats, and multiline require separate parsers; generation compatibility is not guaranteed.</small>
            </label>}
            <div className="guided-hint"><AlertCircle size={16} /> Browser extraction is a preview. DRAFT output is limited to capability-verified JSON, KV, CSV, RFC5424, and standalone CEF/LEEF. Generic Syslog, regex, compound, and multiline output are unsupported.</div>
            <div className={'guided-family-coverage ' + (familyCoverage.incompatible ? 'attention' : '')}
              aria-label="Sample format distribution">
              <strong>Format Distribution · Browser Estimate</strong>
              <div className="guided-family-counts">
                {familyCoverage.groups.map(group => <span key={group.format}>
                  {formatLabel(group.format)} <b>{group.count}</b>
                </span>)}
                {!familyCoverage.groups.length && <span>No Samples</span>}
              </div>
              {familyCoverage.incompatible && <div className="guided-family-warning" role="note" aria-label="Mixed format guidance">
                <AlertTriangle size={15} />
                <span>{draft.format === 'auto'
                  ? 'Auto-detection supports browser preview only. Select an explicit format for DRAFT output.'
                  : 'Samples differing from chosen format: ' + familyCoverage.unexpected + '; unknown: ' + familyCoverage.unknown + ' events.'}
                  Each DRAFT parser supports a single extraction format. Separate and test incompatible event families in distinct drafts.
                  Automatic mixed-format classification and native routing are unsupported.</span>
                {familyCoverage.firstUnexpectedEventId && <button type="button"
                  onClick={() => { setSelectedId(familyCoverage.firstUnexpectedEventId!); setSelectedValue(''); }}>
                  Inspect Different-Format Samples
                </button>}
              </div>}
            </div>
            {familyCoverage.incompatible && isolatableOptions.length>0 &&
              <details className="guided-family-isolation" aria-label="Local family isolation workspace">
                <summary>Review One Event Family Separately · No Data Transfer</summary>
                <p>Mixed event formats require separate parser drafts. This temporary local Web Worker preview selects only one detected format, without editing your complete sample, existing mappings, saved revisions, or backend deployment state. Detected formats are estimates, not guaranteed native parser support.</p>
                <div className="guided-family-isolation-controls">
                  <label className="guided-field"><span>Detected Event Family</span>
                    <select aria-label="Family for isolated browser preview"
                      value={activeIsolatedFamily??''}
                      onChange={(event)=>{
                        setIsolatedFamilyChoice(event.target.value as IsolatableFamily);
                        setIsolatedError('');
                      }}>
                      {isolatableOptions.map(format=>
                        <option key={format} value={format}>{formatLabel(format)}
                          {' · '+(familyCoverage.groups.find(g=>g.format===format)?.count??0)+' event(s)'}
                        </option>)}
                    </select>
                  </label>
                  <button type="button" className="guided-cta-secondary"
                    disabled={pending||isolatedPending||!activeIsolatedFamily}
                    onClick={()=>{void previewSelectedFamily();}}>
                    <ShieldCheck size={15}/>
                    {isolatedPending?'Testing Isolated Family Locally…':'Preview Selected Family Locally'}
                  </button>
                </div>
                {isolatedError && <p role="alert" className="guided-error">{isolatedError}</p>}
                {currentIsolatedReport && <div className="guided-family-isolation-result"
                  aria-label="Isolated family browser result" role="status">
                  <strong>{formatLabel(currentIsolatedReport.format)} · Browser-only Family Preview</strong>
                  <p>{currentIsolatedReport.selectedCount} selected of {currentIsolatedReport.sourceCount} original events
                    {' · '}{currentIsolatedReport.excludedCount} other-family events preserved in the original dataset</p>
                  <div className="guided-family-isolation-metrics">
                    <span>Matched <b>{currentIsolatedReport.counts.matched}</b></span>
                    <span>Extracted <b>{currentIsolatedReport.counts.extracted}</b></span>
                    <span>Normalized <b>{currentIsolatedReport.counts.normalized}</b></span>
                    <span>Failed <b>{currentIsolatedReport.counts.failures}</b></span>
                  </div>
                  <ul aria-label="Isolated event diagnostics">
                    {currentIsolatedReport.perEvent.slice(0,12).map((ev,i)=>
                      <li key={ev.originalLine+'-'+i}>
                        Original line {ev.originalLine} · {ev.status.toUpperCase()}
                        {ev.diagnosticCodes.length>0?' · '+ev.diagnosticCodes.join(', '):' · No diagnostics'}
                      </li>)}
                  </ul>
                  {currentIsolatedReport.perEvent.length>12 &&
                    <small>Only 12 per-event statuses are shown here. All selected records are included in the aggregate counts.</small>}
                  <small>No original event values are included in this report. The source dataset and draft remain unchanged. This browser test is not a native Fluentd run, generated second parser, or Stellar target compatibility proof.</small>
                </div>}
                <div className="guided-all-family-audit" aria-label="All detected families local audit workspace">
                  <strong>Audit All Detected Event Families · Local-only</strong>
                  <p>Inspect every supported event family in separate, bounded browser Web Workers, then account for all unsupported and unknown source events. This does not create native multi-format routing, new parser files, saved revisions, or an export-ready validation result.</p>
                  <button type="button" className="guided-cta-secondary"
                    disabled={allFamilyAuditPending||isolatedPending||pending||!isolatableOptions.length}
                    onClick={()=>{void auditEveryDetectedFamily();}}>
                    <ShieldCheck size={15}/>
                    {allFamilyAuditPending?'Auditing Detected Families Locally…':'Audit All Detected Families Locally'}
                  </button>
                  {allFamilyAuditError && <p role="alert" className="guided-error">{allFamilyAuditError}</p>}
                  {currentAllFamilyAudit && <div className="guided-all-family-result"
                    aria-label="All-family browser audit result" role="status">
                    <strong>Browser-only Audit · Native and Stellar Verification Not Established</strong>
                    <p>{currentAllFamilyAudit.sourceCount} original events accounted for
                      {' · '}{currentAllFamilyAudit.reviewedCount} reviewed in supported format families
                      {' · '}{currentAllFamilyAudit.unreviewableCount} unsupported or unknown</p>
                    <div className="guided-all-family-table" role="group" aria-label="Audited format-family summaries">
                      {currentAllFamilyAudit.families.map(family=>
                        <div className="guided-all-family-row" key={family.format}>
                          <strong>{formatLabel(family.format)}</strong>
                          <span>{family.selectedCount} source events</span>
                          <span>{family.counts.extracted} extracted</span>
                          <span>{family.counts.normalized} normalized</span>
                          <span>{family.counts.failures} failed</span>
                          <small>Source lines: {family.perEvent.slice(0,12)
                            .map(event=>event.originalLine).join(', ')}
                            {family.perEvent.length>12?' (+more)':''}</small>
                          <ul className="guided-all-family-diagnostics"
                            aria-label={'All-family event diagnostics for '+family.format}>
                            {family.perEvent.slice(0,8).map(event=>
                              <li key={event.originalLine}>
                                Original line {event.originalLine} · {event.status.toUpperCase()}
                                {event.diagnosticCodes.length?' · '+event.diagnosticCodes.join(', '):' · No diagnostics'}
                              </li>)}
                          </ul>
                          {family.perEvent.length>8 &&
                            <small>Only 8 event statuses are displayed per family. All records remain counted in the audit.</small>}
                        </div>)}
                    </div>
                    {currentAllFamilyAudit.unreviewableCount>0 &&
                      <p className="guided-all-family-unknown" role="note">
                        Not silently discarded: {currentAllFamilyAudit.unreviewableEvents.slice(0,16)
                          .map(event=>'line '+event.originalLine+' ('+formatLabel(event.format)+')')
                          .join(', ')}
                        {currentAllFamilyAudit.unreviewableCount>16?' (+more)':''}.
                        Unsupported source events still require a separately reviewed parser.
                      </p>}
                    <small>All source events remain in the original dataset. The original draft, raw sample and previously verified files remain unchanged. Passing browser family tests cannot validate a single mixed-format Ruby/CONF parser or live sensor ingestion.</small>
                    <button type="button" className="guided-cta-secondary"
                      disabled={allFamilyEvidenceBusy||pending||allFamilyAuditPending}
                      onClick={()=>{void downloadAllFamilyAuditReport();}}>
                      <FileDown size={15}/>
                      {allFamilyEvidenceBusy?'Preparing Redacted Audit…':'Download Redacted Family Audit JSON'}
                    </button>
                    <small>Explicit download only: the file binds this source/draft to SHA-256 hashes and contains aggregate format counts, source line numbers and explicit unsupported event counts, never raw customer event values.</small>
                    {allFamilyEvidenceError &&
                      <p role="alert" className="guided-error">{allFamilyEvidenceError}</p>}
                  </div>}
                </div>
                <small>Nothing is uploaded, exported, saved, or installed by this action. Unknown, unsupported, multiline, oversized or stale event families cannot silently disappear. Create and validate a separate draft for each supported format before exporting DRAFT files.</small>
              </details>}
            <div className="guided-section-title"><span>02</span> Select a Value in the Sample</div>
            <div className="guided-event-picker">
              <div className="guided-event-buttons" aria-label="Guided event list">
                {(suite?.events ?? []).slice(0, 100).map((event) =>
                  <button type="button" key={event.id} onClick={() => { setSelectedId(event.id); setSelectedValue(''); setKeyboardValue(''); }} className={'guided-event-option ' + (activeEvent?.id === event.id ? 'active' : '')}>
                    <span className={'guided-status-dot ' + event.status} />
                    <strong>#{event.line}</strong><span>{formatLabel(event.detected.format)}</span>
                  </button>)}
              </div>
              <div className="guided-event-raw">
                <div className="guided-raw-label">Raw Event · Drag to Select a Value</div>
                {activeEvent ? <pre aria-label="Guided selectable raw event" tabIndex={0} onMouseUp={() => captureValue(window.getSelection()?.toString() ?? '')}>{selectedValue && activeEvent.raw.includes(selectedValue) ? <>
                  {activeEvent.raw.slice(0, activeEvent.raw.indexOf(selectedValue))}
                  <mark className="guided-selected-token">{selectedValue}</mark>
                  {activeEvent.raw.slice(activeEvent.raw.indexOf(selectedValue) + selectedValue.length)}
                </> : activeEvent.raw}</pre> : <div className="guided-no-events">Add logs first.</div>}
                <details className="guided-keyboard-value" aria-label="Keyboard raw-value selection">
                  <summary>Keyboard Alternative: Select an Exact Raw Value</summary>
                  <p>Enter or paste a short value that appears exactly in the selected raw event. Use the explicit button to prepare a field proposal. The value stays in browser memory; this action does not modify parser rules or send network requests.</p>
                  <div className="guided-keyboard-value-controls">
                    <label className="guided-field"><span>Exact Raw Value from Selected Event</span>
                      <input aria-label="Exact raw value to select" value={keyboardValue}
                        maxLength={80} autoComplete="off" spellCheck={false}
                        onChange={(event)=>setKeyboardValue(event.target.value)}
                        placeholder="Select up to 80 characters from the event"/>
                    </label>
                    <button type="button" className="guided-cta-secondary"
                      disabled={!keyboardCandidateValid}
                      onClick={()=>{
                        if(!keyboardCandidateValid) return;
                        captureValue(keyboardCandidate);
                        setKeyboardValue('');
                      }}>
                      <ShieldCheck size={15}/> Use Value for Field Proposal
                    </button>
                  </div>
                  <small>The button remains disabled when the value is absent, spans multiple lines or exceeds the 80-character limit. Keyboard selection is an alternative to mouse highlighting; it is not automatic field mapping or native parser verification.</small>
                </details>
                <div className="guided-extracted-tags">Detected fields: {activeFieldNames.length ? activeFieldNames.map((field) => {
                  const mapped=draft.mappings.some(mapping=>mapping.source===field);
                  const suggested=unmappedSuggestions.some(candidate=>candidate.source===field);
                  const label=mapped?'Review mapping for '+field:
                    suggested?'Add draft mapping for '+field:
                    'Review field in mapping editor: '+field;
                  return <button type="button" title={label} aria-label={label}
                    key={field} onClick={()=>openFieldMapping(field)}>
                    <Plus size={12}/> {field}
                  </button>;
                }) : 'None yet'}</div>
              </div>
            </div>
            {selectedValue && <div className="guided-proposal">
              <div className="guided-section-title"><WandSparkles size={17} /> Create Field from Selection</div>
              <div className="guided-sample-value">{selectedValue}</div>
              <label className="guided-field"><span>New Field Name</span><input aria-label="Guided proposed field name" value={fieldName} onChange={(e) => { setFieldName(e.target.value); setProposalResult(null); }} /></label>
              {proposal && 'error' in proposal ? <p className="guided-error" role="alert">{proposal.error}</p> : proposal ? <>
                <p className="guided-tip">A candidate value was identified in the log structure. It has not yet been matched across all samples.</p>
                <details className="guided-advanced"><summary>Advanced: View Extraction Rule</summary><pre>{proposal.pattern}</pre></details>
                <div className="guided-inline-actions"><button className="guided-cta-secondary" type="button" onClick={checkProposal} disabled={proposalTesting}>{proposalTesting ? 'Checking…' : 'Test Across All Samples'}</button>
                  <button className="guided-cta-main" type="button" onClick={addRule} disabled={!acceptedResult?.matched}>Apply Field Rule</button></div>
                {acceptedResult && <p className="guided-preview-evidence" role="status">Preview: {acceptedResult.matched} / {acceptedResult.total} matching events · Fluentd not verified</p>}
                {fieldHighlights && <div className="guided-match-review" aria-label="Field match examples">
                  <div className="guided-match-header"><strong>Field Extraction by Sample</strong><span>Showing {fieldHighlights.sampled} / {fieldHighlights.total} samples</span></div>
                  {fieldHighlights.rows.map((row) => {
                    const snippet = matchContext(row);
                    return <div className="guided-match-row" key={row.id}>
                      <div className="guided-match-row-head">
                        <strong>#{row.line}</strong>
                        <span className={'guided-match-status ' + row.status}>
                          {row.status === 'matched' ? 'Matched' : row.status === 'unmatched' ? 'Unmatched' : 'Not Tested'}
                        </span>
                      </div>
                      <code>{snippet.before}{snippet.selected ? <mark className="guided-match-highlight">{snippet.selected}</mark> : null}{snippet.after}</code>
                    </div>;
                  })}
                  {fieldHighlights.omitted > 0 && <p className="guided-match-omitted">Remaining {fieldHighlights.omitted} events omitted here. Refer to the Web Worker summary above for full match counts.</p>}
                  <p className="guided-match-disclaimer">Highlights reflect an approximate browser regex match. They do not prove native Fluentd support or official metadata mapping.</p>
                </div>}
              </> : null}
            </div>}
          </>}

          {step === 2 && <>
            <div className="guided-section-title"><span>01</span> Extracted Fields and Normalization Targets <span className="guided-inline-badge">{draft.mappings.length} rules</span></div>
            <div className="guided-hint"><AlertTriangle size={16} /> Destination fields are draft values. The full official Stellar Cyber Interflow dictionary is not provided until verified.</div>
            <details className="guided-schema-guide" aria-label="Backend authoring schema guide">
              <summary>Inspect Backend Input Schema (not an official field dictionary)</summary>
              <p>Reads only the connected backend ParserProject JSON Schema. No raw samples or mapped values are sent. This is not an official Stellar Cyber dictionary or runtime/ingestion proof.</p>
              <button type="button" className="guided-cta-secondary" disabled={schemaLoading} onClick={() => { void loadAuthoringSchema(); }}>
                <ShieldCheck size={15} /> {schemaLoading ? 'Loading schema…' : 'Fetch Backend Schema (GET)'}
              </button>
              {schemaError && <p className="guided-error" role="alert">{schemaError}</p>}
              {schemaGuide && <div className="guided-schema-verified" aria-label="Verified backend schema summary">
                <strong>ParserProject {schemaGuide.revision} · Local Backend Schema</strong>
                <p><b>Extraction Formats</b> {schemaGuide.formats.join(' · ')}</p>
                <p><b>Normalized Types</b> {schemaGuide.fieldTypes.join(' · ')}</p>
                <p><b>Source/destination naming rules (max {schemaGuide.fieldNameMaxLength} characters)</b></p>
                <code>{schemaGuide.fieldNamePattern}</code>
                <p><b>Receiver Protocols</b> {schemaGuide.receiverProtocols.join(' · ')} · Ports {schemaGuide.port.min}–{schemaGuide.port.max} · Message {schemaGuide.messageLength.min}–{schemaGuide.messageLength.max} bytes</p>
                <small>This lists supported data shapes and types only. It does not verify official field semantics or existence. The UI may apply stricter validation.</small>
              </div>}
            </details>
            <div className="guided-note"><HelpCircle size={15} /> Only a reviewed subset of scalar fields from Stellar Cyber's public <a href={officialDictionaryUrl65} target="_blank" rel="noopener noreferrer">6.5 Metadata Dictionary</a> · <a href={officialDictionaryUrl} target="_blank" rel="noopener noreferrer">7.0 Standard Metadata Dictionary</a> is shown. Actual DP version and parser compatibility require independent validation.</div>
            <div className="guided-map-list">{draft.mappings.map((mapping, index) =>
              <div className={'guided-map-card'+(selectedMappingId===mapping.id?' selected-field':'')}
                key={mapping.id} data-selected={selectedMappingId===mapping.id}
                aria-label={'Mapping for '+mapping.source}>
                <div className="guided-map-number"><span>FIELD {String(index + 1).padStart(2, '0')}</span>
                  <button type="button" title="Remove Mapping" aria-label={'Remove mapping ' + index} onClick={() => setDraft((old) => ({ ...old, mappings: old.mappings.filter((item) => item.id !== mapping.id) }))}><Trash2 size={15} /></button></div>
                <div className="guided-map-inputs">
                  <label className="guided-field"><span>Source Field</span><input aria-label={'Source field ' + index} list="guided-field-suggestions" value={mapping.source} onChange={(e) => setMapping(mapping.id, 'source', e.target.value)} /></label>
                  <span className="guided-arrow-to"><ArrowRight size={18} /></span>
                  <label className="guided-field"><span>Normalized Field</span><input aria-label={'Destination field ' + index} value={mapping.target} onChange={(e) => setMapping(mapping.id, 'target', e.target.value)} /></label>
                </div>
                <div className="guided-map-inputs">
                  <label className="guided-field"><span>Conversion Type</span><select aria-label={'Field type ' + index} value={mapping.type} onChange={(e) => setMapping(mapping.id, 'type', e.target.value)}>{TYPES.map((type) => <option value={type} key={type} disabled={type === 'number'}>{TYPE_LABELS[type]}</option>)}</select></label>
                  <label className="guided-field"><span>Field Group</span><select aria-label={'Mapping group ' + index} value={options.groups[mapping.id] ?? 'vendor_fields'} onChange={(e) => setGuided({ ...options, groups: { ...options.groups, [mapping.id]: e.target.value as FieldGroup } })}>{FIELD_GROUPS.map((group) => <option key={group} value={group}>{GROUP_LABELS[group]}</option>)}</select></label>
                </div>
                <details className="guided-official-field">
                  <summary>Select a Public Metadata Destination (6.5/7.0 docs)</summary>
                  <p>Changes only this mapping destination, type, and group. This is a curated subset, not an automatic recommendation or target compatibility test.</p>
                  <label className="guided-field"><span>Public Metadata Field Candidate</span>
                    <select aria-label={'Official metadata field ' + index} value="" onChange={(event) => {
                      if (event.target.value) chooseOfficialMetadata(mapping.id, event.target.value);
                    }}>
                      <option value="">Select to Apply (keep existing mapping)</option>
                      {curatedOfficialMetadata.map((field) => <option key={field.name} value={field.name}>
                        {field.name} · {field.label} ({field.documentedType})
                      </option>)}
                    </select>
                  </label>
                  {metadataError?.mappingId === mapping.id && <p className="guided-error" role="alert">{metadataError.message}</p>}
                </details>
                <MappingCoverageView suite={suite} mapping={mapping} index={index}
                  onInspect={(eventId) => { setSelectedId(eventId); setSelectedValue(''); setStep(1); }} />
                <TypeSuggestionView suite={suite} mapping={mapping} index={index}
                  onApply={(type) => setMapping(mapping.id, 'type', type)} />
              </div>)}</div>
            <datalist id="guided-field-suggestions">{activeFieldNames.map((name) => <option value={name} key={name} />)}</datalist>
            <div className="guided-inline-actions"><button type="button" className="guided-cta-secondary" onClick={() => addMapping()}><Plus size={15} /> Add Field Mapping</button>
              {activeFieldNames.some((field) => !draft.mappings.some((mapping) => mapping.source === field)) && <button className="guided-link" type="button" onClick={() => { const first = activeFieldNames.find((field) => !draft.mappings.some((mapping) => mapping.source === field)); if (first) addMapping(first); }}><WandSparkles size={15} /> Suggest Another Unmapped Field</button>}
              <button className="guided-cta-secondary" type="button" disabled={!unmappedSuggestions.length} onClick={applyUnmappedSuggestions}>
                <WandSparkles size={15} /> Add Remaining Safe Fields ({unmappedSuggestions.length})
              </button></div>
            <div className="guided-note"><ShieldCheck size={15} /> Unmapped source fields remain visible in preview. The full sample test detects duplicate mappings and type conversion errors.</div>
            <div className="guided-section-title"><span>02</span> Optional Field Enrichment <span className="guided-inline-badge">{options.enrichment?.length ?? 0} steps</span></div>
            <p className="guided-description">Apply constants, copies, lowercase, or uppercase transformations to normalized fields in order. Raw logs are not modified.</p>
            <datalist id="guided-normalized-suggestions">
              {draft.mappings.filter((mapping) => (options.groups[mapping.id] ?? 'vendor_fields') !== 'vendor_fields').map((mapping) => <option key={mapping.id} value={mapping.target} />)}
              {(options.enrichment ?? []).map((rule) => <option key={rule.id} value={rule.target} />)}
            </datalist>
            <div className="guided-enrichment-list">{(options.enrichment ?? []).map((rule, index) => <div key={rule.id} className="guided-enrichment-rule">
              <div className="guided-map-number"><span>Enrichment {index + 1}</span>
                <button type="button" aria-label={'Remove enrichment ' + index} onClick={() => removeEnrichment(rule.id)}><Trash2 size={15} /></button>
              </div>
              <div className="guided-enrichment-fields">
                <label className="guided-field"><span>Operation</span><select aria-label={'Enrichment operator ' + index} value={rule.operator} onChange={(event) => changeEnrichment(rule.id, 'operator', event.target.value)}>
                  <option value="set_const">Set Constant</option><option value="copy">Copy Field</option>
                  <option value="lowercase">Lowercase</option><option value="uppercase">Uppercase</option>
                </select></label>
                {rule.operator === 'set_const'
                  ? <label className="guided-field"><span>Constant Value (text)</span><input aria-label={'Enrichment value ' + index} value={rule.value} onChange={(event) => changeEnrichment(rule.id, 'value', event.target.value)} /></label>
                  : <label className="guided-field"><span>Existing Normalized Field</span><input aria-label={'Enrichment source ' + index} list="guided-normalized-suggestions" value={rule.source} onChange={(event) => changeEnrichment(rule.id, 'source', event.target.value)} /></label>}
                <label className="guided-field"><span>New Output Field</span><input aria-label={'Enrichment target ' + index} value={rule.target} placeholder="custom.extra" onChange={(event) => changeEnrichment(rule.id, 'target', event.target.value)} /></label>
              </div>
            </div>)}</div>
            <button type="button" className="guided-cta-secondary" onClick={addEnrichment} disabled={(options.enrichment?.length ?? 0) >= 64}><Plus size={15} /> Add Enrichment Step</button>
            <div className="guided-hint"><ShieldCheck size={15} /> Before generation, test enrichment with browser preview in step 5. Actual Fluentd execution and Stellar ingestion remain unverified.</div>

          </>}

          {step === 3 && <>
            <div className="guided-section-title"><span>01</span> Log Receiver</div>
            <div className="guided-transport-grid">{(['udp', 'tcp'] as const).map((protocol) =>
              <label className={'guided-transport ' + (options.receiver.protocols.includes(protocol) ? 'active' : '')} key={protocol}>
                <input type="checkbox" aria-label={protocol.toUpperCase() + ' receiver'} checked={options.receiver.protocols.includes(protocol)} onChange={(e) => chooseProtocol(protocol, e.target.checked)} />
                <span><strong>{protocol.toUpperCase()}</strong><small>{protocol === 'udp' ? 'Datagram transport' : 'Connection-oriented · newline-framed'}</small></span>
                {options.receiver.protocols.includes(protocol) && <CheckCircle2 size={18} />}
              </label>)}</div>
            <div className="guided-three-fields">
              <label className="guided-field"><span>Sensor / Parser CONF Port</span><input aria-label="Receiving port" type="number" min={draft.format==='syslog_rfc5424'?6800:1024} max={65535} step={1} value={options.receiver.port} onChange={(e) => setReceiver('port', Number(e.target.value))} /></label>
              <label className="guided-field"><span>Bind Policy</span><select aria-label="Bind policy" value={options.receiver.bindPolicy} onChange={(e) => setReceiver('bindPolicy', e.target.value)}><option value="loopback">Loopback test (127.0.0.1)</option><option value="all">All interfaces (0.0.0.0)</option></select></label>
              <label className="guided-field"><span>Maximum Message Size (bytes)</span><input aria-label="Message limit" type="number" min={1024} max={65536} value={options.receiver.messageLimit} onChange={(e) => setReceiver('messageLimit', Number(e.target.value))} /></label>
            </div>
            <div className="guided-note"><ShieldCheck size={15}/> One shared port: the sensor log destination and generated <code>.conf</code> receiver <code>&lt;source&gt;</code> use the same number. It is not a separate transport port. This does not establish listener readiness.</div>
            {draft.format==='syslog_rfc5424' && options.receiver.port<6800 &&
              <p role="alert" className="guided-error">RFC5424 Syslog sensor and CONF listener port must be at least 6800.</p>}
            <div className="guided-port-proposal" aria-label="Parser listener port candidate">
              <strong>Parser Listener Port Candidate · Read-only</strong>
              <p>Only parser inventories and reservations supplied by an authorized local backend are checked. The candidate is the intended SAME port for sensor log receipt and the generated CONF listener, but actual sensor binding and port availability remain unverified. Recheck ownership and conflicts immediately before deployment.</p>
              <div className="guided-port-actions">
                <button type="button" className="guided-cta-secondary" disabled={portPlanLoading}
                  onClick={() => { void checkParserListenerPort(false); }}>
                  <ShieldCheck size={15} /> {portPlanLoading ? 'Checking inventory…' : 'Request Port Candidate'}
                </button>
                <button type="button" className="guided-cta-secondary" disabled={portPlanLoading}
                  onClick={() => { void checkParserListenerPort(true); }}>
                  <HelpCircle size={15} /> Review Entered Port
                </button>
              </div>
              {currentPortPlanError && <p className="guided-error" role="alert">{currentPortPlanError}</p>}
              {currentPortPlan && <div className="guided-port-result" aria-label="Parser port proposal result">
                <strong>{currentPortPlan.recommendedPort} · {currentPortPlan.source === 'USER_OVERRIDE' ? 'User-entered Port' : 'Suggested Candidate'}</strong>
                <p>Occupancy evidence: {currentPortPlan.occupiedPorts.length} records · {currentPortPlan.status === 'INCOMPLETE_EVIDENCE'
                  ? 'INCOMPLETE_EVIDENCE · Sensor binding or reservation evidence incomplete'
                  : 'CANDIDATE_REQUIRES_DEPLOY_RECHECK · Recheck before deployment'}</p>
                {currentPortPlan.missingEvidence.length > 0 && <small>Missing Evidence: {currentPortPlan.missingEvidence.join(', ')}</small>}
                <small>Shared sensor/CONF port: {currentPortPlan.sensorIngestPort} · Candidate only: not deployable, not proven free, and no verified sensor binding or reservation.</small>
                {currentPortPlan.source === 'SUGGESTED' && <button type="button" className="guided-cta-secondary" onClick={useSuggestedParserPort}>
                  Apply Candidate to Draft (recheck required)
                </button>}
              </div>}
            </div>
            <div className="guided-hint"><ShieldAlert size={16} /> No port can be guaranteed free until sensor bindings and concurrent reservations are verified. Applying a candidate never deploys or opens a network socket.</div>
            <div className="guided-section-title"><span>02</span> Event Classification</div>
            <p className="guided-description">Select the event category from log field values. When multiple rules match, the first matching rule takes precedence.</p>
            <div className="guided-conditions">{options.classification.rules.map((rule, index) =>
              <div key={rule.id} className="guided-condition">
                <span className="guided-condition-index">IF {index + 1}</span>
                <input aria-label={'Rule field ' + index} placeholder="Source field (action)" list="guided-field-suggestions" value={rule.sourceField} onChange={(e) => changeCondition(rule.id, 'sourceField', e.target.value)} />
                <span>Value =</span>
                <input aria-label={'Rule value ' + index} placeholder="deny" value={rule.equals} onChange={(e) => changeCondition(rule.id, 'equals', e.target.value)} />
                <span>→</span>
                <select aria-label={'Rule class ' + index} value={rule.index} onChange={(e) => changeCondition(rule.id, 'index', e.target.value)}>{CLASSIFICATIONS.map((category) => <option key={category} value={category}>{CLASS_LABELS[category]}</option>)}</select>
                <button type="button" aria-label={'Remove rule ' + index} onClick={() => setGuided({ ...options, classification: { ...options.classification, rules: options.classification.rules.filter((item) => item.id !== rule.id) } })}><Trash2 size={14} /></button>
              </div>)}</div>
            <button type="button" className="guided-cta-secondary" onClick={addCondition}><Plus size={15} /> Add Condition</button>
            <div className="guided-default-class"><span>Events with No Matching Condition</span><select aria-label="Default classification" value={options.classification.defaultIndex} onChange={(e) => setGuided({ ...options, classification: { ...options.classification, defaultIndex: e.target.value as EventClass } })}>{CLASSIFICATIONS.map((category) => <option key={category} value={category}>{CLASS_LABELS[category]}</option>)}</select></div>
            <div className="guided-section-title"><span>03</span> Classification by Sample <span className="guided-inline-badge">Local Rule Prediction</span></div>
            <div className="guided-routing-preview" aria-label="Sample classification preview">
              {!suite?.events.length && <div className="guided-route-empty">Add sample logs to preview classification.</div>}
              {(suite?.events ?? []).slice(0, 30).map((event) => {
                const hint = suggestClassification(event, options);
                return <div className="guided-routing-row" key={event.id}>
                  <span className="guided-routing-event">#{event.line}</span>
                  <div><strong className={hint.status === 'unresolved' ? 'unresolved' : hint.status === 'matched' ? 'matched' : 'fallback'}>{hint.index ?? 'Unclassified'}</strong><small>{hint.reason}</small></div>
                  <span className={'guided-route-state ' + hint.status}>{hint.status === 'unresolved' ? 'Extraction Failed' : hint.status === 'matched' ? 'Condition Matched' : 'Default'}</span>
                </div>;
              })}
              {(suite?.events.length ?? 0) > 30 && <p className="guided-route-empty">Only the first 30 events are shown. Run the full suite in step 5.</p>}
            </div>
            <div className="guided-hint"><AlertTriangle size={16} /> Classification is a browser-rule preview. Actual stellar_log_index routing requires independent Fluentd engine validation.</div>
          </>}

          {step === 4 && <>
            <div className="guided-test-header"><div><div className="guided-section-title"><span>01</span> Test All Samples</div><p>Extraction matches are not necessarily correctly normalized. Failures and warnings are shown separately.</p></div>
              <button type="button" className="guided-cta-main" onClick={onRunSuite} disabled={!hasLogs || pending}><Play size={15} /> Run Full Browser Test</button></div>
            <div className="guided-test-metrics">
              {[
                ['Input Events', runState?.suite.counts.total ?? '—'],
                ['Extracted', runState?.suite.counts.extracted ?? '—'],
                ['Normalized', runState?.suite.counts.normalized ?? '—'],
                ['Failures', runState?.suite.counts.failures ?? '—'],
              ].map(([label, value]) => <div key={label} className="guided-test-metric"><span>{label}</span><strong>{value}</strong></div>)}
            </div>
            <div className="guided-hint"><ShieldAlert size={16} /> {runState ? 'Test engine: browser-preview. This does not verify native Fluentd or actual Stellar ingestion.' : 'No full-sample test exists for this draft. Run browser tests first.'}</div>
            <div className="guided-evidence-export" aria-label="Browser test evidence export">
              <button type="button" className="guided-cta-secondary"
                disabled={!runState || pending || evidenceDownloading}
                onClick={() => { void downloadBrowserTestEvidence(); }}>
                <FileDown size={15} /> {evidenceDownloading ? 'Generating Evidence…' : 'Download Browser Test Evidence JSON'}
              </button>
              <small>Evidence covers the current draft and sample only. Raw events, normalized values, and error messages are excluded; SHA-256 hashes and diagnostic codes remain. Fluentd/Stellar compatibility is unverified.</small>
              {evidenceError && <p role="alert" className="guided-error">{evidenceError}</p>}
            </div>            <details className="guided-baseline-compare" aria-label="Browser evidence baseline comparison">
              <summary>Compare Previous Browser Test · Improvements & Regressions</summary>
              <p>Select a previously downloaded evidence JSON file. It is inspected in the browser and must match the current sample SHA-256. This is not native or device E2E.</p>
              <label className="guided-field"><span>Previous Browser Test Evidence File</span>
                <input type="file" accept=".json,application/json" aria-label="Previous browser evidence JSON"
                  onChange={(event) => {
                    setBaselineEvidenceFile(event.target.files?.[0] ?? null);
                    setComparisonResult(null);
                    setComparisonError(null);
                  }} />
              </label>
              <button type="button" className="guided-cta-secondary"
                disabled={!runState || !baselineEvidenceFile || comparingEvidence || pending}
                onClick={() => { void comparePreviousBrowserEvidence(); }}>
                <ClipboardCheck size={15} /> {comparingEvidence ? 'Comparing Baseline…' : 'Compare Same-Sample Evidence'}
              </button>
              {currentComparisonError && <p className="guided-error" role="alert">{currentComparisonError}</p>}
              {currentComparison && <div className="guided-comparison-result" aria-label="Browser evidence comparison result">
                <strong>Same raw sample · Draft {currentComparison.sameDraft ? 'Unchanged' : 'Changed'}</strong>
                <p>Improved {currentComparison.improved} · Regressed {currentComparison.regressed} · Unchanged {currentComparison.unchanged} · Diagnostic Changes {currentComparison.changedDiagnostics}</p>
                {currentComparison.changed.length > 0 && <ul>
                  {currentComparison.changed.map((event) => <li key={event.event}>
                    Event #{event.event} (line {event.line}) · {event.change === 'improved' ? 'Improved' : 'Regressed'}
                  </li>)}
                </ul>}
                <small>Only normalization success is compared. Raw and normalized values are not shown, and Fluentd/Stellar compatibility remains unverified.</small>
              </div>}
            </details>

            <div className="guided-filter"><span>Per-event Results: {suite?.events.length ?? 0} events</span><div>{(['all','fail','warning'] as const).map((filter) => <button type="button" aria-pressed={errorFilter === filter} key={filter} className={errorFilter === filter ? 'selected' : ''} onClick={() => setErrorFilter(filter)}>{filter === 'all' ? 'All' : filter === 'fail' ? 'Failures' : 'Warnings'}</button>)}</div></div>
            <Suspense fallback={<p className="guided-note">Loading local rule diagnostics…</p>}>
            <BrowserRuleTracePanel suite={suite} pending={pending}
              mappings={draft.mappings} selectedEventId={selectedId}
              onSelectEvent={setSelectedId}
              onEditMapping={(index)=>{
                setSelectedMappingId(draft.mappings[index]?.id??null);
                setStep(2);
              }}/>
            </Suspense>
            <div className="guided-test-events">{(suite?.events ?? []).filter((event) => errorFilter === 'all' || event.status === errorFilter).map((event) =>
              <button className="guided-test-event" type="button" key={event.id} onClick={() => { setSelectedId(event.id); setStep(1); }}>
                <span className={'guided-status-dot ' + event.status} />
                <span><strong>Event #{event.line}</strong><small>{event.diagnostics.slice(0, 2).map((diag) => diag.message).join(' · ') || 'No browser preview errors'}</small></span>
                <strong className={'guided-status-name ' + event.status}>{event.status === 'fail' ? 'Failed' : event.status === 'warning' ? 'Warning' : 'Preview Passed'}</strong>
                <ChevronRight size={14} />
              </button>)}
            </div>
            <button type="button" className="guided-link" onClick={onExpert}><Code2 size={15} /> Inspect Errors in Expert Workbench</button>
          </>}

          {step === 5 && <>
            <div className="guided-export-status"><LockKeyhole size={22} /><div><strong>{qualifiedPair ? 'Parser Draft Generated · DRAFT' : 'Draft Validation Stage'}</strong><p>After backend schema validation and browser tests, you can generate two DRAFT files. Native Fluentd and Stellar target ingestion remain unverified. No automatic device deployment occurs.</p></div></div>
            <div className="guided-section-title"><span>01</span> Planned Output Files</div>
            <div className="guided-pair-files">
              <div><FileText size={21} /><span><strong>{names?.config ?? 'Valid Parser ID Required'}</strong><small>Receiver and routing configuration · Awaiting generation</small></span><span className="guided-pending-tag">{qualifiedPair ? 'DRAFT · SHA OK' : 'NOT GENERATED'}</span></div>
              <div><FileText size={21} /><span><strong>{names?.parser ?? 'Valid Parser ID Required'}</strong><small>Extensionless Ruby parser fragment · Awaiting generation</small></span><span className="guided-pending-tag">{qualifiedPair ? 'DRAFT · SHA OK' : 'NOT GENERATED'}</span></div>
            </div>
            <div className="guided-section-title"><span>02</span> Draft Contract Validation</div>
            {artifactContract.ok ? <div className="guided-note"><ClipboardCheck size={17} /> UI input checks passed. Native engine and target compatibility require separate verification.</div> : <div className="guided-contract-errors">{artifactContract.errors.map((issue) => <div key={issue}><AlertCircle size={15} /><span>{issue}</span></div>)}</div>}
            {!backendProject.ok && <div className="guided-contract-errors" aria-label="Backend mapping compatibility errors">{backendProject.issues.map((issue, index) => <div key={issue.code + index}><AlertCircle size={15} /><span>{issue.message}</span></div>)}</div>}
            <div className="guided-section-title"><span>03</span> Local Backend Contract Validation</div>
            <div className="guided-backend-control">
              <button type="button" className="guided-cta-secondary" onClick={() => { void checkBackend(); }} disabled={!backendProject.ok || validatingBackend}>
                <ShieldCheck size={15} /> {validatingBackend ? 'Validating Backend…' : 'Validate Backend Input'}
              </button>
              <span>{qualifiedBackend?.result.ok ? 'Schema PASS · Engine Unverified' : 'Not Validated / Backend Required'}</span>
            </div>
            {qualifiedBackend && !qualifiedBackend.result.ok && <div className="guided-contract-errors" aria-label="Backend validation errors">
              {qualifiedBackend.result.issues.map((issue, index) => {
                const destination = backendIssueTarget(issue.path);
                return <div key={issue.code + index} className="guided-backend-issue">
                  <AlertCircle size={15} /><span>{issue.code}: {issue.message} ({issue.path})</span>
                  <button type="button" className="guided-fix-link" onClick={() => setStep(destination.step)}>{destination.label}</button>
                </div>;
              })}
            </div>}
            {currentBackendError && <div className="guided-error" role="alert">{currentBackendError}</div>}
            <div className="guided-section-title"><span>04</span> Generate and Download Both Files</div>
            <div className="guided-export-actions">
              {qualifiedBackend?.result.ok
                ? <button type="button" className="guided-cta-main" onClick={() => { void buildDraftPair(); }} disabled={generatingPair || !runState?.suite.counts.total || runState.suite.counts.matched !== runState.suite.counts.total || runState.suite.counts.normalized !== runState.suite.counts.total || runState.suite.counts.failures > 0}>
                  <FileArchive size={15} /> {generatingPair ? 'Generating Draft…' : 'Generate 2 Parser Files (DRAFT)'}
                </button>
                : <button type="button" className="guided-cta-main" disabled><FileArchive size={15} /> Generate 2 Parser Files (Backend Required)</button>}
              <button type="button" className="guided-cta-secondary" disabled={!backendProject.ok} onClick={() => { if (backendProject.ok) localDownload('parser-project-'+backendProject.project.slug+'.json', JSON.stringify(backendProject.project, null, 2)); }}><Download size={15} /> Download Project JSON for Backend</button>
            </div>
            <details className="guided-local-project-import" aria-label="Offline Project JSON restore">
              <summary>Restore Existing Project JSON · Offline, Explicit &amp; Lossless</summary>
              <p>Previously downloaded Parser Studio project JSON can be reviewed locally.
                Selecting a file never sends it to a server or changes your draft.
                Unsupported fields, receiver settings, type conversions and routes are refused
                rather than silently dropped.</p>
              <label className="guided-field"><span>Existing Project JSON</span>
                <input type="file" aria-label="Offline project JSON file"
                  accept=".json,application/json" onChange={event=>{
                    localProjectReviewId.current++;
                    setLocalProjectFile(event.target.files?.[0]??null);
                    setLocalProjectCandidate(null);setLocalProjectReplaceConfirmed(false);
                    setLocalProjectReviewBusy(false);setLocalProjectError('');
                  }}/>
              </label>
              <button type="button" className="guided-cta-secondary"
                disabled={!localProjectFile||localProjectReviewBusy}
                onClick={()=>{void inspectLocalProjectFile();}}>
                <ShieldCheck size={15}/>
                {localProjectReviewBusy?'Validating Project JSON…':'Validate Local Project JSON'}
              </button>
              {localProjectError&&<p role="alert" className="guided-error">{localProjectError}</p>}
              {localProjectCandidate&&<div className="guided-local-project-ready" aria-label="Validated local project">
                <strong>Lossless Project Model Verified · No Import Yet</strong>
                <p>{localProjectCandidate.name} · {localProjectCandidate.format.toUpperCase()}
                  {' · '}Mappings: {localProjectCandidate.mappings.length}
                  {' · '}One shared port: {localProjectCandidate.guided?.receiver.port}</p>
                <label className="guided-owner-check">
                  <input type="checkbox" aria-label="Confirm replace draft with Project JSON"
                    checked={localProjectReplaceConfirmed}
                    onChange={event=>setLocalProjectReplaceConfirmed(event.target.checked)}/>
                  Replace the current unsaved draft and clear ALL raw sample logs.
                  This file is not saved as a revision automatically.
                </label>
                <button type="button" className="guided-cta-secondary"
                  disabled={!localProjectReplaceConfirmed||localProjectReviewBusy}
                  onClick={applyLocalProjectDraft}>
                  <FileCheck2 size={15}/> Restore Validated JSON as Unsaved Draft
                </button>
              </div>}
              <small>256 KiB maximum · Strict UTF-8 · No Ruby execution · No DP/sensor traffic ·
                Exact schema and semantics required. Native Fluentd and target import remain unverified.</small>
            </details>
            {qualifiedBackend?.result.ok && (!runState?.suite.counts.total || runState.suite.counts.matched !== runState.suite.counts.total || runState.suite.counts.normalized !== runState.suite.counts.total || runState.suite.counts.failures > 0) && <div className="guided-hint"><AlertTriangle size={16} /> Run the full browser test in step 5 for this exact draft and sample. All events must be extracted and normalized before DRAFT generation is enabled.</div>}
            {qualifiedPair && <div className="guided-generated-pair" aria-label="Generated draft parser pair">
              <div className="guided-generated-header"><FileCheck2 size={18} /><div><strong>2 DRAFT Files · SHA-256 Verified</strong><small>Native Fluentd and Stellar import unverified · No automatic deployment</small></div></div>
              <div className="guided-generated-files">{qualifiedPair.files.map((file) =>
                <button className="guided-cta-secondary" key={file.name} type="button" onClick={() => localDownload(file.name, file.content, 'application/octet-stream')}><Download size={15} /> {file.name}</button>)}</div>
              <div className="guided-generated-warnings">{qualifiedPair.manifest.warnings.map((warning, index) => <p key={index}><AlertTriangle size={13} /> {warning}</p>)}</div>
              <details className="guided-legacy-preflight" aria-label="Legacy deployment preflight only">
                <summary>Legacy POC Upload Preflight (No Actual Upload)</summary>
                <p>Checks the verified files' names, revision, listener port, and SHA-256 on the backend via <code>/stellar/legacy/prepare</code> only. No DP registration, activation, or API key is used.</p>
                <div className="guided-legacy-inputs">
                  <label className="guided-field"><span>Tenant Identifier (not a password or API key)</span>
                    <input aria-label="Legacy dry-run tenant" value={legacyDryTenant}
                      placeholder="synthetic-tenant" autoComplete="off" maxLength={128}
                      onChange={(event) => {
                        legacyRequestToken.current++;
                        setLegacyDryTenant(event.target.value);setLegacyDryProof(null);setLegacyDryError(null);
                      }} />
                  </label>
                  <label className="guided-field"><span>Legacy File Version Label</span>
                    <input aria-label="Legacy dry-run version" value={legacyDryVersion}
                      maxLength={64} placeholder="1.0.0"
                      onChange={(event) => {
                        legacyRequestToken.current++;
                        setLegacyDryVersion(event.target.value);setLegacyDryProof(null);setLegacyDryError(null);
                      }} />
                  </label>
                </div>
                <button type="button" className="guided-cta-secondary"
                  disabled={legacyDryPending || pending ||
                    !/^[A-Za-z0-9_-]{1,128}$/.test(legacyDryTenant) ||
                    !/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(legacyDryVersion)}
                  onClick={() => { void runLegacyDryRun(); }}>
                  <ShieldCheck size={15} /> {legacyDryPending ? 'Legacy Preflight…' : 'Check Legacy Upload Contract Only'}
                </button>
                {currentLegacyError && <p className="guided-error" role="alert">{currentLegacyError}</p>}
                {currentLegacyProof && <div className="guided-legacy-proof" aria-label="Legacy preflight proof">
                  <strong>Parser Pair Integrity Verified · DRAFT · No Upload</strong>
                  <p>{currentLegacyProof.name} · Parser listener port {currentLegacyProof.port} · Tenant {currentLegacyProof.tenant}</p>
                  <p>Ruby SHA-256: {currentLegacyProof.parserHash.slice(0,16)}… / CONF: {currentLegacyProof.confHash.slice(0,16)}…</p>
                  <small>{currentLegacyProof.testOnlyWriteEligible
                    ? 'Limited synthetic POC eligibility only. Not general deployment approval.'
                    : 'General parser: limited POC write eligibility is unverified.'}</small>
                  <small>Actual API registration, runtime parsing, and Stellar ingestion remain unverified; no automatic deployment.</small>
                </div>}
                <small>This is a read-only preflight. Actual Legacy API writes require a separately approved POC process in the backend.</small>
              </details>
              <div className="guided-package-download" aria-label="Draft ZIP bundle download">
                <div className="guided-section-title"><span>ZIP</span> Two Files + Integrity Manifest</div>
                <p>Only available when explicitly supported by the local backend. The archive contains both generated files and manifest.json; no DP connection, API key, or auto-installation is used.</p>
                <div className="guided-package-controls">
                  <label className="guided-field"><span>ZIP Version Label</span>
                    <input aria-label="Draft ZIP package version" maxLength={64}
                      value={zipVersion} onChange={(event) => {
                        setZipVersion(event.target.value);
                        setZipReceipt(null);
                        setZipError(null);
                      }} placeholder="1.0.0" />
                  </label>
                  <button type="button" className="guided-cta-secondary"
                    disabled={zipDownloading || pending || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(zipVersion)}
                    onClick={() => { void downloadCheckedArtifactZip(); }}>
                    <FileArchive size={15} /> {zipDownloading ? 'Verifying ZIP…' : 'Download DRAFT ZIP Package'}
                  </button>
                </div>
                {currentZipError && <p role="alert" className="guided-error">{currentZipError}</p>}
                {currentZipReceipt && <div className="guided-zip-receipt" aria-label="Draft ZIP integrity receipt">
                  <strong>{currentZipReceipt.filename} · DRAFT ZIP · SHA-256 Verified</strong>
                  <p>Listener port {currentZipReceipt.listenerPort} · Engine execution, target ingestion, and deployment unverified</p>
                  <small>ZIP SHA-256: {currentZipReceipt.sha256}</small>
                  <small>Artifact Revision: {currentZipReceipt.artifactRevisionId}</small>
                </div>}
              </div>
            </div>}
            <Suspense fallback={<p className="guided-note">Loading offline version history…</p>}>
            <ArtifactRevisionHistoryPanel
              projectId={backendProject.ok ? backendProject.project.projectId : qualifiedPair?.manifest.projectId}
              draftKey={draftKey}
              pair={qualifiedPair}
              listenerPort={qualifiedBackend?.project.receiver.port ?? null}
              onDownload={localDownloadBinary}
            />
            </Suspense>
            <details className="guided-pair-inspect">
              <summary><FileArchive size={16} /> Inspect Existing Parser Pair (Advanced, Read-only)</summary>
              <p>Selecting files does not upload them automatically. Only an explicit click sends both files to a same-origin local development API for structure and SHA-256 checks. Raw contents are not stored or displayed.</p>
              <div className="guided-pair-inspect-files">
                <label>Receiver Configuration (.conf)<input type="file" aria-label="Inspect pair CONF" accept=".conf,text/plain" onChange={(event) => { inspectRequestId.current++; setInspectConf(event.target.files?.[0] ?? null); setInspecting(false); setImportReplaceConfirmed(false); setInspectionResult(null); setInspectionError(''); }} /></label>
                <label>Extensionless Ruby Parser Fragment<input type="file" aria-label="Inspect pair Ruby fragment" onChange={(event) => { inspectRequestId.current++; setInspectFragment(event.target.files?.[0] ?? null); setInspecting(false); setImportReplaceConfirmed(false); setInspectionResult(null); setInspectionError(''); }} /></label>
              </div>
              <button type="button" className="guided-cta-secondary" disabled={!inspectConf || !inspectFragment || inspecting} onClick={() => { void inspectChosenPair(); }}>
                <ShieldCheck size={15} /> {inspecting ? 'Inspecting Structure…' : 'Inspect Selected Pair (Read-only)'}
              </button>
              {inspectionError && <p className="guided-error" role="alert">{inspectionError}</p>}
              {inspectionResult && <div className="guided-pair-inspection-result" aria-label="Parser pair inspection results">
                <strong>{inspectionResult.editable ? 'Byte-for-byte Generator Match · Import Requires Lossless Conversion' : 'Unknown Original · OPAQUE READ-ONLY'}</strong>
                <p>Receivers {inspectionResult.sourceCount} · Protocols {inspectionResult.protocols.join(', ') || 'Unknown'} · Ports {inspectionResult.ports.join(', ') || 'Unknown'}</p>
                <p>File SHA-256: CONF {inspectionResult.confSha256.slice(0, 16)}… / Parser {inspectionResult.fragmentSha256.slice(0, 16)}…</p>
                {inspectionResult.diagnostics.length > 0 && <ul>{inspectionResult.diagnostics.map((code) => <li key={code}>{code}</li>)}</ul>}
                <small>Raw Ruby execution, automatic edits, and Parser Studio import are not performed. Stellar target deployment is unverified.</small>
                {!importReview && <p className="guided-error" role="alert">
                  A safe import review is unavailable because structural metadata is incomplete or inconsistent. Original files remain unchanged.
                </p>}
                {importReview && <div className="guided-pair-import-review" aria-label="Parser import compatibility review">
                  <strong>{importReview.classification==='EXACT_BACKEND_PAIR'
                    ? 'Exact Backend Pair · Import Not Performed'
                    : 'Opaque Legacy Source · Manual Migration Required'}</strong>
                  <p>{importReview.advice}</p>
                  <p>File integrity: CONF and Ruby SHA-256 verified · Sources: {importReview.source.receiverCount}
                    {' · '}Known ports: {importReview.source.receiverPorts.join(', ')||'None'}
                    {' · '}Protocols: {importReview.source.receiverProtocols.join(', ')||'None'}</p>
                  {importReview.findings.length>0 && <ul>
                    {importReview.findings.map(item=><li key={item.code}>
                      <code>{item.code}</code> — {item.explanation}
                    </li>)}
                  </ul>}
                  <small>Import status: {importReview.lossAssessment} ·
                    {importReview.guidedImportAvailable
                      ? 'Manual lossless Guided draft reconstruction available'
                      : 'Guided draft import unavailable'} ·
                    Native execution, sensor receipt, and Stellar target loading unverified.</small>
                  <button type="button" className="guided-cta-secondary"
                    onClick={()=>localDownload(
                      'parser-import-review-'+importReview.pairName+'.json',
                      JSON.stringify(importReview,null,2)
                    )}>
                    <FileDown size={15}/> Download Safe Import Review JSON
                  </button>
                  <small>Export contains only verified hashes, receiver metadata and fixed diagnostic codes.
                    It excludes raw parser files, raw sample events, secrets and original error messages.</small>
                  {importableDraft && <div className="guided-exact-pair-import" aria-label="Exact parser pair import controls">
                    <strong>Exact Reproducible Project · Optional Guided Draft Restore</strong>
                    <p>The backend reports byte-identical files and this browser independently reconstructed
                      the same complete supported project. This does not execute Ruby, perform a DP import,
                      prove native compatibility or save a revision automatically.</p>
                    <label className="guided-owner-check">
                      <input type="checkbox" aria-label="Confirm replace current parser draft"
                        checked={importReplaceConfirmed}
                        onChange={event=>setImportReplaceConfirmed(event.target.checked)}/>
                      Replace the current unsaved draft and clear ALL current sample logs. Continue editing
                      in Guided Builder; save only when explicitly requested.
                    </label>
                    <button type="button" className="guided-cta-secondary"
                      disabled={!importReplaceConfirmed || inspecting}
                      onClick={applyExactPairAsDraft}>
                      <FileCheck2 size={15}/> Restore Exact Pair as Unsaved Draft
                    </button>
                  </div>}
                  {importReview.backendByteReproducible && !importableDraft &&
                    <small>The backend proved its own file reproduction, but this project cannot be
                      converted losslessly to the currently supported Guided Builder model.
                      Original files remain read-only and unchanged.</small>}
                </div>}
              </div>}
            </details>
            <details className="guided-replay-preview" aria-label="Local synthetic replay preview">
              <summary>Synthetic Replay Preview · No Sensor Delivery</summary>
              <p>Every current single-line record is validated before replay and repeated in order (up to 500 events / 64 KiB). Only current timestamps, documentation IPs, usernames, and URLs are changed. Unrecognized field values may remain unchanged. No output is sent to or saved on a server.</p>
              <div className="guided-replay-controls">
                <label className="guided-field"><span>Local Preview Rate</span>
                  <select aria-label="Replay preview rate" value={localReplayRate}
                    onChange={(event) => setLocalReplayRate(Number(event.target.value) as 1 | 2 | 5 | 10)}>
                    {[1, 2, 5, 10].map((rate) => <option key={rate} value={rate}>{rate} events/sec</option>)}
                  </select>
                </label>
                {localReplayRunning
                  ? <button className="guided-cta-secondary" type="button" onClick={stopLocalReplay}>Stop Local Replay</button>
                  : <button className="guided-cta-secondary" type="button" onClick={startLocalReplay}>Start Local Replay</button>}
              </div>
              <div className="guided-replay-status" role="status">
                Locally generated {localReplayCount} events · Sensor deliveries <strong>0 events</strong> · {localReplayRunning ? 'Running locally' : 'Stopped'}
                {localReplaySource && <span> · Source {localReplaySource.index}/{localReplaySource.total} (line {localReplaySource.line})</span>}
              </div>
              {localReplayError && <p role="alert" className="guided-error">{localReplayError}</p>}
              {localReplayText && <div className="guided-replay-output">
                <span>Latest Synthetic Log · Changed Fields: {localReplayMutations.join(', ') || 'None'}</span>
                <pre aria-label="Local synthetic replay output">{localReplayText}</pre>
              </div>}
              <small>This is not DP upload or UDP/TCP sensor delivery. The delivery API and actual Stellar ingestion require a separately approved and configured backend.</small>
            </details>
            <details className="guided-backend-synthetic" aria-label="Authorized backend synthetic preview">
              <summary>Backend-authorized Synthetic JSON Preview · No Sensor Delivery</summary>
              <p>This button never transmits the current customer logs or parser draft. Only a fixed public documentation JSON sample is sent to an authorized same-origin Test Lab preview API. No sensor or DP connection is used.</p>
              <button type="button" className="guided-cta-secondary"
                disabled={backendSyntheticPending}
                onClick={() => { void requestBackendSyntheticSample(); }}>
                <ShieldCheck size={15} /> {backendSyntheticPending ? 'Verifying Authorized Synthetic Sample…' : 'Preview Backend Public Synthetic Sample'}
              </button>
              {backendSyntheticError && <p className="guided-error" role="alert">{backendSyntheticError}</p>}
              {backendSyntheticData && <div className="guided-backend-synthetic-result" aria-label="Approved synthetic sample result">
                <strong>Synthetic JSON · Local Backend Authorization Verified</strong>
                <p>Changed Fields: {backendSyntheticData.changedPaths.join(' · ')} · Generated At: {backendSyntheticData.generatedAt}</p>
                <pre aria-label="Backend public synthetic log">{backendSyntheticData.syntheticEvent}</pre>
                <small>All addresses and IDs are synthetic documentation values. Sensor delivery disabled; Fluentd execution and Stellar ingestion unverified.</small>
              </div>}
              <small>No success is claimed after HTTP 403, unsupported capability, or invalid response. This is not a session-start or sensor-delivery control.</small>
            </details>
            <details className="guided-scenario-preview" aria-label="Authorized offline synthetic scenario preview">
              <summary>Multi-event Synthetic Scenario · Offline Preview Only</summary>
              <p>Review two fixed public JSON families (allow / deny), each with a current timestamp, documentation-only IP, synthetic username and URL, and a placeholder run marker. Preview up to four manually selected events. No customer sample, active Test Lab run, network destination, DP credentials, or sensor output is sent.</p>
              <div className="guided-scenario-controls">
                <label className="guided-field"><span>Replay Timing Plan</span>
                  <select aria-label="Offline synthetic scenario mode" value={scenarioMode}
                    onChange={(event)=>{
                      setScenarioMode(event.target.value as SyntheticScenarioMode);
                      setScenarioError('');
                    }}>
                    <option value="constant-rate">Constant Rate · 2 events/sec</option>
                    <option value="original-gaps">Reviewed Example Gaps · 600 ms</option>
                  </select>
                </label>
                <label className="guided-field"><span>Synthetic Event Selection</span>
                  <select aria-label="Offline synthetic scenario sequence" value={scenarioSequence}
                    onChange={(event)=>{
                      setScenarioSequence(Number(event.target.value) as SyntheticScenarioSequence);
                      setScenarioError('');
                    }}>
                    {[0,1,2,3].map(sequence=><option key={sequence} value={sequence}>
                      Event #{sequence+1} · {sequence%2===0?'allow':'deny'}
                    </option>)}
                  </select>
                </label>
                <button type="button" className="guided-cta-secondary"
                  disabled={scenarioPending}
                  onClick={()=>{void previewOfflineSyntheticScenario();}}>
                  <ShieldCheck size={15}/>
                  {scenarioPending?'Checking Authorized Scenario…':'Preview Selected Synthetic Scenario Event'}
                </button>
              </div>
              {scenarioError && <p className="guided-error" role="alert">{scenarioError}</p>}
              {currentScenarioResult && <div className="guided-scenario-result" aria-label="Offline synthetic scenario result">
                <strong>{currentScenarioResult.sampleId} · Event #{currentScenarioResult.preview.sequence+1}
                  {' · '+currentScenarioResult.replayMode}</strong>
                <p>Next event gap: {currentScenarioResult.nextDelayMs} ms
                  {' · '} Families: {currentScenarioResult.sampleFamilyCount}
                  {' · '} Generated: {currentScenarioResult.preview.generatedAt}</p>
                <p>Changed: {currentScenarioResult.preview.changedPaths.join(', ')}</p>
                <pre aria-label="Public synthetic scenario event">{currentScenarioResult.preview.syntheticEvent}</pre>
                <small>Not sent to a sensor. No parser started, and backend flags actual sensor ingress, runtime parsing and target verification as false. Only separately authorized sessions can perform live delivery.</small>
              </div>}
              <small>Authorization is checked server-side for each click. Mode or selection changes never start a loop, transport, session or upload. The original-gaps example uses explicit reviewed 600 ms offsets, not inferred customer log timing.</small>
            </details>
            <details className="guided-owner-testlab" aria-label="Owner approved Test Lab session controls">
              <summary>Owner-approved Test Lab Session · Separate Delivery Authorization Required</summary>
              <p>Unlike local browser preview, this can run only when an operator-configured IP-allowlisted UDP/TCP sink, user authentication, independent approval, and audit controls are present. <b>Current customer logs and DP credentials are never sent; only fixed public synthetic JSON is used.</b></p>
              <button className="guided-cta-secondary" type="button"
                disabled={sessionReadiness==='checking' || sessionBusy}
                onClick={() => { void checkApprovedTestLabSession(); }}>
                <ShieldCheck size={15} /> {sessionReadiness==='checking'
                  ? 'Checking Delivery Requirements…' : 'Check Test Lab Delivery Requirements'}
              </button>
              {!sessionStatus && <div className="guided-owner-session-recovery">
                <label className="guided-field"><span>Recover Own Session by Run ID (No New Start)</span>
                  <input aria-label="Existing Test Lab run ID" autoComplete="off"
                    value={sessionRecoveryRunId} maxLength={41}
                    placeholder="test_run_0123456789abcdef0123456789abcdef"
                    onChange={(event)=>setSessionRecoveryRunId(event.target.value)} />
                </label>
                <button type="button" className="guided-cta-secondary"
                  disabled={sessionBusy || !/^test_run_[0-9a-f]{32}$/.test(sessionRecoveryRunId)}
                  onClick={()=>{void recoverApprovedTestLabStatus();}}>
                  <ShieldCheck size={15} /> Look Up Test Lab Session by Run ID
                </button>
                <small>Run IDs do not replace authentication. Only authorized owners can inspect or stop their runs. Unsupported backends deny this request.</small>
              </div>}
              {sessionReadiness==='available' && !sessionStatus && <div className="guided-owner-testlab-confirm">
                <p>The backend reports a delivery capability, but each run still requires independent operator authorization. <strong>Maximum: 60 seconds or 100 synthetic events.</strong> No automatic renewal.</p>
                <label className="guided-field"><span>Test Delivery Approval ID (Not an API Key)</span>
                  <input aria-label="Test Lab approval identifier" autoComplete="off" maxLength={96}
                    value={sessionApproval} placeholder="owner-approved-synthetic"
                    onChange={(event) => setSessionApproval(event.target.value)} />
                </label>
                <label className="guided-field"><span>Requested Maximum Generation Rate</span>
                  <select aria-label="Approved Test Lab rate" value={sessionRate}
                    onChange={(event) => setSessionRate(Number(event.target.value) as 1|2|5)}>
                    {[1,2,5].map(rate=><option key={rate} value={rate}>{rate} events/sec</option>)}
                  </select>
                </label>
                <label className="guided-owner-check">
                  <input type="checkbox" aria-label="I confirm approved sensor test" checked={sessionAcknowledged}
                    onChange={(event) => setSessionAcknowledged(event.target.checked)} />
                  I confirm independent operator and destination approval for a server session lasting no more than 60 seconds.
                </label>
                <button type="button" className="guided-cta-secondary"
                  disabled={sessionBusy || !sessionAcknowledged ||
                    !/^[A-Za-z0-9_.-]{8,96}$/.test(sessionApproval)}
                  onClick={()=>{void startApprovedTestLab();}}>
                  <Play size={15} /> Start Approved Test Lab (Max 60s / 100 Events)
                </button>
              </div>}
              {sessionStatus && <div className="guided-owner-session-status" aria-label="Test Lab session status">
                <strong>Server Session {sessionStatus.state} · Trusted Sink Delivery Calls {sessionStatus.sentCount}/{sessionStatus.maxEvents}</strong>
                <p>Run ID <code>{sessionStatus.runId}</code> · Lease Expires {sessionStatus.leaseExpiresAt}</p>
                <p>Replay: {sessionStatus.replayMode} · Synthetic Families {sessionStatus.sampleFamilyCount} · Requested Rate {sessionStatus.ratePerSecond}/s</p>
                <small>This counts backend delivery callbacks, not proof of sensor receipt, Fluentd normalization, or Stellar ingestion.</small>
                <div className="guided-owner-session-buttons">
                  <button type="button" className="guided-cta-secondary" disabled={sessionBusy}
                    onClick={()=>{void actOnApprovedTestLab('refresh');}}>Refresh Status</button>
                  {sessionStatus.state==='RUNNING' && <button type="button" className="guided-cta-secondary"
                    disabled={sessionBusy} onClick={()=>{void actOnApprovedTestLab('pause');}}>Pause Session</button>}
                  {sessionStatus.state==='PAUSED' && <button type="button" className="guided-cta-secondary"
                    disabled={sessionBusy} onClick={()=>{void actOnApprovedTestLab('resume');}}>Resume Session</button>}
                  {['RUNNING','PAUSED'].includes(sessionStatus.state) && <button type="button"
                    className="guided-cta-secondary" disabled={sessionBusy}
                    onClick={()=>{void actOnApprovedTestLab('stop');}}>Stop Server Session</button>}
                </div>
                {['RUNNING','PAUSED'].includes(sessionStatus.state) &&
                    sessionStatus.replayMode!=='original-gaps' && <details
                    className="guided-owner-rate" aria-label="Approved Test Lab rate adjustment">
                  <summary>Adjust Synthetic Session Rate · New Approval Required</summary>
                  <p>Change only the delivery cadence of this already-owned Test Lab run.
                    This never extends the server lease, raises the event quota, starts a
                    new run, or verifies any sensor or DP result. The backend must independently
                    approve this exact request; no rate changes automatically.</p>
                  <label className="guided-field"><span>Requested New Rate (0.2–5 synthetic events/sec)</span>
                    <select aria-label="New approved Test Lab rate"
                      value={sessionNewRate}
                      onChange={(event)=>{
                        setSessionNewRate(Number(event.target.value) as 0.2|1|2|5);
                        setSessionRateConfirmed(false);
                      }}>
                      {([0.2,1,2,5] as const).map(rate=><option key={rate} value={rate}>
                        {rate} events/sec
                      </option>)}
                    </select>
                  </label>
                  <label className="guided-field"><span>Separate Operator Approval ID (not an API key)</span>
                    <input type="password" autoComplete="off" maxLength={96}
                      aria-label="New Test Lab rate approval"
                      value={sessionRateApproval} onChange={(event)=>{
                        setSessionRateApproval(event.target.value);
                        setSessionRateConfirmed(false);
                      }} />
                  </label>
                  <label className="guided-owner-check">
                    <input type="checkbox" aria-label="Confirm separately approved Test Lab rate"
                      checked={sessionRateConfirmed}
                      onChange={(event)=>setSessionRateConfirmed(event.target.checked)}/>
                    I have independent operator approval for this specific rate on the current run.
                    The server will revalidate ownership, destination policy and active lease.
                  </label>
                  <button type="button" className="guided-cta-secondary"
                    disabled={sessionBusy||!sessionRateConfirmed||
                      !/^[A-Za-z0-9._-]{8,96}$/.test(sessionRateApproval)||
                      sessionNewRate===sessionStatus.ratePerSecond}
                    onClick={()=>{void actOnApprovedTestLab('rate');}}>
                    Apply Separately Approved Rate
                  </button>
                  <small>A denied or unconfigured backend cannot change the displayed
                    rate. The current rate always comes from verified session metadata.</small>
                </details>}
                {['RUNNING','PAUSED'].includes(sessionStatus.state) && <div className="guided-owner-renew">
                  <label className="guided-field"><span>New Approval ID for Renewal (Do Not Reuse Previous Approval)</span>
                    <input aria-label="New Test Lab renewal approval" autoComplete="off" maxLength={96}
                      value={sessionRenewApproval} onChange={(event)=>setSessionRenewApproval(event.target.value)} />
                  </label>
                  <button type="button" className="guided-cta-secondary"
                    disabled={sessionBusy || !/^[A-Za-z0-9_.-]{8,96}$/.test(sessionRenewApproval)}
                    onClick={()=>{void actOnApprovedTestLab('renew');}}>
                    Request Additional 60s / 20 Events
                  </button>
                  <small>Renewal requires independent operator reapproval and never runs automatically.</small>
                </div>}
                {['STOPPED','COMPLETED','EXPIRED','FAILED'].includes(sessionStatus.state) &&
                  <div>
                    <p>The session has ended. A new run requires fresh operator approval and capability checks.</p>
                    <button type="button" className="guided-cta-secondary" onClick={()=>{
                      setSessionStatus(null);setSessionReadiness('unchecked');
                      setSessionApproval('');setSessionRenewApproval('');setSessionAcknowledged(false);
                      setSessionRateApproval('');setSessionRateConfirmed(false);
                      setSessionError('');
                    }}>Prepare New Approved Session</button>
                  </div>}
              </div>}
              {sessionStatus && <Suspense fallback={<p className="guided-note">Loading offline Test Lab evidence…</p>}>
                <TestLabEvidencePanel runId={sessionStatus.runId}
                  onDownload={localDownload}/>
              </Suspense>}
              {sessionStatus && <details className="guided-interflow-readback" aria-label="Audited Interflow field comparison">
                <summary>Compare Parsed Fields in Interflow · Separate Read Approval</summary>
                <p>This is a single bounded, read-only lookup, not a parser deployment or live sensor validation. Your backend must independently verify the run owner, tenant data-read permission and audit sink. Only a run marker, one expected scalar field and a bounded time range are sent; raw events, tenant credentials and DP API keys are never sent from this page.</p>
                <div className="guided-interflow-form">
                  <label className="guided-field"><span>Interflow Index</span>
                    <select aria-label="Interflow index" value={interflowIndex}
                      onChange={(event)=>setInterflowIndex(event.target.value as InterflowIndex)}>
                      {(['session','threat','syslog','winlogevent'] as const).map(index=>
                        <option key={index} value={index}>{index}</option>)}
                    </select>
                  </label>
                  <label className="guided-field"><span>Run Marker Field</span>
                    <input aria-label="Interflow run marker field" autoComplete="off"
                      maxLength={96} value={interflowMarker}
                      onChange={(event)=>setInterflowMarker(event.target.value)}/>
                  </label>
                  <label className="guided-field"><span>Expected Normalized Field</span>
                    <input aria-label="Interflow expected field" autoComplete="off"
                      maxLength={96} value={interflowField}
                      onChange={(event)=>setInterflowField(event.target.value)}/>
                  </label>
                  <label className="guided-field"><span>Expected Text Value (exact comparison)</span>
                    <input aria-label="Interflow expected value" autoComplete="off"
                      maxLength={128} value={interflowExpectedValue}
                      onChange={(event)=>setInterflowExpectedValue(event.target.value)}/>
                  </label>
                  <label className="guided-field"><span>Recent Search Window</span>
                    <select aria-label="Interflow lookback minutes" value={interflowWindow}
                      onChange={(event)=>setInterflowWindow(Number(event.target.value) as 1|5|10)}>
                      {[1,5,10].map(minutes=><option key={minutes} value={minutes}>Last {minutes} minute{minutes===1?'':'s'}</option>)}
                    </select>
                  </label>
                  <label className="guided-owner-check">
                    <input type="checkbox" aria-label="I confirm independent tenant read approval"
                      checked={interflowAcknowledged}
                      onChange={(event)=>setInterflowAcknowledged(event.target.checked)}/>
                    I have an independent authorization to read this tenant's Interflow data. I will not enter secrets or personal data as expected values.
                  </label>
                  <button type="button" className="guided-cta-secondary"
                    disabled={interflowPending || !interflowAcknowledged}
                    onClick={()=>{void readApprovedInterflow();}}>
                    <ShieldCheck size={15}/> {interflowPending ? 'Comparing Fields…' : 'Compare Fields (Read-only, Max 20 Events)'}
                  </button>
                </div>
                {interflowError && <p className="guided-error" role="alert">{interflowError}</p>}
                {currentInterflowResult && <div className="guided-interflow-result" aria-label="Interflow field comparison result">
                  <strong>{currentInterflowResult.state==='MATCHED_RESPONSE_FIELDS'
                    ? 'Requested Fields Matched · E2E Unverified'
                    : currentInterflowResult.state==='FIELD_MISMATCH'
                    ? 'Field Difference Found · E2E Unverified'
                    : 'No Matching Event · E2E Unverified'}</strong>
                  <p>Run {sessionStatus.runId} · Matching events {currentInterflowResult.matchCount}</p>
                  <ul>{currentInterflowResult.fields.map(field=>
                    <li key={field.field}>{field.field}: <strong>{field.status}</strong></li>)}</ul>
                  <small>These are comparisons returned by the audited backend. No raw vendor records are displayed. The backend explicitly reports sensor receipt, runtime parsing, target import and end-to-end verification as false—even when a requested scalar field matches.</small>
                </div>}
                <small>Manual request only · Maximum 20 results · Last 1–10 minutes · No automatic polling or session start. HTTP 403/404 is a permission/session denial, not a successful empty result.</small>
              </details>}
              {sessionError && <p role="alert" className="guided-error">{sessionError}</p>}
              {sessionReadiness==='blocked' && <small>The development backend disables delivery by default. No Start, UDP/TCP sends, or Interflow validation can occur without authorization.</small>}
              <small>This UI does not configure authentication, network allowlists, or delivery auditing. Closing the browser does not guarantee Stop; stop the session explicitly. An unattended run is bounded to 60 seconds / 100 events and cannot renew without a new approval.</small>
            </details>
            <div className="guided-hint"><HelpCircle size={16} /> Project JSON excludes raw logs. Ruby and CONF outputs are DRAFT and must not be represented as validated native parser or portal-upload artifacts.</div>
          </>}
        </div>

        {sessionStatus && ['RUNNING','PAUSED'].includes(sessionStatus.state) && step!==5 &&
          <div className="guided-session-still-active" aria-label="Active Test Lab session indicator">
            <ShieldAlert size={16} />
            <span>Approved Test Lab session {sessionStatus.state} · Progress {sessionStatus.sentCount}/{sessionStatus.maxEvents}. Changing screens does not stop server delivery.</span>
            <button type="button" disabled={sessionBusy} onClick={() => {void actOnApprovedTestLab('stop');}}>
              Stop Server Session Now
            </button>
          </div>}
        {message && <div className="guided-message" role="status"><HelpCircle size={15} /> {message}<button type="button" onClick={() => setMessage('')}>Close</button></div>}
        <div className="guided-bottom-bar">
          <button type="button" className="guided-cta-secondary" onClick={prevStep} disabled={step === 0}><ArrowLeft size={15} /> Previous</button>
          <div>{STEPS[step].label} <strong>{step + 1} / 6</strong></div>
          {step < 5 ? <button type="button" className="guided-cta-main" onClick={nextStep}>Next Step <ArrowRight size={16} /></button>
            : <button type="button" className="guided-cta-secondary" onClick={() => setStep(0)}><RotateCcw size={15} /> Review Again</button>}
        </div>
      </section>
      <aside className="guided-inspector" aria-label="Current preview and compatibility">
        <div className="guided-inspector-heading"><span>LIVE OVERVIEW</span><span className="guided-live-dot" /> Local Preview</div>
        <div className="guided-inspector-metrics">
          <div><strong>{suite?.counts.total ?? '—'}</strong><span>Input</span></div>
          <div><strong>{suite?.counts.matched ?? '—'}</strong><span>Match</span></div>
          <div><strong>{suite?.counts.normalized ?? '—'}</strong><span>Normalized</span></div>
          <div><strong>{hardFails}</strong><span>Failures</span></div>
        </div>
        <div className="guided-inspector-divider" />
        <h3>Processing Preview</h3>
        <p>{activeEvent ? 'Selected Event #' + activeEvent.line : 'No event selected'}</p>
        <pre className="guided-inspector-json">{activeEvent ? JSON.stringify(activeEvent.normalized, null, 2) : 'No preview'}</pre>
        <div className="guided-inspector-divider" />
        <div className="guided-validation-header"><span>Validation Status by Feature</span><HelpCircle size={15} /></div>
        <div className="guided-checks"><div><CheckCircle2 size={15} /><span>Browser Preview</span><strong>{pending ? 'Running' : suite ? 'Completed' : 'Not Run'}</strong></div>
          <div><AlertTriangle size={15} /><span>Ruby/Fluentd Test</span><strong>Unverified</strong></div>
          <div><AlertTriangle size={15} /><span>Stellar Ingestion</span><strong>Unverified</strong></div>
          <div><LockKeyhole size={15} /><span>Automatic Deployment</span><strong>Disabled</strong></div>
        </div>
        <div className="guided-inspector-bottom"><ShieldCheck size={16} /> The model is version-independent. Support is determined only after verifying the actual output adapter.</div>
      </aside>
    </div>
  </main>;
}
