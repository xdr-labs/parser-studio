import { useMemo, useState } from 'react';
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
import { createFieldProposal } from '../pattern';
import { suggestClassification } from './classify';
import { toBackendProject, type BackendParserProject } from './backendAdapter';
import { fetchBackendCapabilities, assertBackendProjectSupported } from './backendCapabilities';
import { inspectParserPair, type PairInspectionSummary } from './pairInspection';
import { backendIssueTarget } from './backendIssueGuide';
import { starterTemplateIds, starterTemplateInfo, loadStarterTemplate, type StarterTemplateId } from './sampleTemplates';
import { validateBackendProject, generateBackendPair, type BackendValidationResult, type GeneratedPair } from './backendClient';
import { highlightPreview, matchContext } from './fieldHighlights';
import {
  CLASSIFICATIONS, FIELD_GROUPS, compilerDraftContract, defaultGuidedOptions,
  plannedPairNames, type EventClass, type FieldGroup, type GuidedOptions, type GuidedEnrichmentRule, type Transport,
} from './contract';

export interface GuidedBuilderProps {
  draft: ParserDraft;
  setDraft: Dispatch<SetStateAction<ParserDraft>>;
  sample: string;
  setSample: (value: string) => void;
  datasetName: string;
  setDatasetName: (value: string) => void;
  suite?: SuiteResult;
  pending: boolean;
  runPreview: (draft: ParserDraft) => Promise<SuiteResult>;
  runState?: { suite: SuiteResult; timestamp: string } | null;
  onRunSuite: () => void;
  onExpert: () => void;
  onSave: () => void;
}

const STEPS = [
  { label: '로그 가져오기', sub: '샘플 입력', icon: FileUp },
  { label: '필드 추출', sub: '필드 만들기', icon: WandSparkles },
  { label: '필드 매핑', sub: '타입·정규화', icon: Layers3 },
  { label: '수신·분류', sub: '프로토콜·이벤트', icon: Settings2 },
  { label: '검사·수정', sub: '전체 샘플 테스트', icon: FlaskConical },
  { label: '파일 생성', sub: '결과·다운로드', icon: FileDown },
] as const;

const TYPES: FieldType[] = ['string', 'ip', 'port', 'integer', 'boolean', 'timestamp', 'number'];
const GROUP_LABELS: Record<FieldGroup, string> = {
  top_fields: '공통 속성',
  ns_fields: '네트워크 속성',
  vendor_fields: '벤더 고유 속성',
};
const TYPE_LABELS: Record<FieldType, string> = {
  string: '텍스트', integer: '정수', number: '실수 (미지원)', boolean: '참/거짓',
  ip: 'IP 주소', port: '포트', timestamp: '시간 (ISO/UTC)',
};
const CLASS_LABELS: Record<EventClass, string> = {
  Session: 'Session / 세션', Threat: 'Threat / 위협',
  Syslog: 'Syslog / 일반 로그', Winlogevent: 'Winlogevent / Windows',
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

export default function GuidedBuilder(props: GuidedBuilderProps) {
  const {
    draft, setDraft, sample, setSample, datasetName, setDatasetName,
    suite, pending, runPreview, runState, onRunSuite, onExpert, onSave,
  } = props;
  const [step, setStep] = useState(0);
  const [selectedId, setSelectedId] = useState('event-1');
  const [selectedValue, setSelectedValue] = useState('');
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
  const [starterChoice, setStarterChoice] = useState<StarterTemplateId | ''>('');


  const options: GuidedOptions = draft.guided ?? defaultGuidedOptions();
  const activeEvent = suite?.events.find((event) => event.id === selectedId) ?? suite?.events[0];
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
  const artifactContract = compilerDraftContract(draft);
  const backendProject = toBackendProject(draft);
  // Bind validation, generated files and suite evidence to the exact draft AND fixture set.
  const draftKey = JSON.stringify([draft, sample]);
  const qualifiedBackend = backendAttempt?.key === draftKey ? backendAttempt : null;
  const qualifiedPair = generatedPair?.key === draftKey ? generatedPair.pair : null;
  const currentBackendError = backendError?.key === draftKey ? backendError.message : '';
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

  const applyStarter = () => {
    if (!starterChoice) return;
    const template = loadStarterTemplate(starterChoice);
    setDraft(template.draft);
    setSample(template.sample);
    setDatasetName('합성 예제 · ' + template.label);
    setSelectedValue('');
    setSelectedId('event-1');
    setProposalResult(null);
    setBackendAttempt(null);
    setGeneratedPair(null);
    setBackendError(null);
    setStarterChoice('');
    notify('선택한 합성 로그·규칙으로 새 초안을 적용했습니다. 실제 고객 로그가 아니며, 브라우저 테스트가 다시 필요합니다.');
  };

  const readSampleFile = async (event: ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    event.target.value = '';
    if (!file) return;
    if (file.size > MAX_DATASET_BYTES) { notify('파일 용량이 64 KiB를 초과했습니다. 더 작은 샘플을 사용하세요.'); return; }
    try {
      const content = new TextDecoder('utf-8', { fatal: true }).decode(await file.arrayBuffer());
      setSample(content);
      setDatasetName(file.name);
      setSelectedValue('');
      setSelectedId('event-1');
      notify('샘플을 불러왔습니다. 로그는 브라우저 세션에만 유지됩니다.');
    } catch {
      notify('UTF-8 텍스트 파일만 업로드할 수 있습니다.');
    }
  };

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
      notify(error instanceof Error ? error.message : '필드 검사를 실행할 수 없습니다.');
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
    notify('필드 규칙을 초안에 추가했습니다. 복합 형식에는 별도 분기 규칙이 필요할 수 있습니다.');
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
      setBackendError({ key: draftKey, message: '필드 매핑과 분류 설정 오류를 먼저 해결하세요.' });
      return;
    }
    setValidatingBackend(true);
    try {
      const capabilities = await fetchBackendCapabilities();
      assertBackendProjectSupported(backendProject.project, capabilities);
      const result = await validateBackendProject(backendProject.project);
      setBackendAttempt({ key: draftKey, project: backendProject.project, result });
      if (result.ok) notify('백엔드 입력 스키마 검사를 통과했습니다. 네이티브 실행 검증은 별도로 필요합니다.');
    } catch (error) {
      setBackendError({ key: draftKey, message: error instanceof Error ? error.message : '백엔드에 연결할 수 없습니다.' });
    } finally {
      setValidatingBackend(false);
    }
  };

  const inspectChosenPair = async () => {
    setInspectionResult(null);
    setInspectionError('');
    if (!inspectConf || !inspectFragment) return;
    const name = inspectFragment.name;
    if (!/^customized_[a-z][a-z0-9_]{1,47}$/.test(name) || inspectConf.name !== name + '.conf') {
      setInspectionError('동일한 customized_<slug> 이름의 CONF와 확장자 없는 파서 파일을 선택하세요.');
      return;
    }
    if (inspectConf.size + inspectFragment.size > 2 * 1024 * 1024) {
      setInspectionError('입력 파일의 합계가 2 MiB를 초과합니다.');
      return;
    }
    setInspecting(true);
    try {
      const capabilities = await fetchBackendCapabilities();
      if (!capabilities.import.structuralInspectionOnly) throw new Error('이 백엔드는 읽기 전용 구조 검사 기능을 제공하지 않습니다.');
      const decoder = new TextDecoder('utf-8', { fatal: true });
      const [confBytes, fragmentBytes] = await Promise.all([inspectConf.arrayBuffer(), inspectFragment.arrayBuffer()]);
      const result = await inspectParserPair({
        name, confContent: decoder.decode(confBytes), fragmentContent: decoder.decode(fragmentBytes),
      });
      setInspectionResult(result);
    } catch (error) {
      setInspectionError(error instanceof Error ? error.message : '파일 검사에 실패했습니다.');
    } finally {
      setInspecting(false);
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
      notify('두 파일을 받았습니다. SHA-256 검사 PASS, 실행·적재 호환성은 검증되지 않은 DRAFT입니다.');
    } catch (error) {
      setBackendError({ key: draftKey, message: error instanceof Error ? error.message : '파일 생성에 실패했습니다.' });
    } finally {
      setGeneratingPair(false);
    }
  };

  const stageStatus = (number: number): 'complete' | 'attention' | 'future' => {
    if (number === 0) return hasLogs ? 'complete' : 'attention';
    if (number === 1) return hasLogs && draft.format !== 'auto' ? 'complete' : hasLogs ? 'attention' : 'future';
    if (number === 2) return draft.mappings.length > 0 ? 'complete' : 'attention';
    if (number === 3) return options.receiver.protocols.length && Number.isInteger(options.receiver.port) && options.receiver.port >= 1024 && options.receiver.port <= 65535 ? 'complete' : 'attention';
    if (number === 4) return runState?.suite.counts.total && runState.suite.counts.failures === 0 ? 'complete' : 'attention';
    return 'future';
  };

  const nextStep = () => setStep(Math.min(5, step + 1));
  const prevStep = () => setStep(Math.max(0, step - 1));

  return <main className="guided-shell" aria-label="No-code Parser Guided Builder">
    <div className="guided-intro">
      <div><div className="guided-breadcrumb">PARSER STUDIO / 시작하기 / <strong>가이드 생성기</strong></div>
        <h1>파서를 직접 만들어 보세요 <span className="guided-crown">NO-CODE BUILDER</span></h1>
        <p>Ruby나 정규식을 몰라도 됩니다. 로그를 추가하고, 필요한 필드를 선택하고, 안전하게 검증하세요.</p>
      </div>
      <div className="guided-intro-actions">
        <button type="button" className="guided-expert" onClick={onExpert}><Code2 size={15} /> 전문가 화면 열기</button>
        <button type="button" className="guided-save" onClick={onSave}><FileCheck2 size={15} /> 초안 저장</button>
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
        <div className="guided-side-note"><LockKeyhole size={17} /><strong>로컬에서 안전하게</strong><p>원본 샘플은 브라우저를 벗어나지 않습니다. 자동 배포나 외부 AI 전송은 없습니다.</p></div>
      </aside>

      <section className="guided-workspace" aria-live="polite">
        <div className="guided-content-head">
          <div className="guided-content-eyebrow">STEP {String(step + 1).padStart(2, '0')} <span>/ 06</span></div>
          <h2>{[
            '어떤 로그를 처리할까요?', '로그에서 어떤 값을 추출할까요?',
            '추출한 정보를 어떻게 해석할까요?', '로그는 어디에서 들어오고 어떻게 분류되나요?',
            '모든 샘플이 제대로 처리되나요?', '어떤 파일을 생성하게 되나요?',
          ][step]}</h2>
          <p>{[
            '장비 로그를 붙여 넣거나 텍스트 파일을 선택하세요. 여러 유형의 이벤트를 포함하면 더 정확하게 검증할 수 있습니다.',
            '원본 로그에서 필요한 값을 드래그해 선택하세요. 구조 기반 필드 추출 규칙을 제안합니다.',
            '추출된 속성을 정규화 필드에 연결하고 저장할 데이터 타입을 고르세요.',
            'UDP/TCP 수신 방법과 이벤트 유형 분류를 설정하세요. 실제 장비 설정은 변경되지 않습니다.',
            '전체 샘플로 로컬 미리보기를 실행합니다. 실패한 로그와 원인을 확인하세요.',
            '2개 파일의 이름과 설정 계약을 확인하세요. 생성 엔진·실행 검증이 연결되기 전에는 배포용 파일을 제공하지 않습니다.',
          ][step]}</p>
        </div>

        <div className="guided-content-body">
          {step === 0 && <>
            <div className="guided-section-title"><span>01</span> 파서 기본 정보 <span className="guided-required">필수</span></div>
            <div className="guided-two-fields">
              <label className="guided-field"><span>파서 이름</span><input aria-label="Guided parser name" value={draft.name} maxLength={90} onChange={(e) => changeDraft('name', e.target.value)} placeholder="예: Firewall Log Parser" /></label>
              <label className="guided-field"><span>장비 제조사</span><input aria-label="Guided vendor" value={draft.vendor} maxLength={80} onChange={(e) => changeDraft('vendor', e.target.value)} placeholder="예: Firewall Vendor" /></label>
            </div>
            <label className="guided-field"><span>파서 ID <small>(출력 파일 이름으로 사용)</small></span><input aria-label="Parser ID" value={options.slug} onChange={(e) => setGuided({ ...options, slug: e.target.value.toLowerCase() })} /><small>영문 소문자, 숫자, 밑줄만 허용합니다. 첫 글자는 영문자로 시작해야 합니다.</small></label>
            <label className="guided-field"><span>로그 소스 유형</span><select aria-label="Source category" value={options.sourceCategory ?? 'network'} onChange={(e) => setGuided({ ...options, sourceCategory: e.target.value as NonNullable<GuidedOptions['sourceCategory']> })}>
              <option value="network">네트워크 장비</option><option value="endpoint">엔드포인트</option><option value="cloud">클라우드</option><option value="application">애플리케이션</option><option value="other">기타</option>
            </select></label>
            <div className="guided-section-title"><span>02</span> 합성 예제로 시작 <span className="guided-inline-badge">선택 사항</span></div>
            <div className="guided-starter-choice">
              <label className="guided-field"><span>파서 형식 예제</span>
                <select aria-label="Synthetic starter template" value={starterChoice} onChange={(event) => setStarterChoice(event.target.value as StarterTemplateId | '')}>
                  <option value="">원하는 형식을 선택하세요</option>
                  {starterTemplateIds.map((id) => <option value={id} key={id}>{starterTemplateInfo(id).label}</option>)}
                </select>
              </label>
              <button className="guided-cta-secondary" type="button" disabled={!starterChoice} onClick={applyStarter}>
                <WandSparkles size={15} /> 합성 예제 적용
              </button>
            </div>
            <div className="guided-hint"><AlertTriangle size={16} /> 예제 적용 버튼을 누르면 현재 초안 규칙과 샘플을 새 합성 예제로 대체합니다. 선택만으로는 변경하거나 서버에 전송하지 않습니다. 예제는 장비·엔진 호환성의 검증 근거가 아닙니다.</div>
            <div className="guided-section-title"><span>03</span> 샘플 로그 추가</div>
            <div className="guided-upload"><FileUp size={21} /><span>로그 텍스트를 직접 입력하거나 파일을 불러오세요.</span><label htmlFor="guided-upload-file" className="guided-upload-button">파일 선택</label><input type="file" id="guided-upload-file" onChange={readSampleFile} accept=".txt,.log,.json,.csv,text/plain" hidden /><small>UTF-8 · 최대 64 KiB · 외부 서버로 전송 안 함</small></div>
            <label className="guided-field"><span>원본 로그 <small>{datasetName}</small></span><textarea aria-label="Guided raw sample logs" spellCheck={false} className="guided-raw-input" value={sample} onChange={(e) => { setSample(e.target.value); setDatasetName('입력한 샘플 · 임시'); }} placeholder="장비의 원본 로그를 여러 줄 붙여 넣으세요" /></label>
            <div className="guided-section-title"><span>04</span> 이벤트 경계 설정</div>
            <div className="guided-boundary-options" role="group" aria-label="Event boundary selector">
              <button type="button" aria-pressed={(options.eventBoundary ?? 'single-line') === 'single-line'} className={(options.eventBoundary ?? 'single-line') === 'single-line' ? 'selected' : ''} onClick={() => setGuided({ ...options, eventBoundary: 'single-line' })}>
                <FileText size={18} /><span><strong>한 줄 = 한 이벤트</strong><small>일반적인 Syslog / JSON Lines / KV 로그</small></span>
              </button>
              <button type="button" aria-pressed={options.eventBoundary === 'blank-line'} className={options.eventBoundary === 'blank-line' ? 'selected' : ''} onClick={() => setGuided({ ...options, eventBoundary: 'blank-line' })}>
                <Layers3 size={18} /><span><strong>빈 줄로 이벤트 구분</strong><small>여러 줄 JSON 등 줄바꿈이 포함된 레코드</small></span>
              </button>
            </div>
            <div className="guided-boundary-count" role="status">
              <span>내용이 있는 물리 줄 <strong>{sample.replace(/\r\n?/g, '\n').split('\n').filter((line) => line.trim()).length}</strong></span>
              <span>논리 이벤트 <strong>{pending ? '계산 중…' : (suite?.counts.total ?? 0)}</strong></span>
            </div>
            {options.eventBoundary === 'blank-line' && <div className="guided-hint"><AlertTriangle size={16} /> 빈 줄 구분은 브라우저 샘플 미리보기 전용입니다. 생성 엔진의 다중 줄 이벤트 지원이 검증되기 전에는 파서 파일 생성을 허용하지 않습니다.</div>}
            <div className="guided-inline-actions"><button className="guided-link" type="button" onClick={() => { setSample(DEMO_SAMPLES); setDatasetName('Synthetic demo events'); }}><RotateCcw size={14} /> 데모 로그 복원</button><button type="button" className="guided-link" onClick={() => { setSample(''); setDatasetName('비어 있음'); }}><Trash2 size={14} /> 샘플 비우기</button></div>
            <div className="guided-note"><ShieldCheck size={16} /> {hasLogs ? `현재 ${suite?.counts.total}개 이벤트를 찾았습니다. 다음 단계에서 형식을 확인하세요.` : '아직 입력된 이벤트가 없습니다. 실제 또는 합성 샘플을 추가하세요.'}</div>
          </>}

          {step === 1 && <>
            <div className="guided-section-title"><span>01</span> 로그 형식 선택 <span className="guided-inline-badge">정확한 형식 선택이 중요합니다</span></div>
            <div className="guided-format-choices" role="group" aria-label="Guided format">
              {(['auto', 'json', 'kv', 'csv', 'syslog_rfc5424', 'cef', 'leef', 'syslog', 'regex'] as const).map((format) =>
                <button type="button" key={format} aria-pressed={draft.format === format} className={'guided-format ' + (draft.format === format ? 'active' : '')} onClick={() => changeDraft('format', format)}>
                  {draft.format === format ? <CheckCircle2 size={17} /> : <FileText size={17} />}
                  <strong>{formatLabel(format)}</strong>
                </button>)}
            </div>
            {draft.format === 'csv' && <label className="guided-field"><span>CSV 열 이름 <small>(쉼표 구분 · 1~100개)</small></span><input aria-label="Guided CSV columns" value={draft.csvColumns} onChange={(event) => changeDraft('csvColumns', event.target.value)} placeholder="action,src_ip,dst_port" /><small>열 순서대로 적용됩니다. 쉼표 CSV 1행당 1이벤트만 DRAFT 생성 대상입니다.</small></label>}
            <div className="guided-hint"><AlertCircle size={16} /> 브라우저 추출은 미리보기입니다. JSON, KV, CSV, 정확한 RFC5424, 단독 CEF/LEEF만 기능 계약 확인 후 DRAFT 생성할 수 있습니다. 일반 Syslog·Regex 및 복합/멀티라인은 미지원입니다.</div>
            <div className="guided-section-title"><span>02</span> 샘플에서 값 선택하기</div>
            <div className="guided-event-picker">
              <div className="guided-event-buttons" aria-label="Guided event list">
                {(suite?.events ?? []).slice(0, 100).map((event) =>
                  <button type="button" key={event.id} onClick={() => { setSelectedId(event.id); setSelectedValue(''); }} className={'guided-event-option ' + (activeEvent?.id === event.id ? 'active' : '')}>
                    <span className={'guided-status-dot ' + event.status} />
                    <strong>#{event.line}</strong><span>{formatLabel(event.detected.format)}</span>
                  </button>)}
              </div>
              <div className="guided-event-raw">
                <div className="guided-raw-label">원본 이벤트 · 값을 드래그해 선택</div>
                {activeEvent ? <pre aria-label="Guided selectable raw event" tabIndex={0} onMouseUp={() => captureValue(window.getSelection()?.toString() ?? '')}>{selectedValue && activeEvent.raw.includes(selectedValue) ? <>
                  {activeEvent.raw.slice(0, activeEvent.raw.indexOf(selectedValue))}
                  <mark className="guided-selected-token">{selectedValue}</mark>
                  {activeEvent.raw.slice(activeEvent.raw.indexOf(selectedValue) + selectedValue.length)}
                </> : activeEvent.raw}</pre> : <div className="guided-no-events">먼저 로그를 입력해 주세요.</div>}
                <div className="guided-extracted-tags">확인된 필드: {Object.keys(activeEvent?.fields ?? {}).length ? Object.keys(activeEvent!.fields).map((field) => <button type="button" title="필드 매핑 단계에서 편집" key={field} onClick={() => { setStep(2); }}><Plus size={12} /> {field}</button>) : '아직 없습니다'}</div>
              </div>
            </div>
            {selectedValue && <div className="guided-proposal">
              <div className="guided-section-title"><WandSparkles size={17} /> 선택한 값으로 필드 생성</div>
              <div className="guided-sample-value">{selectedValue}</div>
              <label className="guided-field"><span>생성할 필드 이름</span><input aria-label="Guided proposed field name" value={fieldName} onChange={(e) => { setFieldName(e.target.value); setProposalResult(null); }} /></label>
              {proposal && 'error' in proposal ? <p className="guided-error" role="alert">{proposal.error}</p> : proposal ? <>
                <p className="guided-tip">로그 구조에서 식별자를 찾았습니다. 아직 모든 샘플에서 일치하는지 확인되지 않았습니다.</p>
                <details className="guided-advanced"><summary>고급 사용자: 추출 규칙 보기</summary><pre>{proposal.pattern}</pre></details>
                <div className="guided-inline-actions"><button className="guided-cta-secondary" type="button" onClick={checkProposal} disabled={proposalTesting}>{proposalTesting ? '검사 중…' : '전체 샘플에서 일치 검사'}</button>
                  <button className="guided-cta-main" type="button" onClick={addRule} disabled={!acceptedResult?.matched}>필드 규칙 적용</button></div>
                {acceptedResult && <p className="guided-preview-evidence" role="status">미리보기: {acceptedResult.matched} / {acceptedResult.total}개 이벤트 일치 · Fluentd 검증 아님</p>}
                {fieldHighlights && <div className="guided-match-review" aria-label="Field match examples">
                  <div className="guided-match-header"><strong>샘플별 필드 추출 비교</strong><span>처음 {fieldHighlights.sampled} / {fieldHighlights.total}개 표시</span></div>
                  {fieldHighlights.rows.map((row) => {
                    const snippet = matchContext(row);
                    return <div className="guided-match-row" key={row.id}>
                      <div className="guided-match-row-head">
                        <strong>#{row.line}</strong>
                        <span className={'guided-match-status ' + row.status}>
                          {row.status === 'matched' ? '일치' : row.status === 'unmatched' ? '미일치' : '검사하지 않음'}
                        </span>
                      </div>
                      <code>{snippet.before}{snippet.selected ? <mark className="guided-match-highlight">{snippet.selected}</mark> : null}{snippet.after}</code>
                    </div>;
                  })}
                  {fieldHighlights.omitted > 0 && <p className="guided-match-omitted">나머지 {fieldHighlights.omitted}개는 여기에서 생략했습니다. 전체 일치 건수는 위의 Web Worker 테스트 결과를 참조하세요.</p>}
                  <p className="guided-match-disclaimer">강조 표시는 임시 브라우저 정규식 결과입니다. Native Fluentd 검증이나 공식 필드 매핑의 증거가 아닙니다.</p>
                </div>}
              </> : null}
            </div>}
          </>}

          {step === 2 && <>
            <div className="guided-section-title"><span>01</span> 추출 필드와 정규화 대상 <span className="guided-inline-badge">{draft.mappings.length}개 규칙</span></div>
            <div className="guided-hint"><AlertTriangle size={16} /> 현재 입력한 대상 필드명은 초안입니다. 공식 Stellar Cyber Interflow 필드 사전은 검증 완료 전까지 제공되지 않습니다.</div>
            <div className="guided-map-list">{draft.mappings.map((mapping, index) =>
              <div className="guided-map-card" key={mapping.id}>
                <div className="guided-map-number"><span>FIELD {String(index + 1).padStart(2, '0')}</span>
                  <button type="button" title="매핑 삭제" aria-label={'Remove mapping ' + index} onClick={() => setDraft((old) => ({ ...old, mappings: old.mappings.filter((item) => item.id !== mapping.id) }))}><Trash2 size={15} /></button></div>
                <div className="guided-map-inputs">
                  <label className="guided-field"><span>원본 필드</span><input aria-label={'Source field ' + index} list="guided-field-suggestions" value={mapping.source} onChange={(e) => setMapping(mapping.id, 'source', e.target.value)} /></label>
                  <span className="guided-arrow-to"><ArrowRight size={18} /></span>
                  <label className="guided-field"><span>정규화 필드</span><input aria-label={'Destination field ' + index} value={mapping.target} onChange={(e) => setMapping(mapping.id, 'target', e.target.value)} /></label>
                </div>
                <div className="guided-map-inputs">
                  <label className="guided-field"><span>변환 타입</span><select aria-label={'Field type ' + index} value={mapping.type} onChange={(e) => setMapping(mapping.id, 'type', e.target.value)}>{TYPES.map((type) => <option value={type} key={type}>{TYPE_LABELS[type]}</option>)}</select></label>
                  <label className="guided-field"><span>필드 분류</span><select aria-label={'Mapping group ' + index} value={options.groups[mapping.id] ?? 'vendor_fields'} onChange={(e) => setGuided({ ...options, groups: { ...options.groups, [mapping.id]: e.target.value as FieldGroup } })}>{FIELD_GROUPS.map((group) => <option key={group} value={group}>{GROUP_LABELS[group]}</option>)}</select></label>
                </div>
              </div>)}</div>
            <datalist id="guided-field-suggestions">{Object.keys(activeEvent?.fields ?? {}).map((name) => <option value={name} key={name} />)}</datalist>
            <div className="guided-inline-actions"><button type="button" className="guided-cta-secondary" onClick={() => addMapping()}><Plus size={15} /> 새 필드 매핑</button>
              {Object.keys(activeEvent?.fields ?? {}).filter((field) => !draft.mappings.some((mapping) => mapping.source === field)).length > 0 && <button className="guided-link" type="button" onClick={() => { const first = Object.keys(activeEvent?.fields ?? {}).find((field) => !draft.mappings.some((mapping) => mapping.source === field)); if (first) addMapping(first); }}><WandSparkles size={15} /> 남은 필드 추천 추가</button>}</div>
            <div className="guided-note"><ShieldCheck size={15} /> 원본 필드는 미매핑 상태에서도 미리보기에 보존됩니다. 중복 매핑·타입 변환 오류는 전체 샘플 검사에서 확인합니다.</div>
            <div className="guided-section-title"><span>02</span> 선택형 필드 보강 <span className="guided-inline-badge">{options.enrichment?.length ?? 0}단계</span></div>
            <p className="guided-description">정규화된 필드에서 상수 추가, 복사, 소문자 또는 대문자 변환을 순서대로 적용합니다. 원본 로그는 사용하지 않습니다.</p>
            <datalist id="guided-normalized-suggestions">
              {draft.mappings.filter((mapping) => (options.groups[mapping.id] ?? 'vendor_fields') !== 'vendor_fields').map((mapping) => <option key={mapping.id} value={mapping.target} />)}
              {(options.enrichment ?? []).map((rule) => <option key={rule.id} value={rule.target} />)}
            </datalist>
            <div className="guided-enrichment-list">{(options.enrichment ?? []).map((rule, index) => <div key={rule.id} className="guided-enrichment-rule">
              <div className="guided-map-number"><span>보강 {index + 1}</span>
                <button type="button" aria-label={'Remove enrichment ' + index} onClick={() => removeEnrichment(rule.id)}><Trash2 size={15} /></button>
              </div>
              <div className="guided-enrichment-fields">
                <label className="guided-field"><span>작업</span><select aria-label={'Enrichment operator ' + index} value={rule.operator} onChange={(event) => changeEnrichment(rule.id, 'operator', event.target.value)}>
                  <option value="set_const">고정 값 추가</option><option value="copy">필드 복사</option>
                  <option value="lowercase">소문자 변환</option><option value="uppercase">대문자 변환</option>
                </select></label>
                {rule.operator === 'set_const'
                  ? <label className="guided-field"><span>추가할 값 (텍스트)</span><input aria-label={'Enrichment value ' + index} value={rule.value} onChange={(event) => changeEnrichment(rule.id, 'value', event.target.value)} /></label>
                  : <label className="guided-field"><span>기존 정규화 필드</span><input aria-label={'Enrichment source ' + index} list="guided-normalized-suggestions" value={rule.source} onChange={(event) => changeEnrichment(rule.id, 'source', event.target.value)} /></label>}
                <label className="guided-field"><span>신규 출력 필드</span><input aria-label={'Enrichment target ' + index} value={rule.target} placeholder="custom.extra" onChange={(event) => changeEnrichment(rule.id, 'target', event.target.value)} /></label>
              </div>
            </div>)}</div>
            <button type="button" className="guided-cta-secondary" onClick={addEnrichment} disabled={(options.enrichment?.length ?? 0) >= 64}><Plus size={15} /> 필드 보강 단계 추가</button>
            <div className="guided-hint"><ShieldCheck size={15} /> 생성 전 5단계에서 필드 보강 결과를 포함한 브라우저 미리보기를 검사합니다. 실제 Fluentd 실행·Stellar 적재는 별도 검증입니다.</div>

          </>}

          {step === 3 && <>
            <div className="guided-section-title"><span>01</span> 로그 수신 방식</div>
            <div className="guided-transport-grid">{(['udp', 'tcp'] as const).map((protocol) =>
              <label className={'guided-transport ' + (options.receiver.protocols.includes(protocol) ? 'active' : '')} key={protocol}>
                <input type="checkbox" aria-label={protocol.toUpperCase() + ' receiver'} checked={options.receiver.protocols.includes(protocol)} onChange={(e) => chooseProtocol(protocol, e.target.checked)} />
                <span><strong>{protocol.toUpperCase()}</strong><small>{protocol === 'udp' ? '데이터그램 방식' : '연결 기반 · 줄바꿈 프레임'}</small></span>
                {options.receiver.protocols.includes(protocol) && <CheckCircle2 size={18} />}
              </label>)}</div>
            <div className="guided-three-fields">
              <label className="guided-field"><span>수신 포트</span><input aria-label="Receiving port" type="number" min={1024} max={65535} step={1} value={options.receiver.port} onChange={(e) => setReceiver('port', Number(e.target.value))} /></label>
              <label className="guided-field"><span>바인드 방식</span><select aria-label="Bind policy" value={options.receiver.bindPolicy} onChange={(e) => setReceiver('bindPolicy', e.target.value)}><option value="loopback">로컬 테스트 (127.0.0.1)</option><option value="all">전체 인터페이스 (0.0.0.0)</option></select></label>
              <label className="guided-field"><span>최대 메시지 (bytes)</span><input aria-label="Message limit" type="number" min={1024} max={65536} value={options.receiver.messageLimit} onChange={(e) => setReceiver('messageLimit', Number(e.target.value))} /></label>
            </div>
            <div className="guided-hint"><ShieldAlert size={16} /> 실제 서버의 수신 포트 충돌·권한 여부는 아직 확인할 수 없습니다. 저장된 샘플의 동일 포트 사용은 활성 충돌의 증거가 아닙니다.</div>
            <div className="guided-section-title"><span>02</span> 이벤트 유형 분류</div>
            <p className="guided-description">로그에 있는 필드 값에 따라 이벤트 유형을 자동 선택합니다. 여러 규칙이 일치하면 위쪽 규칙을 우선합니다.</p>
            <div className="guided-conditions">{options.classification.rules.map((rule, index) =>
              <div key={rule.id} className="guided-condition">
                <span className="guided-condition-index">IF {index + 1}</span>
                <input aria-label={'Rule field ' + index} placeholder="원본 필드 (action)" list="guided-field-suggestions" value={rule.sourceField} onChange={(e) => changeCondition(rule.id, 'sourceField', e.target.value)} />
                <span>값 =</span>
                <input aria-label={'Rule value ' + index} placeholder="deny" value={rule.equals} onChange={(e) => changeCondition(rule.id, 'equals', e.target.value)} />
                <span>→</span>
                <select aria-label={'Rule class ' + index} value={rule.index} onChange={(e) => changeCondition(rule.id, 'index', e.target.value)}>{CLASSIFICATIONS.map((category) => <option key={category} value={category}>{CLASS_LABELS[category]}</option>)}</select>
                <button type="button" aria-label={'Remove rule ' + index} onClick={() => setGuided({ ...options, classification: { ...options.classification, rules: options.classification.rules.filter((item) => item.id !== rule.id) } })}><Trash2 size={14} /></button>
              </div>)}</div>
            <button type="button" className="guided-cta-secondary" onClick={addCondition}><Plus size={15} /> 조건 추가</button>
            <div className="guided-default-class"><span>조건에 맞지 않는 이벤트</span><select aria-label="Default classification" value={options.classification.defaultIndex} onChange={(e) => setGuided({ ...options, classification: { ...options.classification, defaultIndex: e.target.value as EventClass } })}>{CLASSIFICATIONS.map((category) => <option key={category} value={category}>{CLASS_LABELS[category]}</option>)}</select></div>
            <div className="guided-section-title"><span>03</span> 샘플별 분류 미리보기 <span className="guided-inline-badge">로컬 규칙 예상 결과</span></div>
            <div className="guided-routing-preview" aria-label="Sample classification preview">
              {!suite?.events.length && <div className="guided-route-empty">먼저 로그를 추가해야 분류 동작을 미리 볼 수 있습니다.</div>}
              {(suite?.events ?? []).slice(0, 30).map((event) => {
                const hint = suggestClassification(event, options);
                return <div className="guided-routing-row" key={event.id}>
                  <span className="guided-routing-event">#{event.line}</span>
                  <div><strong className={hint.status === 'unresolved' ? 'unresolved' : hint.status === 'matched' ? 'matched' : 'fallback'}>{hint.index ?? '미분류'}</strong><small>{hint.reason}</small></div>
                  <span className={'guided-route-state ' + hint.status}>{hint.status === 'unresolved' ? '추출 실패' : hint.status === 'matched' ? '조건 일치' : '기본값'}</span>
                </div>;
              })}
              {(suite?.events.length ?? 0) > 30 && <p className="guided-route-empty">첫 30개 이벤트만 표시합니다. 전체 이벤트 검사는 5단계에서 수행하세요.</p>}
            </div>
            <div className="guided-hint"><AlertTriangle size={16} /> 분류 결과는 브라우저 조건식 미리보기입니다. 실제 stellar_log_index 태그 라우팅은 별도 Fluentd 엔진 검증이 필요합니다.</div>
          </>}

          {step === 4 && <>
            <div className="guided-test-header"><div><div className="guided-section-title"><span>01</span> 전체 샘플 검사</div><p>일치한 것과 올바르게 정규화한 것은 다릅니다. 실패·경고를 구분해 표시합니다.</p></div>
              <button type="button" className="guided-cta-main" onClick={onRunSuite} disabled={!hasLogs || pending}><Play size={15} /> 브라우저 전체 테스트</button></div>
            <div className="guided-test-metrics">
              {[
                ['입력 이벤트', runState?.suite.counts.total ?? '—'],
                ['추출 성공', runState?.suite.counts.extracted ?? '—'],
                ['정규화 성공', runState?.suite.counts.normalized ?? '—'],
                ['실패', runState?.suite.counts.failures ?? '—'],
              ].map(([label, value]) => <div key={label} className="guided-test-metric"><span>{label}</span><strong>{value}</strong></div>)}
            </div>
            <div className="guided-hint"><ShieldAlert size={16} /> {runState ? '테스트 엔진: browser-preview · 네이티브 Fluentd/실제 Stellar 적재 성공이 아닙니다.' : '아직 이 초안의 전체 샘플 테스트 기록이 없습니다. 먼저 브라우저 테스트를 실행하세요.'}</div>
            <div className="guided-filter"><span>이벤트별 결과 {suite?.events.length ?? 0}건</span><div>{(['all','fail','warning'] as const).map((filter) => <button type="button" aria-pressed={errorFilter === filter} key={filter} className={errorFilter === filter ? 'selected' : ''} onClick={() => setErrorFilter(filter)}>{filter === 'all' ? '전체' : filter === 'fail' ? '실패만' : '경고만'}</button>)}</div></div>
            <div className="guided-test-events">{(suite?.events ?? []).filter((event) => errorFilter === 'all' || event.status === errorFilter).map((event) =>
              <button className="guided-test-event" type="button" key={event.id} onClick={() => { setSelectedId(event.id); setStep(1); }}>
                <span className={'guided-status-dot ' + event.status} />
                <span><strong>이벤트 #{event.line}</strong><small>{event.diagnostics.slice(0, 2).map((diag) => diag.message).join(' · ') || '브라우저 미리보기에서 오류 없음'}</small></span>
                <strong className={'guided-status-name ' + event.status}>{event.status === 'fail' ? '실패' : event.status === 'warning' ? '주의' : '미리보기 성공'}</strong>
                <ChevronRight size={14} />
              </button>)}
            </div>
            <button type="button" className="guided-link" onClick={onExpert}><Code2 size={15} /> 오류 원인 상세 보기 / Expert Workbench</button>
          </>}

          {step === 5 && <>
            <div className="guided-export-status"><LockKeyhole size={22} /><div><strong>{qualifiedPair ? '파서 초안 생성 완료 · DRAFT' : '검증 가능한 초안 생성 단계'}</strong><p>백엔드 입력 검증과 브라우저 샘플 테스트를 통과하면 2개의 DRAFT 파일을 생성할 수 있습니다. 네이티브 Fluentd 실행 및 Stellar Cyber 대상 적재는 아직 검증되지 않았으며, 실제 장비에 자동 배포하지 않습니다.</p></div></div>
            <div className="guided-section-title"><span>01</span> 계획된 출력 파일</div>
            <div className="guided-pair-files">
              <div><FileText size={21} /><span><strong>{names?.config ?? '유효한 파서 ID가 필요합니다'}</strong><small>로그 수신·라우팅 설정 · 생성 대기</small></span><span className="guided-pending-tag">{qualifiedPair ? 'DRAFT · SHA OK' : 'NOT GENERATED'}</span></div>
              <div><FileText size={21} /><span><strong>{names?.parser ?? '유효한 파서 ID가 필요합니다'}</strong><small>확장자 없는 Ruby 파서 조각 · 생성 대기</small></span><span className="guided-pending-tag">{qualifiedPair ? 'DRAFT · SHA OK' : 'NOT GENERATED'}</span></div>
            </div>
            <div className="guided-section-title"><span>02</span> 작성한 데이터 계약 검사</div>
            {artifactContract.ok ? <div className="guided-note"><ClipboardCheck size={17} /> UI 입력 검사는 통과했습니다. 실제 엔진·대상 적재 호환성 검사는 별도입니다.</div> : <div className="guided-contract-errors">{artifactContract.errors.map((issue) => <div key={issue}><AlertCircle size={15} /><span>{issue}</span></div>)}</div>}
            {!backendProject.ok && <div className="guided-contract-errors" aria-label="Backend mapping compatibility errors">{backendProject.issues.map((issue, index) => <div key={issue.code + index}><AlertCircle size={15} /><span>{issue.message}</span></div>)}</div>}
            <div className="guided-section-title"><span>03</span> 로컬 백엔드 계약 검사</div>
            <div className="guided-backend-control">
              <button type="button" className="guided-cta-secondary" onClick={() => { void checkBackend(); }} disabled={!backendProject.ok || validatingBackend}>
                <ShieldCheck size={15} /> {validatingBackend ? '백엔드 검사 중…' : '백엔드 입력 검사'}
              </button>
              <span>{qualifiedBackend?.result.ok ? 'Schema PASS · 엔진 미검증' : '검사 대기 / 백엔드 연결 필요'}</span>
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
            <div className="guided-section-title"><span>04</span> 두 파일 생성 및 다운로드</div>
            <div className="guided-export-actions">
              {qualifiedBackend?.result.ok
                ? <button type="button" className="guided-cta-main" onClick={() => { void buildDraftPair(); }} disabled={generatingPair || !runState?.suite.counts.total || runState.suite.counts.matched !== runState.suite.counts.total || runState.suite.counts.normalized !== runState.suite.counts.total || runState.suite.counts.failures > 0}>
                  <FileArchive size={15} /> {generatingPair ? '초안 생성 중…' : '파서 초안 2개 파일 생성 (DRAFT)'}
                </button>
                : <button type="button" className="guided-cta-main" disabled><FileArchive size={15} /> 파서 2개 파일 생성 (연결 대기)</button>}
              <button type="button" className="guided-cta-secondary" disabled={!backendProject.ok} onClick={() => { if (backendProject.ok) localDownload('parser-project-'+backendProject.project.slug+'.json', JSON.stringify(backendProject.project, null, 2)); }}><Download size={15} /> 백엔드용 프로젝트 JSON 다운로드</button>
            </div>
            {qualifiedBackend?.result.ok && (!runState?.suite.counts.total || runState.suite.counts.matched !== runState.suite.counts.total || runState.suite.counts.normalized !== runState.suite.counts.total || runState.suite.counts.failures > 0) && <div className="guided-hint"><AlertTriangle size={16} /> 동일 초안·샘플로 5단계 전체 브라우저 테스트를 실행하고 모든 이벤트가 추출·정규화됐는지 확인해야 DRAFT 파일 생성이 열립니다.</div>}
            {qualifiedPair && <div className="guided-generated-pair" aria-label="Generated draft parser pair">
              <div className="guided-generated-header"><FileCheck2 size={18} /><div><strong>2개 DRAFT 파일 · SHA-256 무결성 확인</strong><small>Native Fluentd / Stellar import 검증 없음 · 자동 배포 없음</small></div></div>
              <div className="guided-generated-files">{qualifiedPair.files.map((file) =>
                <button className="guided-cta-secondary" key={file.name} type="button" onClick={() => localDownload(file.name, file.content, 'application/octet-stream')}><Download size={15} /> {file.name}</button>)}</div>
              <div className="guided-generated-warnings">{qualifiedPair.manifest.warnings.map((warning, index) => <p key={index}><AlertTriangle size={13} /> {warning}</p>)}</div>
            </div>}
            <details className="guided-pair-inspect">
              <summary><FileArchive size={16} /> 기존 Parser Pair 읽기 전용 검사 (고급)</summary>
              <p>파일을 선택해도 자동 전송하지 않습니다. 아래 버튼을 누를 때만 개발 서버의 같은 출처·로컬 API로 두 파일을 전송해 구조와 SHA-256을 확인합니다. 원본 내용은 저장하거나 화면에 표시하지 않습니다.</p>
              <div className="guided-pair-inspect-files">
                <label>수신 설정 (.conf)<input type="file" aria-label="Inspect pair CONF" accept=".conf,text/plain" onChange={(event) => { setInspectConf(event.target.files?.[0] ?? null); setInspectionResult(null); setInspectionError(''); }} /></label>
                <label>확장자 없는 Ruby 파서 조각<input type="file" aria-label="Inspect pair Ruby fragment" onChange={(event) => { setInspectFragment(event.target.files?.[0] ?? null); setInspectionResult(null); setInspectionError(''); }} /></label>
              </div>
              <button type="button" className="guided-cta-secondary" disabled={!inspectConf || !inspectFragment || inspecting} onClick={() => { void inspectChosenPair(); }}>
                <ShieldCheck size={15} /> {inspecting ? '로컬 구조 검사 중…' : '선택한 두 파일의 구조만 검사'}
              </button>
              {inspectionError && <p className="guided-error" role="alert">{inspectionError}</p>}
              {inspectionResult && <div className="guided-pair-inspection-result" aria-label="Parser pair inspection results">
                <strong>{inspectionResult.editable ? '동일 생성기 출력과 바이트 일치 · 편집형 IR 확인' : '알 수 없는 원본 · OPAQUE READ-ONLY'}</strong>
                <p>수신기 {inspectionResult.sourceCount}개 · 프로토콜 {inspectionResult.protocols.join(', ') || '미확인'} · 포트 {inspectionResult.ports.join(', ') || '미확인'}</p>
                <p>파일 SHA-256: CONF {inspectionResult.confSha256.slice(0, 16)}… / Parser {inspectionResult.fragmentSha256.slice(0, 16)}…</p>
                {inspectionResult.diagnostics.length > 0 && <ul>{inspectionResult.diagnostics.map((code) => <li key={code}>{code}</li>)}</ul>}
                <small>원본 Ruby 실행·자동 수정·Parser Studio 가져오기는 수행하지 않습니다. 실제 Stellar Cyber 적용도 검증되지 않았습니다.</small>
              </div>}
            </details>
            <div className="guided-hint"><HelpCircle size={16} /> 프로젝트 JSON에는 원본 로그가 포함되지 않습니다. 제공 가능한 파일은 DRAFT Ruby 조각과 CONF이며, 포털 업로드 형식이나 네이티브 엔진 검증 결과로 간주할 수 없습니다.</div>
          </>}
        </div>

        {message && <div className="guided-message" role="status"><HelpCircle size={15} /> {message}<button type="button" onClick={() => setMessage('')}>닫기</button></div>}
        <div className="guided-bottom-bar">
          <button type="button" className="guided-cta-secondary" onClick={prevStep} disabled={step === 0}><ArrowLeft size={15} /> 이전</button>
          <div>{STEPS[step].label} <strong>{step + 1} / 6</strong></div>
          {step < 5 ? <button type="button" className="guided-cta-main" onClick={nextStep}>다음 단계 <ArrowRight size={16} /></button>
            : <button type="button" className="guided-cta-secondary" onClick={() => setStep(0)}><RotateCcw size={15} /> 다시 확인</button>}
        </div>
      </section>
      <aside className="guided-inspector" aria-label="Current preview and compatibility">
        <div className="guided-inspector-heading"><span>LIVE OVERVIEW</span><span className="guided-live-dot" /> 로컬 미리보기</div>
        <div className="guided-inspector-metrics">
          <div><strong>{suite?.counts.total ?? '—'}</strong><span>입력</span></div>
          <div><strong>{suite?.counts.matched ?? '—'}</strong><span>일치</span></div>
          <div><strong>{suite?.counts.normalized ?? '—'}</strong><span>정규화</span></div>
          <div><strong>{hardFails}</strong><span>실패</span></div>
        </div>
        <div className="guided-inspector-divider" />
        <h3>처리 결과 미리보기</h3>
        <p>{activeEvent ? '현재 선택된 이벤트 #' + activeEvent.line : '분석할 이벤트가 없습니다'}</p>
        <pre className="guided-inspector-json">{activeEvent ? JSON.stringify(activeEvent.normalized, null, 2) : 'No preview'}</pre>
        <div className="guided-inspector-divider" />
        <div className="guided-validation-header"><span>기능별 검증 상태</span><HelpCircle size={15} /></div>
        <div className="guided-checks"><div><CheckCircle2 size={15} /><span>브라우저 미리보기</span><strong>{pending ? '실행 중' : suite ? '실행됨' : '미실행'}</strong></div>
          <div><AlertTriangle size={15} /><span>Ruby/Fluentd 테스트</span><strong>미검증</strong></div>
          <div><AlertTriangle size={15} /><span>Stellar 적재 검증</span><strong>미검증</strong></div>
          <div><LockKeyhole size={15} /><span>자동 배포</span><strong>비활성</strong></div>
        </div>
        <div className="guided-inspector-bottom"><ShieldCheck size={16} /> 모델은 Stellar 버전과 독립적으로 작성합니다. 지원 여부는 실제 출력 어댑터 검증 후 판단합니다.</div>
      </aside>
    </div>
  </main>;
}
