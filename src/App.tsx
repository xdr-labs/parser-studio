import { useEffect, useMemo, useState } from 'react';
import type { ChangeEvent, ReactNode } from 'react';
import {
  Activity, AlertCircle, AlertTriangle, ArrowLeftRight, BookOpen, Check, CheckCircle2,
  ChevronDown, ChevronRight, CircleHelp, Clock3, Code2, Download, FileCode2, FileDown,
  FileText, FileUp, FlaskConical, FolderOpen, GitBranch, LayoutGrid, Layers3,
  LoaderCircle, LockKeyhole, Plus, Play, RotateCcw, Save, Search, Settings2, ShieldCheck,
  ShieldX, SlidersHorizontal, Trash2, WandSparkles, X,
} from 'lucide-react';
import type { FieldType, Format, MappingRule, ParserDraft, SuiteResult } from './model';
import { createDraft, DEMO_SAMPLES, FORMATS } from './model';
import { formatLabel, MAX_DATASET_BYTES } from './parser';
import { createFieldProposal } from './pattern';
import GuidedBuilder from './guided/GuidedBuilder';
import { exportPortableDraft, readRevisions, saveRevision, type SavedRevision } from './storage';

type Page = 'guided' | 'workbench' | 'test-lab' | 'library' | 'export' | 'schema';
type Stage = 'raw' | 'extracted' | 'normalized' | 'diff';
type EditorTab = 'extraction' | 'mapping';
type PreviewState = { key: string; suite?: SuiteResult; error?: string };
type RunState = { key: string; suite: SuiteResult; timestamp: string };
type NavEntry = { id: Page; label: string; icon: typeof Activity };

const NAV: NavEntry[] = [
  { id: 'guided', label: 'Guided Builder', icon: WandSparkles },
  { id: 'workbench', label: 'Workbench', icon: LayoutGrid },
  { id: 'test-lab', label: 'Test Lab', icon: FlaskConical },
  { id: 'library', label: 'Parser Library', icon: FolderOpen },
  { id: 'export', label: 'Export & History', icon: GitBranch },
  { id: 'schema', label: 'Schema Explorer', icon: BookOpen },
];

const FIELD_TYPES: FieldType[] = ['string', 'integer', 'number', 'boolean', 'ip', 'port', 'timestamp'];
const DEMO_CATALOG = [
  { name: 'custom.source_ip', type: 'ip', description: 'User-defined source address' },
  { name: 'custom.destination_port', type: 'port', description: 'User-defined destination port' },
  { name: 'custom.action', type: 'string', description: 'User-defined outcome' },
  { name: 'custom.event_time', type: 'timestamp', description: 'Explicit timezone timestamp' },
  { name: 'custom.device', type: 'string', description: 'User-defined source device' },
];

function runInWorker(raw: string, draft: ParserDraft): Promise<SuiteResult> {
  return new Promise((resolve, reject) => {
    if (typeof Worker === 'undefined') { reject(new Error('Web Worker is unavailable in this browser')); return; }
    const worker = new Worker(new URL('./preview.worker.ts', import.meta.url), { type: 'module' });
    let complete = false;
    const finish = () => { complete = true; window.clearTimeout(timeout); worker.terminate(); };
    const timeout = window.setTimeout(() => {
      if (!complete) { finish(); reject(new Error('Local preview timed out after 2 seconds')); }
    }, 2000);
    worker.onmessage = (message: MessageEvent<{ suite?: SuiteResult; error?: string }>) => {
      finish();
      if (message.data.suite) resolve(message.data.suite);
      else reject(new Error(message.data.error ?? 'Preview worker failed'));
    };
    worker.onerror = () => { finish(); reject(new Error('Preview worker crashed')); };
    worker.postMessage({ raw, draft });
  });
}

function useLivePreview(raw: string, draft: ParserDraft): { key: string; suite?: SuiteResult; error?: string; pending: boolean } {
  const key = useMemo(() => JSON.stringify([raw, draft]), [raw, draft]);
  const [state, setState] = useState<PreviewState | null>(null);
  useEffect(() => {
    let canceled = false;
    const timer = window.setTimeout(() => {
      runInWorker(raw, draft)
        .then((suite) => { if (!canceled) setState({ key, suite }); })
        .catch((err: unknown) => { if (!canceled) setState({ key, error: err instanceof Error ? err.message : 'Preview failed' }); });
    }, 120);
    return () => { canceled = true; window.clearTimeout(timer); };
  }, [raw, draft, key]);
  return {
    key,
    suite: state?.key === key ? state.suite : undefined,
    error: state?.key === key ? state.error : undefined,
    pending: !state || state.key !== key,
  };
}

function StatusPill({ status, children }: { status: 'pass' | 'warning' | 'fail' | 'pending'; children: ReactNode }) {
  return <span className={`pill pill-${status}`}>{status === 'pass' ? <Check size={12} /> : status === 'fail' ? <X size={12} /> : status === 'warning' ? <AlertTriangle size={12} /> : <Clock3 size={12} />}{children}</span>;
}

function Metric({ label, value, tone = '' }: { label: string; value: number | string; tone?: string }) {
  return <div className={`metric ${tone}`}><span>{label}</span><strong>{value}</strong></div>;
}

function SectionEmpty({ icon, title, detail }: { icon: ReactNode; title: string; detail: string }) {
  return <div className="section-empty"><div className="empty-icon">{icon}</div><h3>{title}</h3><p>{detail}</p></div>;
}

function JsonView({ data }: { data: unknown }) {
  return <pre className="code-output" tabIndex={0}>{JSON.stringify(data, null, 2)}</pre>;
}

function inferType(field: string): FieldType {
  if (/(?:^|_)(?:src_ip|dst_ip|source_ip|dest_ip|ip)(?:$|_)/i.test(field)) return 'ip';
  if (/port/i.test(field)) return 'port';
  if (/(?:timestamp|event_time)/i.test(field)) return 'timestamp';
  return 'string';
}

function saveDownload(name: string, content: string) {
  const filename = (name.trim().toLowerCase().replace(/[^a-z0-9-_]+/g, '-').slice(0, 50) || 'parser') + '.draft.json';
  const url = URL.createObjectURL(new Blob([content], { type: 'application/json;charset=utf-8' }));
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  document.body.append(anchor);
  anchor.click();
  anchor.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export default function App() {
  const [page, setPage] = useState<Page>('guided');
  const [draft, setDraft] = useState<ParserDraft>(() => createDraft());
  const [sample, setSample] = useState(DEMO_SAMPLES);
  const [datasetName, setDatasetName] = useState('Synthetic demo events');
  const [selectedId, setSelectedId] = useState('event-1');
  const [stage, setStage] = useState<Stage>('normalized');
  const [editorTab, setEditorTab] = useState<EditorTab>('extraction');
  const [eventFilter, setEventFilter] = useState<'all' | 'fail' | 'warning'>('all');
  const [revision, setRevision] = useState<SavedRevision | null>(null);
  const [revisions, setRevisions] = useState(() => readRevisions());
  const [runState, setRunState] = useState<RunState | null>(null);
  const [running, setRunning] = useState(false);
  const [rawSelection, setRawSelection] = useState('');
  const [proposalField, setProposalField] = useState('selected_field');
  const [proposalPreview, setProposalPreview] = useState<{ key: string; matched?: number; total?: number; error?: string } | null>(null);
  const [feedback, setFeedback] = useState('');
  const [schemaSearch, setSchemaSearch] = useState('');
  const live = useLivePreview(sample, draft);

  const suite = live.suite;
  const activeEvent = suite?.events.find((item) => item.id === selectedId) ?? suite?.events[0];
  const proposal = activeEvent && rawSelection ? createFieldProposal(activeEvent.raw, rawSelection, proposalField) : null;
  const proposalKey = JSON.stringify([sample, draft, selectedId, rawSelection, proposalField]);
  const validProposalPreview = proposalPreview?.key === proposalKey ? proposalPreview : null;
  const eventList = suite?.events.filter((ev) => eventFilter === 'all' || ev.status === eventFilter) ?? [];
  const validRun = runState?.key === live.key ? runState : null;
  const isDraftDirty = !revision || JSON.stringify(revision.draft) !== JSON.stringify(draft);

  const update = <K extends keyof ParserDraft>(field: K, value: ParserDraft[K]) => {
    setDraft((prev) => ({ ...prev, [field]: value }));
    setFeedback('');
  };
  const notify = (message: string) => { setFeedback(message); window.setTimeout(() => setFeedback(''), 4500); };

  const handleUpload = async (e: ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    e.target.value = '';
    if (!file) return;
    if (file.size > MAX_DATASET_BYTES) { notify('파일이 64 KiB 제한을 초과했습니다.'); return; }
    try {
      const text = new TextDecoder('utf-8', { fatal: true }).decode(await file.arrayBuffer());
      setSample(text);
      setDatasetName(file.name);
      setSelectedId('event-1');
      setRunState(null);
      notify('로컬 브라우저 메모리에만 샘플을 불러왔습니다.');
    } catch { notify('UTF-8 텍스트 파일만 지원합니다.'); }
  };

  const handleSave = () => {
    try {
      const saved = saveRevision(draft);
      setRevision(saved);
      setRevisions(readRevisions());
      notify('버전 저장됨 · 브라우저 로컬 · 원본 로그 미포함');
    } catch { notify('브라우저 로컬 저장에 실패했습니다. 저장 공간이나 권한을 확인하세요.'); }
  };

  const newDraft = () => {
    if (isDraftDirty && !window.confirm('Discard unsaved parser rules and create a new draft?')) return;
    setDraft(createDraft());
    setSample('');
    setDatasetName('No dataset');
    setSelectedId('event-1');
    setRevision(null);
    setRunState(null);
    setPage('guided');
  };

  const openRevision = (saved: SavedRevision) => {
    if (isDraftDirty && !window.confirm('Discard unsaved rules and open this local revision?')) return;
    setDraft(structuredClone(saved.draft));
    setRevision(saved);
    setSample('');
    setDatasetName('No dataset · samples are not saved');
    setSelectedId('event-1');
    setRunState(null);
    setPage('guided');
  };

  const runSuite = async (target: Page = 'test-lab') => {
    setRunning(true);
    const key = live.key;
    try {
      const result = await runInWorker(sample, draft);
      setRunState({ key, suite: result, timestamp: new Date().toLocaleString('ko-KR') });
      setPage(target);
    } catch (error) {
      notify(error instanceof Error ? error.message : 'Suite failed to run');
    } finally { setRunning(false); }
  };

  const addMapping = (source = '') => {
    const resolved = source || Object.keys(activeEvent?.fields ?? {}).find((field) => !draft.mappings.some((m) => m.source === field)) || '';
    const mapping: MappingRule = {
      id: crypto.randomUUID(),
      source: resolved,
      target: resolved ? 'custom.' + resolved.replace(/[^\w]+/g, '_').replace(/^\d/, '_$&') : '',
      type: inferType(resolved),
    };
    update('mappings', [...draft.mappings, mapping]);
    setEditorTab('mapping');
  };

  const captureRawSelection = (selection: string, eventId?: string) => {
    const token = selection.trim();
    if (!token || token.includes('\n') || token.length > 80) return;
    const sourceEvent = eventId ? suite?.events.find((event) => event.id === eventId) : suite?.events.find((event) => event.raw.includes(token));
    if (!sourceEvent || !sourceEvent.raw.includes(token)) return;
    setSelectedId(sourceEvent.id);
    setRawSelection(token);
    setProposalField('selected_field');
    setProposalPreview(null);
    setEditorTab('extraction');
    setStage('raw');
  };

  const runFieldProposal = async () => {
    if (!proposal || 'error' in proposal) return;
    setProposalPreview(null);
    try {
      const proposedDraft = { ...draft, format: 'regex' as const, pattern: proposal.pattern };
      const result = await runInWorker(sample, proposedDraft);
      setProposalPreview({ key: proposalKey, matched: result.counts.matched, total: result.counts.total });
    } catch (error) {
      setProposalPreview({ key: proposalKey, error: error instanceof Error ? error.message : 'Proposal preview unavailable' });
    }
  };

  const applyFieldProposal = () => {
    if (!proposal || 'error' in proposal || !validProposalPreview || validProposalPreview.error || !validProposalPreview.total) return;
    const mapping: MappingRule = {
      id: crypto.randomUUID(), source: proposal.field,
      target: 'custom.' + proposal.field, type: inferType(proposal.field),
    };
    setDraft((prev) => ({ ...prev, format: 'regex', pattern: proposal.pattern, mappings: [...prev.mappings, mapping] }));
    setRawSelection('');
    setProposalPreview(null);
    setEditorTab('mapping');
    notify('Starter regex added. Review other event variants and native compatibility before export.');
  };

  const updateMapping = (id: string, field: keyof MappingRule, value: string) =>
    update('mappings', draft.mappings.map((item) => item.id === id ? { ...item, [field]: value } : item));

  return (
    <div className="app-shell">
      <aside className="nav-rail" aria-label="Main navigation">
        <div className="brand-symbol"><Layers3 size={23} strokeWidth={2.4} /></div>
        <div className="rail-group">
          {NAV.map(({ id, label, icon: Icon }) => (
            <button key={id} type="button" className={`rail-link ${page === id ? 'selected' : ''}`} onClick={() => setPage(id)} title={label} aria-label={label}>
              <Icon size={19} strokeWidth={1.9} /><span>{label}</span>
            </button>
          ))}
        </div>
        <div className="rail-footer" title="Local-only workspace">
          <LockKeyhole size={17} /><span>LOCAL</span>
        </div>
      </aside>

      <div className="app-main">
        <header className="topbar">
          <div className="topbar-identity">
            <span className="crumb-icon"><Activity size={18} /></span>
            <div><span className="eyebrow">XDR LABS / PARSER STUDIO</span><div className="header-title">Build reliable parsers. <span>See every event.</span></div></div>
          </div>
          <div className="topbar-actions">
            <span className="context-flag"><span className="status-dot" /> Browser preview only</span>
            <button className="button subtle" type="button" onClick={newDraft}><Plus size={16} /> New</button>
            <button className="button secondary" type="button" onClick={handleSave}><Save size={16} /> Save revision</button>
            <button className="button primary" type="button" onClick={() => { void runSuite(); }} disabled={running || !suite?.events.length || Boolean(live.error)}>{running ? <LoaderCircle size={16} className="spin" /> : <Play size={16} fill="currentColor" />} Run suite</button>
          </div>
        </header>

        {page !== 'guided' && <div className="content-heading">
          <div className="heading-stack">
            <div className="breadcrumbs">WORKSPACE <ChevronRight size={13} /> <strong>{NAV.find((item) => item.id === page)?.label}</strong></div>
            {page === 'workbench' ? (
              <div className="project-identity">
                <input aria-label="Parser project name" className="project-name" value={draft.name} onChange={(e) => update('name', e.target.value)} maxLength={90} />
                <StatusPill status="pending">{isDraftDirty ? 'Unsaved changes' : 'Saved local revision'}</StatusPill>
              </div>
            ) : <h1 className="page-title">{NAV.find((item) => item.id === page)?.label}</h1>}
            <p className="subtitle">{page === 'workbench' ? 'Design extraction rules, map fields and inspect transparent local previews.' : 'All results are local-browser evidence; native Fluentd and Stellar validation are separate gates.'}</p>
          </div>
          <div className="stage-marker"><span className="stage-index">01</span><div>WORKBENCH PREVIEW <small>R2 / in development</small></div></div>
        </div>}

        {page === 'guided' && <GuidedBuilder
          draft={draft} setDraft={setDraft} sample={sample} setSample={setSample}
          datasetName={datasetName} setDatasetName={setDatasetName}
          suite={suite} pending={live.pending} runState={validRun}
          runPreview={(candidate) => runInWorker(sample, candidate)}
          onRunSuite={() => { void runSuite('guided'); }}
          onExpert={() => setPage('workbench')} onSave={handleSave}
        />}

        {feedback && <div className="toast" role="status"><CircleHelp size={16} />{feedback}<button aria-label="Dismiss notification" onClick={() => setFeedback('')}><X size={14} /></button></div>}

        {page === 'workbench' && (
          <div className="workbench-grid">
            <section className="pane sample-pane" aria-label="Sample logs">
              <div className="pane-heading"><div><div className="pane-index">01 / INPUT</div><h2><FileText size={18} /> Sample logs</h2></div><span className="tiny-tag">LOCAL ONLY</span></div>
              <div className="dataset-card">
                <div className="field-caption">ACTIVE DATASET <span className="muted-text">· max 64 KiB</span></div>
                <div className="dataset-meta"><FileCode2 size={16} /><strong title={datasetName}>{datasetName}</strong><ChevronDown size={14} /></div>
                <div className="sample-toolbar">
                  <label className="button tiny upload-button" htmlFor="sample-upload"><FileUp size={14} /> Upload text</label>
                  <input type="file" id="sample-upload" accept=".log,.txt,.json,.csv,text/plain,application/json" onChange={handleUpload} hidden />
                  <button className="button tiny ghost" type="button" onClick={() => { setSample(DEMO_SAMPLES); setDatasetName('Synthetic demo events'); setSelectedId('event-1'); }}><RotateCcw size={13} /> Demo</button>
                  <button className="button tiny ghost" type="button" onClick={() => { setSample(''); setDatasetName('No dataset'); }}><Trash2 size={13} /> Clear</button>
                </div>
              </div>
              <label className="field-caption" htmlFor="sample-textarea">PASTE RAW EVENTS <span className="muted-text">· one physical line per event</span></label>
              <textarea className="sample-input" id="sample-textarea" spellCheck={false} value={sample} onChange={(e) => { setSample(e.target.value); setDatasetName('Pasted · session only'); }} onSelect={(e) => { const element = e.currentTarget; captureRawSelection(element.value.slice(element.selectionStart, element.selectionEnd)); }} placeholder="Paste raw log messages here. Select one value to propose a field. Each non-empty line is one event…" />
              <div className="list-topbar"><span>EVENT EXPLORER <strong>{suite?.events.length ?? '—'}</strong></span><div className="filter-pills">
                {(['all', 'fail', 'warning'] as const).map((filter) => <button type="button" key={filter} onClick={() => setEventFilter(filter)} className={eventFilter === filter ? 'active' : ''}>{filter === 'all' ? 'All' : filter === 'fail' ? 'Failed' : 'Warnings'}</button>)}
              </div></div>
              <div className="event-list" aria-label="Sample event explorer">
                {!suite && <SectionEmpty icon={<LoaderCircle size={18} />} title={live.error ? 'Preview unavailable' : 'Analyzing safely'} detail={live.error || 'The isolated browser worker is processing events.'} />}
                {suite && !eventList.length && <SectionEmpty icon={<FileText size={18} />} title="No events in this view" detail="Paste logs or choose another event filter." />}
                {eventList.map((ev) => <button className={`event-row ${ev.id === activeEvent?.id ? 'active' : ''}`} key={ev.id} type="button" onClick={() => setSelectedId(ev.id)}>
                  <span className={`event-dot ${ev.status}`} />
                  <div className="event-row-content"><div><strong>Event {ev.line.toString().padStart(2, '0')}</strong><span>{formatLabel(ev.effectiveFormat)}</span></div><p>{ev.raw}</p></div><ChevronRight size={14} />
                </button>)}
              </div>
              <div className="pane-footnote"><LockKeyhole size={13} /> Sample contents remain in this browser session and are not saved with revisions.</div>
            </section>

            <section className="pane rules-pane" aria-label="Parser pipeline rules">
              <div className="pane-heading"><div><div className="pane-index">02 / CONFIGURATION</div><h2><SlidersHorizontal size={18} /> Parser pipeline</h2></div><StatusPill status="pending">Draft</StatusPill></div>
              <div className="input-row">
                <label><span className="field-caption">PRODUCT / VENDOR LABEL</span><input value={draft.vendor} onChange={(e) => update('vendor', e.target.value)} maxLength={90} placeholder="e.g. Demo Firewall" /></label>
              </div>
              <div className="pipeline-track"><div className="pipeline-step current"><span>1</span> Detect & extract</div><ChevronRight size={14} /><div className="pipeline-step"><span>2</span> Normalize</div><ChevronRight size={14} /><div className="pipeline-step future"><span>3</span> Validate</div></div>
              <div className="editor-switch" role="tablist" aria-label="Parser rule editor tabs">
                <button type="button" role="tab" aria-selected={editorTab === 'extraction'} className={editorTab === 'extraction' ? 'selected' : ''} onClick={() => setEditorTab('extraction')}><Code2 size={15} /> Extraction</button>
                <button type="button" role="tab" aria-selected={editorTab === 'mapping'} className={editorTab === 'mapping' ? 'selected' : ''} onClick={() => setEditorTab('mapping')}><ArrowLeftRight size={15} /> Field mapping <span className="count-label">{draft.mappings.length}</span></button>
              </div>
              {editorTab === 'extraction' ? (
                <div className="editor-content">
                  <div className="rule-heading"><div><div className="field-caption">STAGE 01</div><h3>Extraction configuration</h3></div><span className="mini-symbol"><Code2 size={16} /></span></div>
                  <label className="form-label" htmlFor="format-select">Input format</label>
                  <select id="format-select" value={draft.format} onChange={(e) => update('format', e.target.value as Format)}>
                    {FORMATS.map((f) => <option key={f} value={f}>{formatLabel(f)}</option>)}
                  </select>
                  {draft.format === 'auto' && <p className="helper">Auto selects the detected format for each event. Inspect unmatched variants before export.</p>}
                  {draft.format === 'regex' && <>
                    <label className="form-label" htmlFor="regex-pattern">Named-group regular expression</label>
                    <textarea id="regex-pattern" className="rule-textarea" spellCheck={false} value={draft.pattern} onChange={(e) => update('pattern', e.target.value)} />
                    <p className="helper warn-helper"><AlertTriangle size={13} /> Browser regex preview has a 2s worker timeout. Native Fluentd equivalence is not established.</p>
                  </>}
                  {draft.format === 'csv' && <>
                    <label className="form-label" htmlFor="csv-columns">CSV columns (ordered, comma-separated)</label>
                    <input id="csv-columns" value={draft.csvColumns} onChange={(e) => update('csvColumns', e.target.value)} />
                  </>}
                  <div className="recognition-card">
                    <div className="recognition-head"><span className="field-caption">SELECTED EVENT · FORMAT CANDIDATE</span><StatusPill status={activeEvent?.detected.format === 'unknown' ? 'warning' : 'pending'}>{activeEvent ? formatLabel(activeEvent.detected.format) : 'No event'}</StatusPill></div>
                    <div className="confidence-row"><span>Detection confidence</span><strong>{activeEvent ? Math.round(activeEvent.detected.confidence * 100) + '%' : '—'}</strong></div>
                    <div className="confidence-track"><div style={{ width: (activeEvent?.detected.confidence ?? 0) * 100 + '%' }} /></div>
                    <p>{activeEvent?.detected.reason ?? 'Paste an event to see detection reasons.'}</p>
                  </div>
                  {rawSelection && <div className="field-proposal">
                    <div className="field-proposal-top"><div><span className="field-caption">SOURCE SELECTION / FIELD PROPOSAL</span><h4>Propose a field from source value</h4></div><button className="icon-action" type="button" aria-label="Close field proposal" onClick={() => { setRawSelection(''); setProposalPreview(null); }}><X size={15} /></button></div>
                    <div className="field-proposal-token" title={rawSelection}>{rawSelection}</div>
                    <label htmlFor="proposal-field" className="form-label">New field name</label>
                    <input id="proposal-field" aria-label="New field name" value={proposalField} onChange={(e) => { setProposalField(e.target.value); setProposalPreview(null); }} />
                    {proposal && 'error' in proposal ? <p className="proposal-error">{proposal.error}</p> : proposal ? <>
                      <div className="proposal-regex"><span>Proposed regular expression · event-specific</span><code>{proposal.pattern}</code></div>
                      <p className="helper">{proposal.caveat}</p>
                      <div className="proposal-actions"><button className="button tiny secondary-light" type="button" onClick={runFieldProposal}><Play size={13} /> Preview all samples</button><button className="button tiny apply-proposal" type="button" onClick={applyFieldProposal} disabled={!validProposalPreview || Boolean(validProposalPreview.error) || !validProposalPreview.matched}>Apply as draft rule</button></div>
                      {validProposalPreview && <div className="proposal-result" role="status">{validProposalPreview.error ?? ('Matched ' + validProposalPreview.matched + ' / ' + validProposalPreview.total + ' sample events · browser preview only')}</div>}
                    </> : null}
                  </div>}
                  <div className="extracted-label"><span>EXTRACTED FIELDS</span><span>{Object.keys(activeEvent?.fields ?? {}).length} available</span></div>
                  {activeEvent && Object.keys(activeEvent.fields).length ? <div className="field-pills">{Object.entries(activeEvent.fields).map(([key, value]) =>
                    <button title={`Add mapping for ${key}`} type="button" className="field-pill" key={key} onClick={() => addMapping(key)}><Plus size={12} /><b>{key}</b><span>{String(value).slice(0, 27)}</span></button>)}</div> :
                    <div className="inline-empty">No fields extracted from the current event.</div>}
                  <div className="compatibility-tip"><ShieldCheck size={17} /><div><strong>Transparent preview</strong><p>Supported local extractors: JSON, KV, CSV, RFC5424 subset and named-group regex. No native parser has run.</p></div></div>
                </div>
              ) : (
                <div className="editor-content">
                  <div className="rule-heading"><div><div className="field-caption">STAGE 02</div><h3>Typed field mapping</h3></div><span className="mini-symbol"><ArrowLeftRight size={16} /></span></div>
                  <p className="helper mapping-explainer">Map extracted source values to explicit custom fields. These are local example names, <b>not</b> a verified Stellar Interflow schema.</p>
                  <div className="mapping-heading"><span>SOURCE FIELD</span><span>OUTPUT FIELD</span><span>TYPE</span></div>
                  <div className="mapping-list">{draft.mappings.map((mapping) => <div className="mapping-row" key={mapping.id}>
                    <input aria-label={`Source for ${mapping.id}`} placeholder="src_ip" value={mapping.source} onChange={(e) => updateMapping(mapping.id, 'source', e.target.value)} />
                    <input aria-label={`Target for ${mapping.id}`} placeholder="custom.source_ip" value={mapping.target} onChange={(e) => updateMapping(mapping.id, 'target', e.target.value)} />
                    <select aria-label={`Type for ${mapping.id}`} value={mapping.type} onChange={(e) => updateMapping(mapping.id, 'type', e.target.value)}>{FIELD_TYPES.map((t) => <option value={t} key={t}>{t}</option>)}</select>
                    <button type="button" aria-label={`Remove ${mapping.id}`} className="icon-action" onClick={() => update('mappings', draft.mappings.filter((m) => m.id !== mapping.id))}><Trash2 size={15} /></button>
                  </div>)}</div>
                  <button type="button" className="button dashed" onClick={() => addMapping()}><Plus size={15} /> Add mapping</button>
                  <div className="mapping-note"><AlertCircle size={16} /> Missing fields, invalid types and output collisions are shown per event. Unmapped source fields are always listed.</div>
                </div>
              )}
              <div className="rules-bottom"><span><Settings2 size={14} /> IR draft · vendor-version neutral</span><button className="text-link" type="button" onClick={() => setPage('schema')}>Browse demo schema <ChevronRight size={14} /></button></div>
            </section>

            <section className="pane results-pane" aria-label="Preview results">
              <div className="pane-heading"><div><div className="pane-index">03 / OBSERVABILITY</div><h2><Activity size={18} /> Live result</h2></div>{live.pending ? <StatusPill status="pending">Running</StatusPill> : <StatusPill status={activeEvent?.status === 'fail' ? 'fail' : activeEvent?.status === 'warning' ? 'warning' : activeEvent ? 'pass' : 'pending'}>{activeEvent ? activeEvent.status : 'No event'}</StatusPill>}</div>
              <div className="result-runtime"><span className="runtime-dot" /><div><strong>Isolated browser worker</strong><span>Approximate parser preview · not Fluentd / Stellar</span></div><CircleHelp size={16} /></div>
              <div className="result-topline"><span>EVENT INSPECTOR</span><strong>{activeEvent ? `EVENT ${activeEvent.line.toString().padStart(2, '0')}` : '—'}</strong></div>
              <div className="result-tabs" role="tablist" aria-label="Event processing stages">
                {(['raw', 'extracted', 'normalized', 'diff'] as const).map((tab) => <button type="button" role="tab" aria-selected={stage === tab} key={tab} className={stage === tab ? 'selected' : ''} onClick={() => setStage(tab)}>{tab.toUpperCase()}</button>)}
              </div>
              <div className="result-code-area">
                {!activeEvent && <SectionEmpty icon={<Code2 size={20} />} title="No result yet" detail="Paste a log event to inspect each stage." />}
                {activeEvent && stage === 'raw' && <div className="raw-inspector"><div className="raw-inspector-hint">Select any source value to propose an extraction field</div><pre className="code-output raw-view" tabIndex={0} onMouseUp={() => captureRawSelection(window.getSelection()?.toString() ?? '', activeEvent.id)}>{activeEvent.raw}</pre></div>}
                {activeEvent && stage === 'extracted' && <JsonView data={activeEvent.fields} />}
                {activeEvent && stage === 'normalized' && <JsonView data={activeEvent.normalized} />}
                {activeEvent && stage === 'diff' && <div className="diff-table">
                  <div className="diff-head"><span>SOURCE</span><span>OUTPUT / MAPPING</span></div>
                  {Object.entries(activeEvent.fields).map(([key, value]) => {
                    const mapping = draft.mappings.find((m) => m.source === key);
                    return <div className="diff-row" key={key}><span><b>{key}</b><small>{String(value)}</small></span><span>{mapping ? <><b>{mapping.target}</b><small>{Object.prototype.hasOwnProperty.call(activeEvent.normalized, mapping.target) ? String(activeEvent.normalized[mapping.target]) : 'Conversion failed / missing'}</small></> : <em>Unmapped · preserved in source</em>}</span></div>;
                  })}
                </div>}
              </div>
              <div className="trace-heading"><span>PROCESSING TRACE</span><span>{activeEvent?.trace.length ?? 0} stages</span></div>
              <div className="trace-list">{(activeEvent?.trace ?? []).map((step, i) => <div className="trace-step" key={i}><div className={`trace-node ${step.ok ? 'ok' : 'not-ok'}`}>{step.ok ? <Check size={11} /> : <AlertCircle size={11} />}</div><div><strong>{step.stage}</strong><p>{step.detail}</p></div></div>)}</div>
              <div className="diagnostic-heading"><span>DIAGNOSTICS</span><strong>{activeEvent?.diagnostics.length ?? 0}</strong></div>
              <div className="diagnostic-list">
                {activeEvent?.diagnostics.length ? activeEvent.diagnostics.map((item, i) =>
                  <div className={`diagnostic ${item.severity}`} key={i}><AlertCircle size={15} /><div><b>{item.code}</b><p>{item.message}</p></div></div>) :
                  <div className="inline-empty">No diagnostics for selected event.</div>}
              </div>
            </section>
          </div>
        )}

        {page === 'test-lab' && <div className="surface-page">
          <div className="surface-top"><div><span className="pane-index">VALIDATION / 01</span><h2>Fixture runs & diagnostics</h2><p>Run this browser-local dataset explicitly. Results are not native Fluentd acceptance evidence.</p></div><button type="button" className="button primary" disabled={running || !suite?.events.length} onClick={() => { void runSuite(); }}><Play size={15} /> {running ? 'Running...' : 'Run local suite'}</button></div>
          {!validRun ? <SectionEmpty icon={<FlaskConical size={25} />} title="No current suite run" detail="Use Run local suite to record a browser-only result for the exact current rules and dataset." /> : <>
            <div className="report-banner"><CheckCircle2 size={19} /><div><strong>Browser suite executed</strong><span>{validRun.timestamp} · Isolated Web Worker · Native equivalence NOT VERIFIED</span></div><StatusPill status="pending">NOT FLUENTD VERIFIED</StatusPill></div>
            <div className="metric-grid"><Metric label="Events" value={validRun.suite.counts.total} /><Metric label="Matched" value={validRun.suite.counts.matched} /><Metric label="Normalized" value={validRun.suite.counts.normalized} tone="good" /><Metric label="Failed" value={validRun.suite.counts.failures} tone="bad" /><Metric label="Warnings" value={validRun.suite.counts.warnings} tone="warn" /></div>
            <div className="table-scroll"><table className="report-table"><thead><tr><th>EVENT</th><th>FORMAT</th><th>EXTRACTED</th><th>NORMALIZED</th><th>DIAGNOSTICS</th><th>RESULT</th></tr></thead><tbody>
              {validRun.suite.events.map((ev) => <tr key={ev.id} onClick={() => { setSelectedId(ev.id); setPage('workbench'); }} className="clickable-row"><td>Event {ev.line.toString().padStart(2, '0')}</td><td>{formatLabel(ev.effectiveFormat)}</td><td>{Object.keys(ev.fields).length} fields</td><td>{Object.keys(ev.normalized).length} fields</td><td>{ev.diagnostics.length}</td><td><StatusPill status={ev.status}>{ev.status}</StatusPill></td></tr>)}
            </tbody></table></div>
            <p className="report-note"><ShieldX size={15} /> A browser-only match never qualifies as a verified Fluentd or Stellar Cyber parser export.</p>
          </>}
        </div>}

        {page === 'library' && <div className="surface-page">
          <div className="surface-top"><div><span className="pane-index">PROJECTS / LOCAL HISTORY</span><h2>Saved parser revisions</h2><p>Rule configurations stored in this browser only; raw log samples are deliberately excluded.</p></div><button className="button secondary" type="button" onClick={newDraft}><Plus size={15} /> New draft</button></div>
          {revisions.length ? <div className="revision-grid">{revisions.map((item) => <button className="revision-card" type="button" key={item.id} onClick={() => openRevision(item)}>
            <div><span className="revision-icon"><FileCode2 size={21} /></span><StatusPill status="pending">Local draft</StatusPill></div><h3>{item.draft.name}</h3><p>{item.draft.vendor}</p><div className="revision-meta"><span><Clock3 size={13} /> {new Date(item.createdAt).toLocaleString('ko-KR')}</span><span>{item.draft.mappings.length} mappings <ChevronRight size={14} /></span></div>
          </button>)}</div> : <SectionEmpty icon={<FolderOpen size={26} />} title="No saved revisions" detail="Save your current parser rules to create a local revision. Sample logs will not be persisted." />}
        </div>}

        {page === 'export' && <div className="surface-page">
          <div className="surface-top"><div><span className="pane-index">COMPATIBILITY / ARTIFACTS</span><h2>Export & history</h2><p>Draft interchange is available. Deployable parser artifacts need actual engine and target-import evidence.</p></div><button type="button" className="button secondary" onClick={() => saveDownload(draft.name, exportPortableDraft(draft))}><FileDown size={16} /> Download draft JSON</button></div>
          <div className="adapter-grid">
            <div className="adapter-card"><span className="adapter-icon"><FileCode2 size={23} /></span><StatusPill status="pending">LOCAL DRAFT</StatusPill><h3>Portable parser project</h3><p>Configuration only. Includes explicit not-verified flags; never includes raw samples.</p><button className="button secondary" type="button" onClick={() => saveDownload(draft.name, exportPortableDraft(draft))}><Download size={15} /> Download .json</button></div>
            <div className="adapter-card disabled"><span className="adapter-icon"><Layers3 size={23} /></span><StatusPill status="pending">PENDING RUNNER</StatusPill><h3>Fluentd configuration</h3><p>Pinned native Fluentd sandbox and plugin capability tests are not implemented. Export is unavailable.</p><span className="locked-action"><LockKeyhole size={15} /> Export unavailable</span></div>
            <div className="adapter-card disabled"><span className="adapter-icon"><ShieldCheck size={23} /></span><StatusPill status="pending">PENDING EVIDENCE</StatusPill><h3>Stellar Cyber parser</h3><p>Actual vendor-specific artifact structure and target import verification are pending real samples.</p><span className="locked-action"><LockKeyhole size={15} /> Export unavailable</span></div>
          </div>
          <div className="security-banner"><ShieldX size={20} /><div><strong>Compatibility is earned, never assumed.</strong><p>Preview stages use a sandboxed browser worker, not Fluentd or the Stellar runtime. No live deployment, production writes or implicit adapter success.</p></div></div>
        </div>}

        {page === 'schema' && <div className="surface-page">
          <div className="surface-top"><div><span className="pane-index">DATA MODEL / CATALOG</span><h2>Destination field explorer</h2><p>This is a small user-defined <b>demo dictionary</b>, not the official Stellar Cyber Interflow field catalog.</p></div><StatusPill status="pending">CATALOG PENDING EVIDENCE</StatusPill></div>
          <div className="schema-search"><Search size={17} /><input aria-label="Search example fields" placeholder="Search field, type or meaning…" value={schemaSearch} onChange={(e) => setSchemaSearch(e.target.value)} /></div>
          <div className="table-scroll"><table className="report-table"><thead><tr><th>FIELD NAME</th><th>TYPE</th><th>DESCRIPTION</th></tr></thead><tbody>{DEMO_CATALOG.filter((item) => (item.name + item.type + item.description).toLowerCase().includes(schemaSearch.toLowerCase())).map((item) =>
            <tr key={item.name}><td className="mono">{item.name}</td><td>{item.type}</td><td>{item.description}</td></tr>)}</tbody></table></div>
          <p className="report-note"><AlertTriangle size={15} /> Official mappings must be verified from owner-supplied parser evidence before any compatibility claims.</p>
          <button className="button secondary" type="button" onClick={() => { setPage('workbench'); setEditorTab('mapping'); }}><ChevronRight size={15} /> Return to field mapping</button>
        </div>}

        <footer className="status-strip">
          <div className="strip-left"><span className="strip-label"><span className="status-dot" /> ENGINE: BROWSER PREVIEW</span><span>Dataset <strong>{suite?.counts.total ?? '—'}</strong></span><span>Matched <strong>{suite?.counts.matched ?? '—'}</strong></span><span>Normalized <strong>{suite?.counts.normalized ?? '—'}</strong></span><span>Failed <strong className="red-number">{suite?.counts.failures ?? '—'}</strong></span></div>
          <div className="strip-right"><span className="runtime-warning"><AlertTriangle size={13} /> Fluentd & Stellar: NOT VERIFIED</span><span className="version">v0.1 · R2 preview</span></div>
        </footer>
      </div>
    </div>
  );
}
