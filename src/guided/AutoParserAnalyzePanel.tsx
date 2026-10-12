import {useEffect,useRef,useState} from 'react';
import {ShieldCheck,WandSparkles} from 'lucide-react';
import type {ParserDraft} from '../model';
import {analyzeLogEnvelopes,assessEnvelopeCompilation,
  type EnvelopeLedger,type CompilerAssessment} from './autoParserEnvelope';
import {fetchBackendCapabilities} from './backendCapabilities';
import type {EventBoundary} from './contract';

interface Props{
  sample:string;
  boundary:EventBoundary;
  selectedFormat:ParserDraft['format'];
  selectedBody:ParserDraft['syslogBodyFormat'];
  onApply:(format:Exclude<CompilerAssessment['format'],null>,
    body:CompilerAssessment['bodyFormat'])=>void;
}
const LABELS:Record<CompilerAssessment['status'],string>={
  DRAFT_COMPILABLE:'The connected backend advertises this exact extraction shape as a DRAFT compiler input. User-parser native execution and target import remain unverified.',
  COMPILER_UNSUPPORTED:'The backend has not qualified this envelope and body combination. No Ruby/CONF pair can be generated from this candidate.',
  MIXED_OR_UNKNOWN:'Different, malformed or unknown source events require separate review. A single-parser compilation cannot silently ignore them.',
  COLUMNS_REQUIRED:'CSV column names must be explicitly reviewed before any DRAFT compiler handoff.',
  BOUNDARY_REVIEW:'Multiline event boundaries require review; native event breaking is not supported.',
  BACKEND_UNAVAILABLE:'Local analysis is available, but backend compiler compatibility could not be checked.',
  BACKEND_UNTRUSTED:'The backend returned unsupported verification flags or an incompatible capability contract.',
  SOURCE_LIMIT:'The source is empty, truncated or over the bounded local analysis budget.',
};
const ENVELOPES={none:'Standalone',rfc3164:'RFC3164 Syslog',rfc5424:'RFC5424 Syslog'} as const;
const BODIES={json:'JSON',kv:'Key / Value',cef:'CEF',leef:'LEEF',csv:'CSV',unknown:'Unknown'} as const;
const STATUS={
  RECOGNIZED:'Candidate identified',
  HEADER_MALFORMED:'Malformed header',
  BODY_MALFORMED:'Malformed body',
  BOUNDARY_AMBIGUOUS:'Multiline boundary uncertain',
  TOO_LONG:'Oversized event',
  UNKNOWN:'Unrecognized event',
} as const;
type Run={key:string;report:EnvelopeLedger;compiler:CompilerAssessment};
export default function AutoParserAnalyzePanel({
  sample,boundary,selectedFormat,selectedBody,onApply,
}:Props){
  const [run,setRun]=useState<Run|null>(null);
  const [busy,setBusy]=useState(false);
  const [backendNotice,setBackendNotice]=useState('');
  const latest=useRef('');
  const epoch=useRef(0);
  const key=JSON.stringify([sample,boundary]);
  latest.current=key;
  useEffect(()=>{
    epoch.current++;
    setRun(null);setBusy(false);setBackendNotice('');
    return ()=>{epoch.current++;};
  },[key]);
  const current=run?.key===key?run:null;
  const analyze=async()=>{
    if(busy)return;
    const token=++epoch.current;
    const expectedKey=key;
    setBusy(true);setBackendNotice('');setRun(null);
    // The source stays exclusively in the browser. Only a GET for static
    // capability metadata may reach the same-origin loopback backend.
    const report=analyzeLogEnvelopes(sample,boundary);
    let compiler=assessEnvelopeCompilation(report,null);
    if(report.complete&&report.sourceCount>0){
      try{
        const capabilities=await fetchBackendCapabilities();
        compiler=assessEnvelopeCompilation(report,capabilities);
      }catch{
        if(token===epoch.current)setBackendNotice(
          'Compiler metadata could not be verified. No parser will be generated or applied from this analysis.');
      }
    }
    if(token===epoch.current&&expectedKey===latest.current){
      setRun({key,report,compiler});
      setBusy(false);
    }
  };
  const selected=current?.compiler.format!==null &&
    selectedFormat===current?.compiler.format &&
    (selectedFormat!=='syslog_rfc5424' ||
     selectedBody===(current?.compiler.bodyFormat??'raw'));
  return <section className="guided-auto-envelope" aria-label="Auto Parser envelope and body review">
    <div className="guided-auto-envelope-heading">
      <strong><WandSparkles size={17}/> Analyze Logs · Envelope + Body</strong>
      <button type="button" className="guided-cta-secondary" disabled={!sample.trim()||busy}
        onClick={()=>{void analyze();}}>
        <ShieldCheck size={14}/>{busy?'Analyzing…':'Analyze Logs'}
      </button>
    </div>
    <p>Review all source events as candidate families without choosing JSON,
      CEF, LEEF or Syslog first. Only fixed statuses, original line numbers
      and counts are shown here. Sample contents never enter the report.</p>
    {backendNotice&&<p role="status" className="guided-note">{backendNotice}</p>}
    {current&&<div className="guided-auto-envelope-results" aria-label="Auto Parser source ledger">
      <strong>{current.report.accounted}/{current.report.sourceCount} logical events accounted for
        {' · '}{current.report.unsupported} need review</strong>
      <p>{LABELS[current.compiler.status]}</p>
      <small>Compiler contract: <b>{current.compiler.status}</b> ·
        Native parser unverified · Stellar target not verified</small>
      {current.report.families.length>0&&
        <div className="guided-auto-envelope-families" aria-label="Envelope body family totals">
          {current.report.families.map(group=>
            <span key={group.envelope+'/'+group.body}>
              {ENVELOPES[group.envelope]} / {BODIES[group.body]}: {group.count}
            </span>)}
        </div>}
      <ol className="guided-auto-envelope-events" aria-label="Source event statuses">
        {current.report.events.slice(0,30).map(entry=><li key={entry.sequence}>
          <b>Line {entry.line}</b> · {ENVELOPES[entry.envelope]} /
          {' '}{BODIES[entry.body]} · {STATUS[entry.status]}
          {entry.timePolicy==='YEAR_AND_ZONE_UNKNOWN'
            ?' · Year/timezone ambiguous':''}
        </li>)}
      </ol>
      {current.report.events.length>30&&
        <small>{current.report.events.length-30} additional events are included in the totals.
          No record was excluded silently.</small>}
      {current.compiler.status==='DRAFT_COMPILABLE'&&current.compiler.format&&
        <div className="guided-auto-envelope-apply">
          <p>Review this single-family DRAFT candidate. Selecting it changes
            only the draft extraction/body setting, not the source or mappings.</p>
          <button type="button" className="guided-cta-secondary"
            aria-label="Apply analyzed draft candidate" disabled={Boolean(selected)}
            onClick={()=>{if(current.compiler.format){
              onApply(current.compiler.format,current.compiler.bodyFormat);
            }}}>
            {selected?'Candidate Already Selected':'Use This DRAFT Candidate'}
          </button>
        </div>}
    </div>}
    <small>RFC3164 has no year or timezone in its header and cannot be compiled
      by the currently reviewed backend. Mixed, multiline and unknown records
      remain visible, not silently dropped. This analysis does not send a log,
      run Ruby, contact a DP or install a parser.</small>
  </section>;
}
