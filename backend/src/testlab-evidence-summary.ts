/**
 * Owner-scoped offline Test Lab evidence aggregation.
 * An exact allowlist-validated report is the ONLY accepted source, so no
 * raw samples, customer values, hostnames, target URLs or credentials enter
 * the summary. Zero real-target/engine/E2E claims regardless of mock probes.
 */
import type {TestLabEvidenceLedger} from "./testlab-evidence.js";
import {exportRedactedEvidenceReport,TestLabReportExportError}
  from "./testlab-report-export.js";
type Report=ReturnType<TestLabEvidenceLedger["report"]>;

const safePercent=(n:number,total:number):number=>
  total===0?0:Math.round((n*10000)/total)/100;

export type EvidenceFieldCoverage={
  field:string;comparedEvents:number;matched:number;mismatched:number;
  missing:number;coveragePercent:number;matchPercent:number;
};
export type EvidenceSummary={
  contract:"testlab-redacted-summary.v0.1";
  mode:"OFFLINE_CONTRACT";runId:string;artifactRevisionId:string;
  expiresAt:string;
  comparisonStatus:"NOT_VERIFIED"|"OFFLINE_EVIDENCE_ONLY";
  counts:Report["counts"];
  failureGroups:Array<{errorCode:string;events:number}>;
  fieldCoverage:EvidenceFieldCoverage[];
  realSensorVerified:false;runtimeParsingVerified:false;liveE2eVerified:false;
};
export function summarizeRedactedEvidenceReport(raw:unknown):EvidenceSummary{
  // Same strict field names, stages, counters, upper bounds and owner-only
  // source contract as the already-reviewed downloadable report.
  const sanitized=exportRedactedEvidenceReport(raw).bytes;
  const report=JSON.parse(sanitized.toString("utf8")) as Report;
  const failures=new Map<string,number>();
  const fields=new Map<string,{matched:number;mismatched:number;missing:number}>();
  for(const event of report.events){
    if(event.errorCode)failures.set(event.errorCode,(failures.get(event.errorCode)??0)+1);
    if(!event.dpIndexed)continue;
    for(const entry of event.fields){
      let totals=fields.get(entry.field);
      if(!totals){
        if(fields.size>=256)throw new TestLabReportExportError("EVIDENCE_SUMMARY_CAPACITY");
        totals={matched:0,mismatched:0,missing:0};
        fields.set(entry.field,totals);
      }
      if(entry.status==="MATCH")totals.matched++;
      else if(entry.status==="MISMATCH")totals.mismatched++;
      else totals.missing++;
    }
  }
  const fieldCoverage:EvidenceFieldCoverage[]=[...fields].sort(([a],[b])=>
    a.localeCompare(b)).map(([field,c])=>{
      const comparedEvents=c.matched+c.mismatched+c.missing;
      return {field,comparedEvents,matched:c.matched,mismatched:c.mismatched,
        missing:c.missing,
        coveragePercent:safePercent(comparedEvents,report.counts.dpIndexed),
        matchPercent:safePercent(c.matched,comparedEvents)};
    });
  return {
    contract:"testlab-redacted-summary.v0.1",mode:"OFFLINE_CONTRACT",
    runId:report.runId,artifactRevisionId:report.artifactRevisionId,
    expiresAt:report.expiresAt,
    comparisonStatus:report.counts.dpIndexed===0?"NOT_VERIFIED":"OFFLINE_EVIDENCE_ONLY",
    counts:{...report.counts},
    failureGroups:[...failures].sort(([a],[b])=>a.localeCompare(b))
      .map(([errorCode,events])=>({errorCode,events})),
    fieldCoverage,realSensorVerified:false,
    runtimeParsingVerified:false,liveE2eVerified:false,
  };
}
