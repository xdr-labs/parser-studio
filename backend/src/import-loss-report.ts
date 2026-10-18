/**
 * Redacted, read-only import loss assessment. Unsupported Ruby is NEVER
 * rewritten or evaluated. An opaque import has unknown (not zero) loss risk.
 * All diagnostics originate in the existing bounded structural inspector.
 */
import {inspectPair,type PairInspectionInput,
  type InspectionDiagnosticCode} from "./import.js";
export type ImportLossReport={
  contract:"parser-import-loss-report.v0.1";
  conversionStatus:"EXACT_EDITABLE"|"OPAQUE_KEEP_ORIGINALS";
  sourceHashes:{conf:string;fragment:string};
  roundTripVerified:boolean;
  knownConversionLoss:false|null;
  unknownContentRisk:boolean;
  requiresOriginalFiles:boolean;
  receiver:{
    sourceCount:number;
    supportedProtocols:string[];
    declaredPorts:number[];
    portConsistencyVerified:boolean;
  };
  issueCodes:InspectionDiagnosticCode[];
  includesSourceText:false;
  deployableNow:false;
  realRuntimeParsingVerified:false;
  targetImportVerified:false;
};
export function buildImportLossReport(source:PairInspectionInput):ImportLossReport{
  const observed=inspectPair(source);
  const exact=observed.importStatus==="EDITABLE_EXACT"&&
    observed.roundTripVerified===true;
  const issueCodes=observed.diagnostics.map(x=>x.code).sort();
  return {
    contract:"parser-import-loss-report.v0.1",
    conversionStatus:exact?"EXACT_EDITABLE":"OPAQUE_KEEP_ORIGINALS",
    sourceHashes:{...observed.originalHashes},
    roundTripVerified:exact,
    knownConversionLoss:exact?false:null,
    unknownContentRisk:!exact,
    requiresOriginalFiles:!exact,
    receiver:{
      sourceCount:observed.receiver.sourceCount,
      supportedProtocols:[...observed.receiver.protocols].sort(),
      declaredPorts:[...observed.receiver.ports].sort((a,b)=>a-b),
      portConsistencyVerified:exact&&observed.receiver.ports.length===1,
    },
    issueCodes,
    includesSourceText:false,
    deployableNow:false,
    realRuntimeParsingVerified:false,
    targetImportVerified:false,
  };
}
