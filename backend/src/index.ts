export { validateProject, canonicalJson, MAX_PROJECT_BYTES } from "./validate.js";
export { compilePair } from "./compiler.js";
export { BACKEND_CAPABILITIES } from "./capabilities.js";
export { inspectPair } from "./import.js";
export type { PairInspection, PairInspectionInput } from "./import.js";
export { createBackendServer } from "./http.js";
export type { ParserProject, FieldType, FieldMap, FieldRule, LogIndex,
  ValidationIssue, ValidationResult, PairExport, ExportManifest, ExportFile } from "./types.js";


export {
  LEGACY_POC_CAPABILITIES, LegacyContractError,
  LegacyUploadPlan, makeLegacyUploadPlan, makeDisposablePocTestPair,
  requireDisposablePocWrite,
} from "./stellar-legacy-plan.js";
export { LegacyPocClient, LegacyApiError } from "./stellar-legacy-client.js";
export type {
  LegacyAuditEvent, LegacyWriteIntent, LegacyPocClientConfig,
  LegacyOperationResult, LegacyParserMetadata, LegacyCatalogueRecord,
} from "./stellar-legacy-client.js";
