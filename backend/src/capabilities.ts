/**
 * Public shape for the local-only parser backend integration. These are
 * capabilities, not deployment or provenance claims. Keep aligned with the
 * validated ParserProject v0.1 schema and reviewed compiler implementation.
 */
import projectSchema from "../schema/parser-project.v0.1.schema.json" with { type: "json" };
import { MAX_IMPORT_BYTES } from "./import.js";
import { MAX_PROJECT_BYTES } from "./validate.js";

const props = projectSchema.properties;
export const BACKEND_CAPABILITIES = Object.freeze({
  contract: "host-customized-pair.v0.1" as const,
  projectSchemaRevision: "0.1" as const,
  authoring: {
    receiverProtocols: [...props.receiver.properties.protocols.items.enum],
    extractionFormats: [...props.extraction.properties.format.enum],
    httpReceiver: false,
    multipleDistinctReceiverPorts: false,
    formatCoverage: "reviewed-bounded-subset" as const,
    rfc5424AdjacentStructuredDataSubset: true,
    rfc5424StructuredDataMaxBytes: 1024,
    rfc5424BodyFormats: [...props.extraction.properties.syslogBodyFormat.enum],
    leefHexSeparatorSubset: true,
    multiline: false,
    arbitraryRuby: false,
  },
  testLab: {
    offlineJsonPreview: true,
    offlineKvPreview: true,
    offlineCefPreview: true,
    offlineLeefPreview: true,
    offlineSyslogPreview: true,
    syslogPreviewStructuredDataSubset: "nilvalue-only",
    syslogPreviewBodyFormats: ["kv"],
    offlineCsvPreview: true,
    requiresBackendPreviewAuthorization: true,
    trustedSinkSessionControlAvailable: true,
    sessionControlRequiresBackendAuthorization: true,
    scenarioOfflinePreviewAvailable: true,
    multiSampleReplayAvailable: true,
    constantRateScenarioAvailable: true,
    boundedOriginalGapsScenarioAvailable: true,
    scenarioMaxSamples: 12,
    scenarioRunMarkerRequired: true,
    sessionMaxRatePerSecond: 5,
    sessionMaxLeaseMs: 900000,
    sessionMaxAdditionalEventsPerRenewal: 3000,
    sessionMaxCumulativeEvents: 300000,
    sessionRenewalRequiresSeparateApproval: true,
    sessionDurableAcrossRestart: false,
    serverInjectedUdpTcpSinkAvailable: true,
    sinkRequiresIpLiteralAllowlist: true,
    sinkRequiresPerDeliveryPolicyAndAudit: true,
    sensorIngestVerified: false,
    interflowReadClientAvailable: true,
    interflowBoundedPollingAvailable: true,
    interflowMaxPollAttempts: 6,
    interflowMaxPollWindowMs: 15000,
    interflowCursorVerified: false,
    interflowSearchPermissionsVerified: false,
    interflowRealTargetVerified: false,
    liveSensorSenderEnabled: false,
    runtimeParsingVerified: false,
  },
  downloads: {
    individualGeneratedFiles: true,
    zipWithManifest: true,
    requiresDpConnection: false,
    requiresApiKey: false,
    autoDeploys: false,
    exactArtifactRevision: true,
  },
  import: {
    exactInternalPairsEditable: true,
    unknownLegacyRubyEditable: false,
    structuralInspectionOnly: true,
  },
  verification: {
    // Identifies the synthetics-qualified offline runner, NOT a per-project
    // engine/target verification result or vendor loader qualification.
    nativeSyntheticProfile: "ruby3.2.3-fluentd1.17.1" as const,
    liveListenerVerified: false,
    proprietaryLoaderVerified: false,
    targetImportVerified: false,
    engineVerified: false,
  },
  limits: {
    maxInspectBodyBytes: MAX_IMPORT_BYTES,
    maxProjectBodyBytes: MAX_PROJECT_BYTES,
  },
});
