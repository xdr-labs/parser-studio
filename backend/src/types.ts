export type LogIndex = "syslog" | "session" | "threat" | "winlogevent";
export type FieldType = "string" | "integer" | "ip" | "port" | "boolean" | "date";
export type FieldRule = {
  normalized_name: string;
  data_type: FieldType;
  time_format?: "iso8601";
  timezone?: "UTC";
};
export type FieldMap = Record<string, FieldRule>;
export interface ParserProject {
  schemaRevision: "0.1";
  projectId: string;
  revision: number;
  slug: string;
  vendor: string;
  product: string;
  sourceCategory: "network" | "endpoint" | "cloud" | "application" | "other";
  receiver: {
    protocols: ("udp" | "tcp")[];
    port: number;
    bindAddress: "0.0.0.0" | "127.0.0.1";
    messageLengthLimit: number;
    tcpFraming: "line" | "delimiter";
    delimiter?: string;
  };
  extraction: {
    format: "json" | "kv" | "csv" | "syslog_rfc3164" | "syslog_rfc5424" | "cef" | "leef";
    csvColumns?: string[];
    csvDelimiter?: "," | ";" | "\t";
    syslogBodyFormat?: "raw" | "json" | "kv" | "cef" | "leef";
    maxDepth?: number;
  };
  normalization: {
    msgOriginSource: string;
    msgClass: string;
    msgOriginCategory: string;
    ignoreValues: string[];
    topFields: FieldMap;
    nsFields: FieldMap;
    vendorFields: FieldMap;
  };
  enrichment?: Array<
    | { operator: "set_const"; target: string; value: string | number | boolean }
    | { operator: "copy" | "lowercase" | "uppercase"; source: string; target: string }
  >;
  classification: {
    defaultIndex: LogIndex;
    rules: Array<{
      field: string;
      operator: "equals" | "exists";
      value?: string | number | boolean;
      index: LogIndex;
    }>;
  };
  unsupportedOpaqueBlocks?: Array<Record<string, unknown>>;
}
export type ValidationIssue = {
  code: string;
  path: string;
  message: string;
};
export type ValidationResult = { ok: boolean; issues: ValidationIssue[] };
export type ExportFile = {
  name: string;
  content: string;
  sha256: string;
  bytes: number;
};
export type ExportManifest = {
  status: "DRAFT";
  contract: "host-customized-pair.v0.1";
  projectId: string;
  projectRevision: number;
  fileHashes: Record<string, string>;
  schemaRevision: "0.1";
  engineVerified: false;
  targetImportVerified: false;
  warnings: string[];
};
export type PairExport = {
  contract: "host-customized-pair.v0.1";
  files: ExportFile[];
  manifest: ExportManifest;
};
