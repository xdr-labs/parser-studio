export type LogIndex = "syslog" | "session" | "threat" | "winlogevent";
export type FieldType = "string" | "integer" | "ip" | "port" | "boolean" | "date";
export type FieldRule = {
  normalized_name: string;
  data_type: FieldType;
  source_path_kind?: 'literal_root' | 'nested';
  when?:{sourcePath:string;operator:'in';values:string[]};
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
  productVersion?: string;
  sourceCategory: "network" | "endpoint" | "cloud" | "application" | "other";
  receiver: {
    protocols: ("udp" | "tcp")[];
    port: number;
    bindAddress: "0.0.0.0" | "127.0.0.1";
    messageLengthLimit: number;
    tcpFraming: "line" | "delimiter" | "blank_line_json" | "blank_line_java";
    delimiter?: string;
  };
  extraction: {
    format: "json" | "kv" | "csv" | "syslog_rfc3164" | "syslog_rfc5424" | "cef" | "leef" | "mixed" | "java_stacktrace" | "regex" | "generic_structural";
    pattern?: string;
    forwarder?: { maxHops: 1 | 2 | 3; relayHosts: string[] };
    mixedFormats?: ("json"|"kv"|"cef"|"leef"|"rfc5424_cef"|"rfc5424_leef"|"rfc3164_kv"|"rfc5424_json"|"rfc5424_kv"|"rfc3164_cef"|"rfc3164_leef"|"csv")[];
    csvColumns?: string[];
    csvDelimiter?: "," | ";" | "\t";
    syslogBodyFormat?: "raw" | "json" | "kv" | "cef" | "leef" | "regex";
    genericStructuralProfile?: "syslog_prefix_kv" | "leef2_implicit_tab" |
      "syslog_prefix_kv_leef2_implicit_tab_v1";
    /** Generic Structural only: leave the full raw line (source_raw) out of parserstudio_source. */
    omitSourceRaw?: true;
    /**
     * Generic Structural only (owner policy D-2). "dedicated": a line that claims to be CEF or LEEF is read by the
     * CEF/LEEF grammar or declined. Absent keeps the V15 legacy route of existing projects.
     */
    genericStructuralFamilyGrammar?: "dedicated";
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
    eventProfiles?: {
      discriminator: string;
      unknown: "reject";
      variants: Array<{
        name: string;
        equals: string;
        topFields: FieldMap;
        nsFields: FieldMap;
        vendorFields: FieldMap;
      }>;
    };
  };
  enrichment?: Array<
    | { operator: "set_const"; target: string; value: string | number | boolean }
    | { operator: "copy" | "lowercase" | "uppercase"; source: string; target: string }
    | { operator: "split_field"; source: string; delimiter: string; targets: string[] }
    | { operator: "merge_fields"; sources: string[]; delimiter: string; target: string }
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
