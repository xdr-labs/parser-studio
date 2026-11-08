import { createHash } from "node:crypto";
import { compilePair } from "./compiler.js";
import { validateProject } from "./validate.js";
import type { ParserProject } from "./types.js";

export const MAX_IMPORT_BYTES = 2 * 1024 * 1024;
const PAIR_NAME = /^customized_[a-z][a-z0-9_]{1,47}$/;
type KnownProtocol = "udp" | "tcp" | "http";

export interface PairInspectionInput {
  name: string;
  confContent: string;
  fragmentContent: string;
}
export type PairInspectionErrorCode = "PAIR_NAME_INVALID" | "PAIR_CONTENT_INVALID" | "PAIR_SIZE_EXCEEDED";
export class PairInspectionError extends Error {
  constructor(readonly code: PairInspectionErrorCode, message: string) {
    super(message);
    this.name = "PairInspectionError";
  }
}
export type InspectionDiagnosticCode =
  | "CONF_NO_SOURCE" | "CONF_UNSUPPORTED_PROTOCOL" | "CONF_INVALID_PORT"
  | "CONF_SOURCE_MISMATCH" | "CONF_SOURCE_MISSING_REFERENCE"
  | "CONF_RECEIVER_NOT_EDITABLE" | "CONF_MULTI_PORT_LAYOUT"
  | "RUBY_MARKERS_INCOMPLETE" | "RUBY_PARSE_ENTRY_MISSING" | "PAIR_NOT_REPRODUCIBLE";

export interface PairInspectionDiagnostic {
  code: InspectionDiagnosticCode;
  severity: "warning";
  message: string;
}
export interface PairInspection {
  format: "host-customized-pair";
  name: string;
  originalHashes: { conf: string; fragment: string };
  receiver: { protocols: KnownProtocol[]; ports: number[]; sourceCount: number };
  fragment: { markersComplete: boolean; hasParseEntry: boolean; opaqueRuby: boolean };
  importStatus: "EDITABLE_EXACT" | "OPAQUE_READ_ONLY";
  roundTripVerified: boolean;
  portableProject: ParserProject | null;
  diagnostics: PairInspectionDiagnostic[];
  /** Legacy display convenience; clients should branch on diagnostics[].code. */
  warnings: string[];
}

function sha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}
function warn(diagnostics: PairInspectionDiagnostic[], code: InspectionDiagnosticCode, message: string): void {
  if (!diagnostics.some(item => item.code === code)) diagnostics.push({ code, severity: "warning", message });
}

const markerOrder = [
  "# STELLAR_INIT_BEGIN", "# STELLAR_INIT_END",
  "# STELLAR_PARSE_BEGIN", "# STELLAR_PARSE_END",
] as const;
function markerComplete(fragment: string): boolean {
  // Strict comment-only marker lines, not their names inside arbitrary strings.
  const lines = fragment.split(/\r?\n/).map(line => line.trim());
  const indexes = markerOrder.map(marker => lines.indexOf(marker));
  return indexes.every(index => index >= 0) &&
    indexes.every((index, i) => i === 0 || index > indexes[i - 1]!) &&
    markerOrder.every(marker => lines.lastIndexOf(marker) === lines.indexOf(marker));
}

function directive(text: string, key: "@type" | "port" | "tag"): string | undefined {
  for (const line of text.split(/\r?\n/)) {
    const match = line.match(/^[ \t]*(@type|port|tag)[ \t]+([^#\r\n]+?)[ \t]*(?:#.*)?$/);
    if (match && match[1] === key) return match[2]!.trim();
  }
  return undefined;
}

/** Parse only a bounded, comment-stripped structural subset of Fluentd CONF. */
function parseConfSource(conf: string, pairName: string, diagnostics: PairInspectionDiagnostic[]): {
  protocols: KnownProtocol[]; ports: number[]; count: number;
} {
  const uncommented = conf.replace(/^[ \t]*#.*$/gm, "");
  const sources = [...uncommented.matchAll(/^[ \t]*<source>[ \t]*\r?\n([\s\S]*?)^[ \t]*<\/source>[ \t]*$/gm)];
  const protocols: KnownProtocol[] = [];
  const ports: number[] = [];
  if (sources.length === 0) {
    warn(diagnostics, "CONF_NO_SOURCE", "No Fluentd source section was identified.");
  }
  for (const match of sources) {
    const source = match[1]!;
    const outsideParse = source.replace(/^[ \t]*<parse>[ \t]*\r?\n[\s\S]*?^[ \t]*<\/parse>[ \t]*$/gm, "");
    const type = directive(outsideParse, "@type");
    if (type === "udp" || type === "tcp" || type === "http") {
      if (!protocols.includes(type)) protocols.push(type);
      if (type === "http") {
        warn(diagnostics, "CONF_RECEIVER_NOT_EDITABLE", "HTTP receiver is visible for inspection but not supported in the current no-code receiver model.");
      }
    } else {
      warn(diagnostics, "CONF_UNSUPPORTED_PROTOCOL", "Source protocol is unknown or not recognized.");
    }
    const rawPort = directive(outsideParse, "port");
    const port = rawPort && /^[0-9]{1,5}$/.test(rawPort) ? Number(rawPort) : NaN;
    if (Number.isInteger(port) && port >= 1 && port <= 65535) {
      if (!ports.includes(port)) ports.push(port);
    } else {
      warn(diagnostics, "CONF_INVALID_PORT", "Source port is missing or outside the valid range.");
    }
    const tag = directive(outsideParse, "tag");
    const parses = [...source.matchAll(/^[ \t]*<parse>[ \t]*\r?\n([\s\S]*?)^[ \t]*<\/parse>[ \t]*$/gm)];
    if (!tag || parses.length === 0) {
      warn(diagnostics, "CONF_SOURCE_MISSING_REFERENCE", "Source tag or parse section is missing.");
    }
    if ((tag && tag !== pairName) ||
        parses.some(parse => {
          const parserType = directive(parse[1]!, "@type");
          return parserType !== pairName;
        })) {
      warn(diagnostics, "CONF_SOURCE_MISMATCH", "CONF source parser/tag is inconsistent with the provided pair name.");
    }
  }
  if (ports.length > 1) {
    warn(diagnostics, "CONF_MULTI_PORT_LAYOUT", "Legacy sources use multiple distinct ports; the current no-code receiver model supports one shared port.");
  }
  return { protocols, ports, count: sources.length };
}

function tryRoundTrip(input: PairInspectionInput): ParserProject | null {
  // Do not evaluate Ruby. Select only the canonical project assignment;
  // other compiler-owned Base64 payloads (for example pinned Unicode data)
  // are not project candidates. Exact regeneration still verifies both files.
  const matches = [...input.fragmentContent.matchAll(/^[ \t]*@parser_rule_set = JSON\.parse\(Base64\.strict_decode64\('([A-Za-z0-9+/=]+)'\)\)[ \t]*$/gm)];
  if (matches.length !== 1 || !matches[0]?.[1]) return null;
  try {
    const value: unknown = JSON.parse(Buffer.from(matches[0][1], "base64").toString("utf8"));
    if (!validateProject(value).ok) return null;
    const artifact = compilePair(value);
    if (artifact.files[0]?.name !== input.name + ".conf" || artifact.files[1]?.name !== input.name) return null;
    if (artifact.files[0]?.content !== input.confContent || artifact.files[1]?.content !== input.fragmentContent) return null;
    return value as ParserProject;
  } catch {
    return null;
  }
}

/** Read-only in-memory inspection: never eval, log, persist or echo source bytes. */
export function inspectPair(input: PairInspectionInput): PairInspection {
  if (!input || typeof input.name !== "string" || !PAIR_NAME.test(input.name)) {
    throw new PairInspectionError("PAIR_NAME_INVALID", "Invalid parser pair name; expected a valid customized_<slug> filename.");
  }
  if (typeof input.confContent !== "string" || typeof input.fragmentContent !== "string") {
    throw new PairInspectionError("PAIR_CONTENT_INVALID", "Both parser file contents must be UTF-8 strings.");
  }
  const count = Buffer.byteLength(input.confContent, "utf8") + Buffer.byteLength(input.fragmentContent, "utf8");
  if (count > MAX_IMPORT_BYTES) {
    throw new PairInspectionError("PAIR_SIZE_EXCEEDED", "Import size limit exceeded (2 MiB combined parser source).");
  }
  const diagnostics: PairInspectionDiagnostic[] = [];
  const receiver = parseConfSource(input.confContent, input.name, diagnostics);
  const markersComplete = markerComplete(input.fragmentContent);
  const hasParseEntry = /^[ \t]*def[ \t]+parse[ \t]*\([ \t]*text[ \t]*\)/m.test(input.fragmentContent);
  if (!markersComplete) {
    warn(diagnostics, "RUBY_MARKERS_INCOMPLETE", "Ruby source has incomplete or duplicate STELLAR section markers.");
  }
  if (!hasParseEntry) {
    warn(diagnostics, "RUBY_PARSE_ENTRY_MISSING", "Ruby source entry point parse(text) was not found.");
  }
  const editable = tryRoundTrip(input);
  if (editable === null) {
    warn(diagnostics, "PAIR_NOT_REPRODUCIBLE", "Source is not byte-for-byte reproducible from a validated internal project; imported Ruby remains opaque and read-only.");
  }
  return {
    format: "host-customized-pair",
    name: input.name,
    originalHashes: { conf: sha256(input.confContent), fragment: sha256(input.fragmentContent) },
    receiver: { protocols: receiver.protocols, ports: receiver.ports, sourceCount: receiver.count },
    fragment: { markersComplete, hasParseEntry, opaqueRuby: editable === null },
    importStatus: editable ? "EDITABLE_EXACT" : "OPAQUE_READ_ONLY",
    roundTripVerified: editable !== null,
    portableProject: editable,
    diagnostics,
    warnings: diagnostics.map(item => item.message),
  };
}
