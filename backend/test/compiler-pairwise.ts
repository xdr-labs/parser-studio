// Deterministic all-pairs (pairwise) coverage of the Compiler's independent
// generation axes. The enumerated list in compiler-variants.ts varies one axis
// at a time; defects that need two axes together (for example CSV together with
// event profiles) only show up here.
//
// How it works, with no hand-picked combinations:
//   1. Every full combination of every level is built and judged by the real
//      validateProject. Valid ones are candidates; invalid ones are the product's
//      own constraints (for example a relay cannot wrap CSV).
//   2. A pair of levels from two factors is "feasible" when at least one valid
//      combination contains it. Pairs no valid combination contains are reported,
//      never silently dropped (the test pins them).
//   3. A greedy cover picks valid combinations until every feasible pair appears
//      in at least one. The result is stable for a given set of levels.
import type { ParserProject } from "../src/types.js";
import { validateProject } from "../src/index.js";
import { sampleProject } from "./fixture.js";

type Edit = (project: ParserProject) => void;
export interface Level { name: string; edit: Edit }
export interface Factor { name: string; levels: Level[] }

const columns = ["alpha", "bravo", "charlie"];
const relay = { maxHops: 1 as const, relayHosts: ["relay01"] };

export const FACTORS: Factor[] = [
  { name: "extraction", levels: [
    { name: "json", edit: p => { p.extraction = { format: "json" }; } },
    { name: "kv", edit: p => { p.extraction = { format: "kv" }; } },
    { name: "cef", edit: p => { p.extraction = { format: "cef" }; } },
    { name: "leef", edit: p => { p.extraction = { format: "leef" }; } },
    { name: "csv", edit: p => { p.extraction = { format: "csv", csvColumns: columns, csvDelimiter: "," }; } },
    { name: "regex", edit: p => { p.extraction = { format: "regex", pattern: "^(?<action>ALLOW)$" }; } },
    { name: "rfc3164-kv", edit: p => { p.extraction = { format: "syslog_rfc3164", syslogBodyFormat: "kv" }; } },
    { name: "rfc5424-json", edit: p => { p.extraction = { format: "syslog_rfc5424", syslogBodyFormat: "json" }; } },
    { name: "mixed-json-kv", edit: p => { p.extraction = { format: "mixed", mixedFormats: ["json", "kv"] }; } },
    { name: "mixed-json-csv", edit: p => { p.extraction = { format: "mixed", mixedFormats: ["json", "csv"], csvColumns: columns, csvDelimiter: "," }; } },
    { name: "generic", edit: p => { p.extraction = { format: "generic_structural" }; } },
  ] },
  { name: "forwarder", levels: [
    { name: "none", edit: () => undefined },
    { name: "relay", edit: p => { p.extraction = { ...p.extraction, forwarder: relay }; } },
  ] },
  { name: "receiver", levels: [
    { name: "udp+tcp", edit: () => undefined },
    { name: "udp", edit: p => { p.receiver.protocols = ["udp"]; } },
    { name: "tcp", edit: p => { p.receiver.protocols = ["tcp"]; } },
    { name: "tcp-delimiter", edit: p => { p.receiver.protocols = ["tcp"]; p.receiver.tcpFraming = "delimiter"; p.receiver.delimiter = "|"; } },
  ] },
  { name: "bind", levels: [
    { name: "all-interfaces", edit: p => { p.receiver.bindAddress = "0.0.0.0"; } },
    { name: "loopback", edit: p => { p.receiver.bindAddress = "127.0.0.1"; } },
  ] },
  { name: "classification", levels: [
    { name: "syslog-only", edit: p => { p.classification = { defaultIndex: "syslog", rules: [] }; } },
    { name: "all-classes", edit: p => { p.classification = { defaultIndex: "syslog", rules: [
      { field: "action", operator: "equals", value: "deny", index: "threat" },
      { field: "srcip", operator: "exists", index: "session" },
      { field: "dstip", operator: "exists", index: "winlogevent" },
    ] }; } },
    { name: "threat-default", edit: p => { p.classification = { defaultIndex: "threat", rules: [] }; } },
  ] },
  { name: "enrichment", levels: [
    { name: "none", edit: p => { p.enrichment = []; } },
    { name: "set_const", edit: p => { p.enrichment = [{ operator: "set_const", target: "log.constant", value: "fixed" }]; } },
    { name: "copy", edit: p => { p.enrichment = [{ operator: "copy", source: "action", target: "log.action_copy" }]; } },
    { name: "split_field", edit: p => { p.enrichment = [{ operator: "split_field", source: "action", delimiter: ":", targets: ["log.action_head", "log.action_tail"] }]; } },
  ] },
  { name: "event-profiles", levels: [
    { name: "none", edit: () => undefined },
    { name: "two-families", edit: p => {
      p.normalization.eventProfiles = { discriminator: "event_type", unknown: "reject", variants: [
        { name: "security", equals: "security", topFields: { "user.name": { normalized_name: "username", data_type: "string" } }, nsFields: {}, vendorFields: {} },
        { name: "other", equals: "other", topFields: { "host.name": { normalized_name: "hostname", data_type: "string" } }, nsFields: {}, vendorFields: {} },
      ] };
    } },
  ] },
];

export interface PairwiseVariant { id: string; axis: "pairwise"; levels: string[]; project: ParserProject }
export interface PairwiseReport {
  combinations: number;
  valid: number;
  /** "factorA=levelA & factorB=levelB" pairs that no valid combination contains. */
  infeasiblePairs: string[];
  variants: PairwiseVariant[];
}

function build(indices: number[]): ParserProject {
  const project = sampleProject();
  indices.forEach((levelIndex, factorIndex) => FACTORS[factorIndex]!.levels[levelIndex]!.edit(project));
  return project;
}

const pairKey = (fa: number, la: number, fb: number, lb: number) => fa + ":" + la + "|" + fb + ":" + lb;
function pairsOf(indices: number[]): string[] {
  const out: string[] = [];
  for (let a = 0; a < indices.length; a++)
    for (let b = a + 1; b < indices.length; b++) out.push(pairKey(a, indices[a]!, b, indices[b]!));
  return out;
}

export function pairwiseReport(): PairwiseReport {
  const sizes = FACTORS.map(f => f.levels.length);
  const valid: number[][] = [];
  let combinations = 0;
  const cursor = sizes.map(() => 0);
  for (;;) {
    combinations += 1;
    if (validateProject(build(cursor)).ok) valid.push([...cursor]);
    let at = sizes.length - 1;
    while (at >= 0 && ++cursor[at]! === sizes[at]) { cursor[at] = 0; at -= 1; }
    if (at < 0) break;
  }
  const feasible = new Set<string>();
  for (const tuple of valid) for (const key of pairsOf(tuple)) feasible.add(key);
  const infeasiblePairs: string[] = [];
  for (let a = 0; a < sizes.length; a++)
    for (let b = a + 1; b < sizes.length; b++)
      for (let la = 0; la < sizes[a]!; la++)
        for (let lb = 0; lb < sizes[b]!; lb++)
          if (!feasible.has(pairKey(a, la, b, lb)))
            infeasiblePairs.push(FACTORS[a]!.name + "=" + FACTORS[a]!.levels[la]!.name + " & " + FACTORS[b]!.name + "=" + FACTORS[b]!.levels[lb]!.name);

  const uncovered = new Set(feasible);
  const chosen: number[][] = [];
  while (uncovered.size) {
    let best = -1;
    let bestGain = 0;
    valid.forEach((tuple, index) => {
      const gain = pairsOf(tuple).filter(key => uncovered.has(key)).length;
      if (gain > bestGain) { best = index; bestGain = gain; }
    });
    if (best < 0) throw new Error("PAIRWISE_COVER_STALLED");
    chosen.push(valid[best]!);
    for (const key of pairsOf(valid[best]!)) uncovered.delete(key);
  }
  const variants = chosen.map((tuple, index) => {
    const levels = tuple.map((levelIndex, factorIndex) => FACTORS[factorIndex]!.name + "=" + FACTORS[factorIndex]!.levels[levelIndex]!.name);
    return { id: "pairwise:" + String(index + 1).padStart(2, "0") + ":" + levels.join(","), axis: "pairwise" as const, levels, project: build(tuple) };
  });
  return { combinations, valid: valid.length, infeasiblePairs: infeasiblePairs.sort(), variants };
}

let cached: PairwiseReport | undefined;
export function pairwiseVariants(): PairwiseVariant[] {
  cached ??= pairwiseReport();
  return cached.variants.map(variant => ({ ...variant, project: structuredClone(variant.project) }));
}
