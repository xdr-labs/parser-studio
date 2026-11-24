/**
 * Reading one event: extraction and the Parsing Success Contract together.
 *
 * readEvent is what the generated Ruby parser executes for every event (as its translation,
 * scripts/grammar/ts2rb) and what the browser preview grades an event with. A result is a parsed event only
 * when its status is FULL; "the extractor returned no error" is never enough (src/grammar/parseStatus.ts).
 */
import { bodyKindOf, extractStructuredFamily, type StructuredExtraction } from '../structuredFamilies';
import { getTag, matchAt } from './primitives';
import { GRAMMAR_FRAGMENTS } from './syslogHeaderGrammar.generated';
import { cefEventUnaccounted, csvRowUnaccounted, jsonTextUnaccounted, leefEventUnaccounted } from './lossGuard';
import { inspectDeclaredForwarders, type ForwarderHop } from '../guided/declaredForwarder';
import { extractEvent, type ExtractionSettings } from './extractEvent';
import { classifyGenericStructural } from './genericParseStatus';
import { classifyStructuredParse, type ParseVerdict } from './parseStatus';

export interface EventReading {
  fields: Record<string, unknown>;
  errors: string[];
  status: 'FULL' | 'PARTIAL' | 'UNKNOWN' | 'ERROR';
  reasons: string[];
  /** Keys of key=value pairs that are visible in the event text and missing from the fields. */
  lostKeys: string[];
  /** The relay envelopes that were removed, outermost first. */
  forwarderHops: ForwarderHop[];
  /** The family a mixed parser read the event with (src/grammar/extractEvent.ts extractMixed); '' otherwise. */
  family: string;
  /** PARTIAL only because a Syslog message no grammar reads was kept whole as text (owner decision D-2). */
  textKept: boolean;
}

/**
 * What of a CSV, JSON, CEF or LEEF event the fields do not account for (src/grammar/lossGuard.ts); null when
 * the fields spell the text, and for the dialects that have another contract (key=value) or none (raw, regex).
 */
function unaccountedText(raw: string, settings: ExtractionSettings, extraction: StructuredExtraction): string | null {
  const kind = bodyKindOf(extraction);
  if (kind === 'csv') {
    const cells = (settings.csvColumns ?? []).map(name => extraction.fields[name]);
    if (Object.keys(extraction.fields).length !== cells.length) return 'an extracted field is not a CSV column of the row';
    return csvRowUnaccounted(raw, settings.csvDelimiter ?? ',', cells);
  }
  if (kind !== 'json' && kind !== 'cef' && kind !== 'leef') return null;
  // Inside a Syslog envelope the dialect read the message of the envelope, and its fields are under `body`.
  const message = getTag(extraction, 'bodyText');
  const text = typeof message === 'string' ? message : raw;
  const body = typeof message === 'string' ? extraction.fields.body : extraction.fields;
  if (body === null || typeof body !== 'object' || Array.isArray(body)) return 'the fields of the event body are not where the extractor reports them';
  const fields = body as Record<string, unknown>;
  if (kind === 'json') return jsonTextUnaccounted(text, fields);
  return kind === 'cef' ? cefEventUnaccounted(text, fields) : leefEventUnaccounted(text, fields);
}

// Contract fragment structured_family_claim: "CEF" or "LEEF", blanks, ":", blanks, a digit (the Python Multi-Pass
// reader and the Generic Structural route use the same fragment).
const FAMILY_CLAIM = new RegExp(GRAMMAR_FRAGMENTS.structured_family_claim.source, 'yu');

/**
 * Owner decision D-2 (2026-11-25): a Syslog message that claims to be CEF or LEEF (`CEF : 3 alerts today`,
 * `CEF :0|A|...`) but that the CEF/LEEF grammar does not read is not CEF or LEEF. The envelope is read and the
 * message is kept whole as text, but the body is not parsed, so the event is not FULL. The claim is read after a
 * leading BOM, space or tab, like the Python reader. A plain message (`service restarted`, `CEF team meeting`)
 * makes no claim and stays FULL; a valid CEF/LEEF message kept as text by an explicit raw body stays as it was.
 */
function malformedFamilyClaim(settings: ExtractionSettings, extraction: StructuredExtraction): string {
  if (settings.format !== 'syslog_rfc3164' && settings.format !== 'syslog_rfc5424') return '';
  // A raw body is the message itself (RFC 5424 tags it `raw`, the RFC 3164 reader leaves it untagged); a JSON,
  // key=value, CEF, LEEF or regex body is tagged and its fields are under `body`.
  const kind = bodyKindOf(extraction);
  if (kind !== undefined && kind !== 'raw') return '';
  const message = extraction.fields.message;
  if (typeof message !== 'string') return '';
  let start = 0;
  while (start < message.length && (message[start] === '\ufeff' || message[start] === ' ' || message[start] === '\t')) start++;
  const text = message.slice(start);
  const claim = matchAt(FAMILY_CLAIM, text, 0);
  if (claim === null) return '';
  const family = claim.groups!.family === 'LEEF' ? 'leef' : 'cef';
  return extractStructuredFamily(text, family).errors.length > 0 ? claim.groups!.family! : '';
}

/** The verdict on an extraction the caller already holds. */
export function gradeExtraction(raw: string, settings: ExtractionSettings, extraction: StructuredExtraction): ParseVerdict {
  if (settings.format === 'generic_structural') return classifyGenericStructural(raw, extraction);
  // A key=value body is known from the settings (format kv, or Syslog with body kv) or from what the extractor
  // says it parsed (an `auto` body that resolved to key=value, the key=value branches of a mixed allowlist).
  const keyValueBody = settings.format === 'kv' || bodyKindOf(extraction) === 'kv' ||
    ((settings.format === 'syslog_rfc3164' || settings.format === 'syslog_rfc5424') && settings.syslogBodyFormat === 'kv');
  const verdict = classifyStructuredParse(raw, extraction, keyValueBody ? 'kv' : 'other');
  if (verdict.status !== 'FULL') return verdict;
  // "No error and no lost pair" is not yet "nothing lost" for the dialects without key=value accounting.
  const reason = unaccountedText(raw, settings, extraction);
  if (reason !== null) return { status: 'PARTIAL', lostPairs: [], reasons: [reason] };
  const claim = malformedFamilyClaim(settings, extraction);
  if (claim === '') return verdict;
  return { status: 'PARTIAL', lostPairs: [], textKept: true,
    reasons: ['the message claims to be ' + claim + ' but has no valid ' + claim + ' header; it is kept as text'] };
}

export function readEvent(raw: string, settings: ExtractionSettings): EventReading {
  // Only a declared relay host and a complete Syslog envelope qualify for removal; anything else about a
  // relayed event that cannot be replayed exactly declines it.
  const relay = inspectDeclaredForwarders(raw, settings.forwarder);
  if (relay.status === 'ABSTAIN_UNSAFE') {
    const reason = 'The forwarded log cannot be safely unwrapped: ' + relay.reason;
    return { fields: {}, errors: [reason], status: 'UNKNOWN', reasons: [reason], lostKeys: [], forwarderHops: [], family: '', textKept: false };
  }
  const source = relay.status === 'UNWRAPPED' ? relay.payload : raw;
  const extraction = extractEvent(source, settings);
  const verdict = gradeExtraction(source, settings, extraction);
  const family = getTag(extraction, 'mixedFamily');
  return {
    fields: extraction.fields, errors: extraction.errors, status: verdict.status, reasons: verdict.reasons,
    lostKeys: verdict.lostPairs.map(pair => pair.key), forwarderHops: relay.hops,
    family: typeof family === 'string' ? family : '',
    textKept: verdict.textKept === true,
  };
}
