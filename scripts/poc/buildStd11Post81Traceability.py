#!/usr/bin/env python3
"""Reconcile committed standards evidence without silently changing old oracles.

Every stored SHA is pre-registered, never computed into the expected values.
The generated ledger is a point-in-time source-only inventory, not certification.
"""
from pathlib import Path
import hashlib
import json

ROOT = Path(__file__).resolve().parents[2]
SHA = lambda content: hashlib.sha256(content).hexdigest()
BASE_SOURCE = "309189334fcfd3328c4dc15be11a30c3645de34c"
OLD_LEDGER = "scripts/poc/standardCrossFamilyEvidenceLedger.v1.json"
OLD_LEDGER_SHA = "5de2502812b4e8b8f587a91af825c4e526736f179d26e8b9f28da2016075325e"
INITIAL_LEDGER = "scripts/poc/standardCoverageLedger.v1.json"
INITIAL_LEDGER_SHA = "33d3ea9be0d98b77119bd199c2deabffd51afdb59f8a6fc57f3d1cbefb5ecc4c"
AUTHORITY = "scripts/poc/normativeGrammarSources.pinned.json"
AUTHORITY_SHA = "401ea5dd49f89e9ef96abf894d50237b054a0ae4f54b8a548476ddde03355b12"

def row(
    pr, head, stage, sections, code, tests, oracle, sha, count, evidence,
    risk, finding, remaining, disposition="REVIEW_ONLY_OR_ABSTAIN",
):
    return {
      "pr":pr, "exactHead":head, "ciObserved":"SUCCESS",
      "roadmapStage":stage, "sections":sections,
      "codePaths":code, "testPaths":tests,
      "pinnedOracle":oracle, "pinnedOracleSha256":sha,
      "frozenCases":count, "evidenceClass":evidence,
      "impactRisk":risk, "finding":finding, "stillUnverified":remaining,
      "sourceDisposition":disposition, "owner":"CHATGPT_CHAT_SOURCE_ONLY",
      "productIntegrated":False, "manufacturerWireCertified":False,
      "nativeVerified":False, "autoPromotionAuthorized":False
    }

SYN="INDEPENDENT_STANDARDS_DERIVED_SYNTHETIC"
DOC="PUBLISHER_DOCUMENTATION_ILLUSTRATION_NOT_DEVICE_CAPTURE"
COMPOSE="CROSS_FAMILY_SAFETY_REPLAY_NO_NEW_ORACLE"
S5424=["RFC5424", "RFC6587"]
rows=[
  row(69,"f9542b0bd3f6404de57ab68de0686c318390639a","STD-9",
      [{"id":"CEF26","section":"publisher header and extension documentation"}],
      ["src/cefStandardHeaderGrammar.ts","src/cefStandardExtensionGrammar.ts"],
      ["src/poc/standard9PublisherCefOraclePin.test.ts"],
      "scripts/poc/standard9PublisherCefExamples.pinned.json",
      "c4384572021d05515f7a92918c4f00618eb0acf3e15637172be0adceaa4b4882",2,DOC,"HIGH",
      "Published CEF illustrative source byte expectations pinned separately.",
      "Not manufacturer-produced live wire, escaped producer variants or native parsing."),
  row(70,"981996fac77c881c5b382db605809ab9cccba617","STD-3/9",
      [{"id":"CEF26","section":"extension escaped values and field separators"}],
      ["src/cefStandardExtensionGrammar.ts","src/structuredFamilies.ts",
       "src/poc/independentNonJsonStructural.ts"],
      ["src/poc/standardCefPublisherEscapesPin.test.ts",
       "src/poc/standardCefExtensionSourceParity.test.ts"],
      "scripts/poc/standardCefPublisherEscapes.pinned.json",
      "ec43bbf61e211e693cff40ce813a289863743396a64b164194cfc65fe16f7309",4,DOC,"HIGH",
      "Shared CEF extension raw/decoded boundaries avoid quoted and key-looking false splits.",
      "Publisher illustration is not cross-firmware producer-wire or native semantics."),
  row(71,"07403224b8793a2098deae0794e9f7dff1583183","STD-2",
      [{"id":"RFC5424","section":"6.3 structured data and source ownership"}],
      ["src/syslogEnvelope.ts","src/poc/rfc5424SdByteEscapes.ts"],
      ["src/poc/standardRfc5424OuterObserverParity.test.ts"],
      "scripts/poc/standardRfc5424OuterObserverParity.pinned.json",
      "acc3e484221c9edb48c3952d3c4b7e023c4ecae86433974f80110ea900dee4db",14,SYN,"HIGH",
      "Distinguish syntactic SD validity from unverified ownership of the original message.",
      "Actual producer and independently attested source/relay ownership unverified."),
  row(72,"b058f4f2e721251a42353ea699b82b76c510c8b9","STD-2",
      [{"id":"RFC5424","section":"6.2.1 VERSION and 6.2.3 TIMESTAMP"}],
      ["src/syslogEnvelope.ts","src/rfc5424Subset.ts"],
      ["src/poc/standardRfc5424TimeVersionParity.test.ts"],
      "scripts/poc/standardRfc5424TimeVersion.pinned.json",
      "2a281fccd420261d1387569a1d73ef7a8984b9ab33fb2ff711f0bac6eba0eced",14,SYN,"HIGH",
      "Guard invalid RFC5424 version/timestamp and fractional precision at shared boundaries.",
      "Source clocks, producer timezone truth and native interpretation remain unverified."),
  row(73,"b998025ad02e2f6411b6be672fabb8ddaaf6b7b9","STD-7",
      [{"id":"ZEEK","section":"logging framework #fields/#types/#close and rotation"}],
      ["src/zeekTabular.ts"],
      ["src/poc/standardZeekRotationSource.test.ts"],
      "scripts/poc/standardZeekRotationStream.pinned.json",
      "6415e09bafa6ecac25889c1a882d5b6c9f9017b47f77a246039d80b4f030e7ee",13,SYN,"MEDIUM",
      "Close and schema transitions preserve original Zeek source spans.",
      "Captured version-specific publisher stream and native backend proof missing."),
  row(74,"20b8aa7a7b1990eeb942aef1c947af6f03b0b672","STD-7",
      [{"id":"W3CLOG","section":"Extended Log Format Version and Fields directives"}],
      ["src/w3cTabular.ts"],
      ["src/poc/standardW3cRequiredDeclarations.test.ts"],
      "scripts/poc/standardW3cRequiredDeclarations.pinned.json",
      "c51f6586c0d74c1bb3d968b5d38cc71131032d435d40eb280c15224ea5350984",18,SYN,"HIGH",
      "Prevent data rows without required W3C v1 declarations from passing extraction.",
      "Publisher schema rotation and native fields not fully qualified."),
  row(75,"67e267625b2b73f19a960c08afd5d02033fed406","STD-10/11",
      [{"id":"RFC5424","section":"6 source grammar composition"},
       {"id":"CEF26","section":"extension composition"},
       {"id":"W3CLOG","section":"declared block composition"}],
      ["src/poc/standardSourceCompletenessGate.ts","src/structuredFamilies.ts"],
      ["src/poc/standardCrossFamilyConvergence.test.ts"],
      None,None,0,COMPOSE,"MEDIUM",
      "Post-audit CEF, RFC5424, Zeek and W3C changes compose on one source SHA.",
      "Integration tests are not a new independent oracle or native qualification.",
      "REGRESSION_ONLY"),
  row(76,"e5f08ac85d9de52e3fc6bccec8d6e5ede4bd2617","STD-5",
      [{"id":"RFC8259","section":"4 object members, 6 numbers, 8 strings"},
       {"id":"RFC7464","section":"2 JSON text sequences"}],
      ["src/standardSourceCompletenessGate.ts"],
      ["src/poc/standardJsonNestedOriginalSpans.test.ts"],
      "scripts/poc/standardJsonNestedOriginalSpans.pinned.json",
      "03c6e1ae49a5cfb2c2c034d4ae584e777115acecdb08d006928286ff1db614e0",18,SYN,"HIGH",
      "Nested JSON Pointer and raw UTF-8 span tracking without parsed-tree reserialization.",
      "Complete independent manufacturer JSON event values and native arrays unverified."),
  row(77,"71b19c002b03a3233b3475653dbc1e0e3eddabb1","STD-6",
      [{"id":"RFC4180","section":"2 quoted field, escaped quote, CR/LF row grammar"}],
      ["src/rfc4180Csv.ts","src/utf8OriginalByteOffsets.ts"],
      ["src/poc/standardCsvMultilineOriginalSpans.test.ts"],
      "scripts/poc/standardCsvMultilineOriginalSpans.pinned.json",
      "25c3f27ff07e13e37bf7ff78ad8fe05bac15143a496db61e5a7e9a95fe4eebff",22,SYN,"HIGH",
      "Preserve multiline CSV logical records, raw lexemes, exact original UTF-8 offsets and blanks.",
      "Producer column semantics and actual forwarded CSV native records unverified."),
  row(78,"66c234c6b83800cc9870869690fb254b7951ab67","STD-1/2",
      [{"id":"RFC5424","section":"6 header fields and claimed origin"},
       {"id":"RFC5425","section":"4 authenticated transport hop"},
       {"id":"RFC3164","section":"4 legacy relay/header limitations"}],
      ["src/poc/standardRelayProvenanceReview.ts","src/syslogEnvelope.ts"],
      ["src/poc/standardRelayProvenanceReview.test.ts"],
      "scripts/poc/standardRelayProvenanceReview.pinned.json",
      "d22ba4469494deb3394ececb09a075acc8043cbbac7c843681614bb7b064253a",17,SYN,"HIGH",
      "Distinguish one-hop lexical byte matches from authenticated source host/time.",
      "Matched upstream and relay device captures, attested clock and TLS peers absent."),
  row(79,"0be503d485b8bd235c194d38684d003da7ef29b5","STD-4",
      [{"id":"LEEF20","section":"attributes, delimiters and repeated source keys"}],
      ["src/poc/independentLeefSource.ts","src/structuredFamilies.ts"],
      ["src/poc/standardLeefEmptySourceSemantics.test.ts"],
      "scripts/poc/standardLeefEmptySourceSemantics.pinned.json",
      "e6b0c14dddb51a67833009e9336c0351dc0558c0306c8b9f7cb69eb9d065918a",15,SYN,"HIGH",
      "Keep explicit zero-byte lexical values distinct from missing keys and preserve occurrences.",
      "Producer-specific empty/null and QRadar/Stellar repeated-key meaning unverified."),
  row(80,"615f1f87e86c456dc9bd3897397a09709b5c1e0e","STD-1/2",
      [{"id":"RFC6587","section":"3.4.1 octet-counted framing"},
       {"id":"RFC5424","section":"6.4 MSG-ANY and MSG-UTF8"}],
      ["src/syslogFraming.ts","src/syslogEnvelope.ts","src/rfc5424Subset.ts",
       "src/poc/standardCountedRfc5424MsgSource.ts"],
      ["src/poc/standardCountedRfc5424MsgSource.test.ts"],
      "scripts/poc/standardCountedRfc5424MsgSource.pinned.json",
      "c43c7b0f604777f12ce5491206ec0295e3975310e44f1042c6b373fb27011852",22,SYN,"HIGH",
      "Allow control octets in RFC5424 MSG only when octet-counted boundary is independently qualified.",
      "Opaque non-UTF8 original bytes and native target remain separate acceptance gates."),
  row(81,"309189334fcfd3328c4dc15be11a30c3645de34c","STD-1/2",
      [{"id":"RFC5424","section":"6.4 MSG-ANY octets and BOM-tagged MSG-UTF8"},
       {"id":"RFC6587","section":"3.4.1 exact frame size in OCTETS"}],
      ["src/syslogFraming.ts","src/poc/rfc5424SdByteEscapes.ts",
       "src/poc/standardOpaqueRfc5424MsgBytes.ts"],
      ["src/poc/standardOpaqueRfc5424MsgBytes.test.ts"],
      "scripts/poc/standardOpaqueRfc5424MsgBytes.pinned.json",
      "60f1234f32bf993aaeab1ff7d09168123cadd6edca63898f33adb3a2780cb902",24,SYN,"HIGH",
      "Preserve arbitrary non-UTF8 MSG-ANY bytes; strict valid UTF8 required only when BOM declares it.",
      "Full original device wire, native Fluentd/Stellar and decoded message semantics unverified."),
]


ANCHORS={
  69:("src/cefStandardHeaderGrammar.ts","scanCefStandardHeaderGrammar"),
  70:("src/cefStandardExtensionGrammar.ts","scanCefStandardExtensions"),
  71:("src/syslogEnvelope.ts","parseSyslogEnvelope"),
  72:("src/rfc5424Subset.ts","parseRfc5424Subset"),
  73:("src/zeekTabular.ts","parseZeekTsvBlock"),
  74:("src/w3cTabular.ts","parseW3cLogBlock"),
  75:("src/structuredFamilies.ts","extractStructuredFamily"),
  76:("src/standardSourceCompletenessGate.ts","inspectSourceCompleteness"),
  77:("src/rfc4180Csv.ts","parseRfc4180HeaderCsv"),
  78:("src/poc/standardRelayProvenanceReview.ts","reviewNestedSyslogProvenance"),
  79:("src/poc/independentLeefSource.ts","arbitrateIndependentLeef"),
  80:("src/poc/standardCountedRfc5424MsgSource.ts","inspectCountedRfc5424MsgStream"),
  81:("src/poc/standardOpaqueRfc5424MsgBytes.ts","inspectOpaqueCountedRfc5424Source"),
}
# Versioned baseline statuses stay immutable, but their current narrow
# remediations/unresolved qualifications must be explicitly reconciled.
RECONCILE={
 "STD-1-RFC6587-FRAMING":([80,81],"BYTE_FRAMING_NARROWLY_FIXED_TLS_NATIVE_NOT_VERIFIED"),
 "STD-2-RFC3164-ENVELOPE":([78],"RELAY_ORIGIN_UNATTESTED"),
 "STD-2-RFC5424-SD":([71,72,80,81],"SHARED_SOURCE_SEMANTICS_NARROWLY_GATED"),
 "STD-3-CEF-BROWSER-EXT":([70],"ESCAPE_SOURCE_LEXEMES_NARROWLY_VERIFIED"),
 "STD-3-CEF-SOURCE-BYTE-DIVERGENCE":([69,70],"CEF_SOURCE_OBSERVER_NARROWLY_CONVERGED"),
 "STD-3-CEF-REQUIRED-HEADER":([],"COVERED_IN_PRIOR_BASE_NO_NATIVE_PROOF"),
 "STD-4-LEEF2-CUSTOM-DELIMITER":([79],"DECLARED_DELIMITERS_PRIOR_BASE_EMPTY_SEMANTICS_UNVERIFIED"),
 "STD-5-JSON-DUPLICATE-MEMBER":([76],"LOSSLESS_NESTED_SOURCES_ONLY_PUBLISHER_PENDING"),
 "STD-5-JSON-NUMERIC":([76],"LOSSLESS_NUMBER_SOURCE_ONLY_PUBLISHER_PENDING"),
 "STD-5-JSON-UNICODE":([76],"NESTED_UTF8_SOURCE_ONLY_PUBLISHER_PENDING"),
 "STD-5-RFC7464-SEQ":([],"OLDER_BOUNDED_JSON_SEQUENCE_NATIVE_NOT_VERIFIED"),
 "STD-6-RFC4180-STRICT":([77],"MULTILINE_SOURCE_INTERVALS_NARROWLY_GATED"),
 "STD-6-CSV-EDGE-SPACES":([77],"STRICT_SPACE_SOURCE_NARROWLY_GATED_PRODUCER_SCHEMA_UNKNOWN"),
 "STD-7-KV-UNCONSUMED-RAW":([],"EARLIER_KV_SOURCE_GATE_PUBLISHER_PENDING"),
 "STD-7-KV-UNKNOWN-ESCAPE":([],"ESCAPE_POLICY_UNVERIFIED_BY_PRODUCER"),
 "STD-7-W3C-ZEEK-DECLARED":([73,74],"SCHEMA_ROTATION_NARROWLY_GATED_REAL_WIRE_PENDING"),
 "STD-8-FUNNEL-CONFLICT":([75],"CONVERGENCE_REGRESSION_ONLY_NATIVE_ARBITRATION_OPEN"),
 "STD-9-INDEPENDENT-PROVENANCE":([69,78],"PUBLISHER_DOC_AND_RELAY_SYNTHETIC_NOT_DEVICE_WIRE"),
 "STD-NATIVE-CONTRACT":([],"NATIVE_TARGET_NOT_VERIFIED"),
}

def function_line(path,symbol):
    lines=(ROOT/path).read_text().splitlines()
    matches=[i+1 for i,line in enumerate(lines)
        if ("function "+symbol+"(" in line) or
           ("function "+symbol+"<" in line) or
           ("const "+symbol+"=" in line)]
    assert len(matches)==1, "Missing/ambiguous source symbol "+path+":"+symbol
    return matches[0]
for item in rows:
    file,symbol=ANCHORS[item["pr"]]
    assert file in item["codePaths"], "Source anchor not in code paths"
    item["functionAnchor"]={"path":file,"symbol":symbol,
      "line":function_line(file,symbol)}

def file_sha(name):
    return SHA((ROOT/name).read_bytes())
for file,expected in [
    (OLD_LEDGER,OLD_LEDGER_SHA),
    (INITIAL_LEDGER,INITIAL_LEDGER_SHA),
    (AUTHORITY,AUTHORITY_SHA),
]:
    assert file_sha(file)==expected, "Frozen baseline ledger changed: "+file

authorities=json.loads((ROOT/AUTHORITY).read_text())
valid_refs=set(x["id"] for x in authorities["sources"])
old=json.loads((ROOT/OLD_LEDGER).read_text())
assert len(old["evidence"])==11, "Baseline old ledger shape changed"
initial=json.loads((ROOT/INITIAL_LEDGER).read_text())
assert {x["id"] for x in initial["entries"]}==set(RECONCILE), "Baseline coverage not fully reconciled"
assert [r["pr"] for r in rows]==list(range(69,82))
assert len({r["exactHead"] for r in rows})==13
counts={SYN:0,DOC:0,COMPOSE:0}
for r in rows:
    assert r["ciObserved"]=="SUCCESS" and len(r["exactHead"])==40
    assert r["stillUnverified"] and r["finding"] and r["impactRisk"] in ("HIGH","MEDIUM")
    assert all(s["id"] in valid_refs and s["section"] for s in r["sections"])
    for f in r["codePaths"]+r["testPaths"]:
        assert (ROOT/f).is_file(), "Missing code or test path: "+f
    if r["pinnedOracle"] is None:
        assert r["pr"]==75 and r["evidenceClass"]==COMPOSE and r["frozenCases"]==0
    else:
        assert file_sha(r["pinnedOracle"])==r["pinnedOracleSha256"], "Oracle mutated: "+r["pinnedOracle"]
        assert len(json.loads((ROOT/r["pinnedOracle"]).read_text())["cases"])==r["frozenCases"]
    counts[r["evidenceClass"]]+=r["frozenCases"]

reconciled=[{
  "id":item["id"],
  "originalFindingStatus":item["status"],
  "risk":item["risk"],
  "sourceOnlyFollowupPRs":RECONCILE[item["id"]][0],
  "currentQualifiedInterpretation":RECONCILE[item["id"]][1],
  "nativeVerified":False,
} for item in initial["entries"]]
summary={
  "contract":"parserstudio.p0-std-post81-source-evidence-addendum.v1",
  "sourceBaseExactHead":BASE_SOURCE,
  "scope":"PREVIOUSLY_VERIFIED_SOURCE_GRAMMAR_AND_TEST_TRACEABILITY_NOT_ENGINE_COMPLIANCE",
  "initialAuditLedgerSha256":INITIAL_LEDGER_SHA,
  "priorCrossFamilyLedgerSha256":OLD_LEDGER_SHA,
  "normativeSourcePinsSha256":AUTHORITY_SHA,
  "priorRows":len(old["evidence"]),
  "initialRiskRows":len(initial["entries"]),
  "initialRiskReconciliation":reconciled,
  "newRows":len(rows),
  "traceableTotalRows":len(old["evidence"])+len(rows),
  "authoredSyntheticCasesNotDeduplicated":counts[SYN],
  "publisherDocumentationCasesNotDeviceCaptures":counts[DOC],
  "convergenceNewOracleCases":counts[COMPOSE],
  "casesNotDistinctEventsOrGeneralizationAccuracy":True,
  "regressionHistoryOnly":{"originals":1361,"invalidMutations":2892,
    "unchangedReviewOnly":197,"priorIndependentOriginals":50},
  "flags":{"sourceOnly":True,"productIntegrated":False,"nativeVerified":False,
    "manufacturerWireCertified":False,"completeEventF1Measured":False,
    "allStandardsCompliant":False,"releaseAuthorized":False},
  "rows":rows,
}
output=ROOT/"scripts/poc/standardPost81Traceability.v1.json"
output.write_text(json.dumps(summary,ensure_ascii=True,indent=2)+"\n")
print("STD11_POST81_LEDGER",json.dumps({
   "rows":len(rows),"baselineRows":len(old["evidence"]),
   "synthetic":counts[SYN],"publishedIllustrations":counts[DOC],
   "composedNoNewOracle":counts[COMPOSE],"sha256":file_sha("scripts/poc/standardPost81Traceability.v1.json"),
   "sourceOnly":True,
}))
