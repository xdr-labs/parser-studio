# ChatGPT-assisted JSONata field mapping (review-only)

Date: 2026-11-04
Product: Parser Studio 2.0 — Auto Parser → Map Fields
Initial feature branch: feat/chatgpt-jsonata-field-mapping-20261104
Target: Stellar Cyber published metadata dictionary 7.0.xs

## User workflow

1. Paste one or more original security logs, select the manufacturer and product, then run **Analyze Logs → Review Fields → Map Fields**.
2. Under **Improve with ChatGPT (JSONata)**, select **Prepare Mapping Prompt**. The initial prompt contains only parsed source field paths, inferred coarse value types, their observed counts, current manufacturer/product hints, existing destination field names, recommended candidates and a SHA-256 sample fingerprint. It does **not** include raw events, actual field values or credentials by default.
3. Review the text; use **Copy Mapping Prompt** to paste into a separate ChatGPT conversation. Sending is entirely manual, with no browser-to-provider API request. If original values are necessary, explicitly select the **Include observed values** option, then re-create and review the prompt. These values may contain sensitive information.
4. Paste the strict mapping JSON that ChatGPT returns into **Paste the ChatGPT JSONata mapping response**, and press **Check JSONata Mappings**.
5. Review each candidate's source/target, observed sample coverage, datatype and status. Only READY or CHECK FIRST items can be selected. BLOCKED and UNCHANGED items cannot be applied. CHECK FIRST requires a separate explicit confirmation of field semantics.
6. Approve the selected mappings. The editor updates the destination names and types for the selected fields, retains unrelated/vendor-only fields, and refreshes the per-event preview.
7. Continue to Create Parser. A successful result is still a **DRAFT** Ruby + .conf pair, not evidence of actual Stellar DP import or live ingestion.

## Contract and supported expression subset

The response is one strict JSON object with exactly the following structure (the sample hash is supplied by the actual prompt, not a constant):

```json
{
  "contract": "parser-studio.mapping-jsonata.v0.1",
  "sample": { "sha256": "<exact 64-character digest>", "events": 2 },
  "mappings": [
    { "expression": "syslog_sd.element_1.params.`source-address`", "target": "srcip" },
    { "expression": "syslog_sd.element_1.params.`destination-address`", "target": "dstip" }
  ]
}
```

The product accepts a **read-only JSONata property selector subset**: unquoted identifier paths, optional `$.` root, and JSONata backtick-quoted path segments for hyphenated source field names. Each selector must match a locally observed source path and be safely represented as an existing Parser Studio MappingRule. JSONata itself is **not evaluated** in the browser or in generated Ruby.

Excluded from this version: function calls, arithmetic, unit conversions, conditions, array wildcards or indexing, object constructors, references to external APIs, dynamic code execution, and arbitrary JSONata expressions. These features would require a separate verified compiler/runtime contract; no support is implied by this UI.

## Security, semantic and consistency gates

- Identity: the response contract, sample fingerprint and exact event count must agree. Pasted responses are bounded to 24 KiB with at most 100 mapping items. UI invalidates the prompt and review on sample/draft or manufacturer/product mutation.
- Source: every source selector must be a safe leaf path found in the actual parsed sample; reject prototype keys, arrays and arbitrary computation.
- Destination: every target must be a directly mappable member of the pinned official 7.0 dictionary, with the dictionary-required datatype and output group.
- Values: each informative observed value must pass target-specific constraints. Missing/placeholder values never provide affirmative evidence; sparse heterogeneous samples require manual review.
- Safety: reject collisions and duplicate mappings. Known semantic false friends are rejected: Juniper NAT vs original IPs, ICMP/IGMP pseudoports, vendor application services vs Layer 4 protocols, FortiOS seconds vs Stellar milliseconds and vendor-specific type/direction fields, Syslog PRI severity vs event severity, PAN-OS TRAFFIC type vs unrelated agent type.
- Approval: unverified source/target semantic pairings require separate confirmation. No ChatGPT output is applied automatically.
- Compilation: selected mappings are rechecked at the apply boundary, validated against all current samples and converted to native source→target mappings through the existing backend adapter. The generated pair is still DRAFT and cannot claim target import verification.

## Test coverage

- Pure-selector safety and source-path round-trip, fingerprint-matched response schema, privacy opt-in, type, duplicate and semantic collision guards, forged READY-row denial: `src/guided/jsonataMappingAssist.test.ts`.
- Review-only browser UI, disabled apply before user approval, no network action, opt-in sample values and unsupported expression refusal: `src/guided/JsonataMappingAssistant.test.tsx`.
- Published original 2-event Juniper sample: intentionally remap an official source to a vendor field, recover it via approved JSONata selection, reject NAT and arithmetic suggestions, inspect source/value preview, and generate native DRAFT Ruby/.conf through pinned backend: `tests/docs-jsonata-mapping-assisted-20261104.spec.ts`.
- Full published documentation practice corpus regression: `tests/docs-practice-*.spec.ts` and the existing Snort-assisted and FortiGate mixed-event E2E.

Real Stellar Cyber 7.0 DP installation, runtime ingestion, and arbitrary JSONata transforms are not verified.
