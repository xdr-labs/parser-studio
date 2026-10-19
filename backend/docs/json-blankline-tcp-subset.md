# Explicit TCP blank-line framed JSON — restricted Native subset

## Scope

This is a **limited, opt-in framing transport** for events already separated by an exact double line-feed (LF LF) between complete JSON objects. A JSON event itself can contain physical line feeds in its pretty-printed object. It does **not** infer boundaries from indentation, header timestamps, Java stack traces, or arbitrary unmatched data; it is not universal Multiline.

The ParserProject v0.1 receiver must declare exactly `tcpFraming=blank_line_json` and `protocols=[tcp]` (no UDP) with `extraction.format=json` and **no user-supplied delimiter**. All other combinations fail validation. The generated `.conf` uses the explicitly chosen common receiving port for TCP and emits the literal Fluentd config value `delimiter "\\n\\n"`, interpreted by pinned Fluentd 1.17.1 as LF LF. It does not infer a sensor port or supply missing separators. If the sender does not put LF LF after each event, a TCP frame may remain buffered or be misgrouped; the operator must verify the upstream framing contract before using this option.

ParserRecipe v0.2 represents this only as `split_event(boundary=blank-line)` paired with the above exact legacy receiver metadata. Switching a recipe to or from `single-line` without changing matching transport metadata fails closed. ParserProject JSON with a TCP `delimiter` from older versions is never silently converted or repurposed. DRAFT files remain Native user parser NOT VERIFIED and proprietary Stellar DP target NOT VERIFIED.

## Qualification

`test/blankline-json.test.ts` covers exact JSON-only TCP settings, new boundary stage, pair hashes, rejection of UDP/mixed/non-JSON/custom delimiters and mismatched v0.2 review. A new fixed `v02_json_blanks` profile in the public-synthetic Native corpus includes two pretty JSON objects containing multiple physical source lines, separated by LF LF for the simulated transport stream. The native Ruby 3.2 + Fluentd 1.17.1 smoke independently validates the generated `.conf` AST and exact decoded `delimiter` value, then invokes the actual pinned Ruby parser callback for each resulting frame and compares normalized typed golden records.

This evidence proves the **configuration value** and per-frame Ruby parser semantics, not actual TCP socket flow, an independent sensor's framing, live listener traffic, proprietary Stellar loader import, Interflow or real-user E2E. The dedicated private dev runtime and generated `.tmp` fixtures do not touch DP or customer logs.

## Remaining

- Independently qualify a sender/receiver framing profile before declaring live TCP stream operation (especially incomplete trailing frames, reconnects, dropped stream fragments and input caps).
- Java stack-trace and mixed multiline routing remain browser review-only. These need a separately verified transport/receiver and explicit boundary state machine, not automatic promotion from browser suggestions.
- UI may enable the new metadata only behind an explicit transport policy selection and exact signed backend capability, never as a default inferred from pretty JSON.
