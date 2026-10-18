# Explicit TCP blank-line JSON — opt-in Web UI / compiler contract

## Authoring flow

The beginner Add Logs view retains browser-only logical-boundary hints. **It must not automatically choose a receiving transport from a pasted sample.** To use the new bounded backend capability, open **Edit Details** and explicitly select: JSON format, blank-line event grouping, TCP receiver only, and **TCP JSON Event Framing: TCP-only · Pretty JSON separated by an empty line (LF LF)**. The same chosen receiver port is used by the sensor destination and generated CONF listener. UDP is not supported for this framing mode.

The actual upstream sender must supply exactly two consecutive LF characters between complete JSON objects, and must terminate each event with the delimiter. There is no Java stack-trace multiline reassembly, no generic regular-expression boundary inference, no CSV/RFC3164/5424 mixed routing, and no automatic conversion of a browser-only boundary suggestion into a native parser. Without this explicit selection, blank-line grouping stays preview-only and DRAFT generation is blocked.

## Strict gates

- The v0.1 adapter sends only reviewed metadata `receiver.tcpFraming=blank_line_json`, `receiver.protocols=[tcp]`, and `extraction.format=json`. It never includes raw JSON event values, user credentials or arbitrary separator strings.
- The normal backend capabilities must explicitly advertise `jsonBlankLineTcpFraming=true`, `jsonBlankLineOtherTransports=false` and `jsonBlankLineDelimiter=LF_LF`. Older, missing or forged capabilities fail closed.
- ParserRecipe v0.2's `split_event` boundary is `blank-line` only for the matching JSON format and explicitly reviewed receiver. The versioned v0.2 compiler verifies exact stage-to-v0.1 transport equivalence, user and source SHA, and returns a DRAFT Ruby + CONF pair with exact hashes and `nativeUserParserVerified=false` and `targetImportVerified=false`.
- Native proof at backend `d5f3992a951eadc83970d087fe1751b9bfd4229b` comprises the fixed Fluentd 1.17.1 CONF parser and Ruby parser plugin callback on two public-synthetic pretty-printed JSON records. The native test does **not** open a live TCP sensor listener or demonstrate complete end-to-end sensor framing.

## Regression evidence

The browser unit test `src/guided/blankLineJsonUI.test.ts` checks the two-event grouping, explicit receiver state, strict capability gate and v0.2 stage review without private samples. The synthetic Chromium scenario `tests/guided.spec.ts` checks that default blank-line preview cannot generate, enabling the framing without disabling UDP is denied, and explicitly choosing TCP-only permits a source-free reviewed project download. The UI CI pins backend SHA `d5f3992a951eadc83970d087fe1751b9bfd4229b` and checks localhost API integration, not target DP/sensor E2E.

No actual customer logs, target DP credentials, device changes, release, merge or authorized sensor send are performed by this implementation.
