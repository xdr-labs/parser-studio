# Parser Studio — Five Re-audit Correctness Fixes (2026-11-04)

## Scope

Owner-directed correction of five independently reproduced security-log parser defects, based on the already merged main `3d5851354b7ba82636a1d190523e97b89719d92f`.

The changes preserve Parser Studio's two primary workflows, its existing parser grammar and DRAFT Ruby + .conf export model. This is a development-preview release candidate, not a Stellar Cyber 7.0 DP import or ingestion certification.

## Changes

| Finding | Exact issue | Correction and fail-closed behavior |
| --- | --- | --- |
| P1 JSONata source identity | A reviewed literal root key literal `source.ip` was later treated as nested `source.ip` on an unseen event. | Persist optional `sourcePathKind` / `source_path_kind` (`literal_root`, `nested`) from UI review through browser preview, API project schema, recipe stages and Ruby runtime. Legacy unspecified mappings retain previous behavior. Reject mixed interpretations in a single record, without selecting an arbitrary IP. |
| P1 calendar-date integrity | Invalid `2026-02-30` was silently normalized to March 2 by JavaScript and native Ruby. | Validate ISO calendar day/month/year and leap year before conversion in browser and generated Ruby. Preserve explicit timezone requirement; invalid calendar dates fail normalization. |
| P2 regex nested alternation | `^(?<field>((a|aa))+)$` passed the old preflight, despite exponential backtracking on short mismatching input. | Conservatively detect quantified nested alternatives in browser and backend regex validator, while retaining the browser Web Worker execution-time limit. |
| P2 protocol-pair coherence | `proto=6` and `proto_name=UDP` could coexist as approved standard metadata. | Validate official IP protocol / L4 name pairs in browser preview, mapping review blocking findings, and generated Ruby parser templates for main and conditional-family events; retain valid TCP, UDP, ICMP (1 and 58), IGMP combinations. |
| P2 object string parity | Browser encoded a mapped object as JSON while native Ruby encoded Ruby Hash inspection syntax. | Use native `JSON.generate` for object/array-to-string conversion, matching browser `JSON.stringify` on the supported JSON source forms. |

## Compatibility and safeguards

- The project JSON schema allows an optional `source_path_kind` field rule. Existing projects without the field remain compatible.
- Optional recipe `map_field.source_path_kind` must match the exact compiled project. No arbitrary JSONata functions or dynamic code execution are introduced.
- Strict selectors apply only to reviewed JSONata mappings. When an author manually edits the source path, the previous strict selector identity is cleared. The mapping UI labels active JSONata selector semantics and shows values using the same strict source lookup.
- Invalid timestamps, contradictory protocol fields, and ambiguous competing paths produce errors rather than unreviewed normalizations. No DP mutation is introduced.
- The synthetic/loopback/null-sink-only Stellar API POC template allowlist must be repinned to the exact tested Ruby template SHA; existing approval, tenant, port, recompile-byte and verification gates remain unchanged.

## Verification requirements

1. Browser-focused six regression tests for dangerous regex, invalid dates, root-literal/nested selection, protocol conflict and object serialization.
2. Nine generated Ruby native regression tests, covering both single-event and conditional-family templates, preserving good cases.
3. Full frontend Vitest, production TypeScript/Vite build and full backend Node + Ruby + Drain3 suite on the exact candidate.
4. Real Chromium user E2E on published security documentation examples, JSONata review/approval, multi-event FortiGate and DRAFT pair generation.
5. GitHub CI and exact-head check; rollout only to the development preview using a rollback snapshot.

Separate unverified gates: actual Stellar Cyber 7.0 DP import/receive and independent external ChatGPT first-response success-rate measurement.
