# 10 — Guided Builder UI → Paired Compiler Integration Contract

**UI ownership:** ChatGPT Chat development lane, `feat/r2-web-workbench` / Draft PR #3.
**Backend ownership:** separate implementation session / independent branch and worktree.
**Related authoritative docs:** draft PR #2 `08_NO_CODE_USER_EXPERIENCE.md` and `09_BACKEND_PAIRED_ARTIFACT_DESIGN.md`, canonical Issue #1.

## Product boundary, not a compatibility assertion

- The **Guided Builder is the default landing page**, supporting the six user questions: Add Logs → Extract Fields → Map/Enrich → Receive/Classify → Test/Fix → Generate.
- The existing three-pane Web Workbench is an optional Expert view; both share a single parser rule draft and browser-only sample set.
- The UI does not include or execute the external backend's Ruby files, compiler, td-agent plugins, Fluentd or Stellar portal integration.
- No native parser runner or target importer is available in this UI PR. Therefore actual `customized_<slug>.conf` and extensionless `customized_<slug>` **cannot be downloaded**; both are explicitly marked NOT GENERATED.
- The one enabled interchange artifact is a **configuration-only proposed backend project JSON**, carrying `exportProfile=host-customized-pair-draft`. It is not an installed parser, deployment bundle or vendor portal upload file.

## Contract creator

Source: `src/guided/contract.ts`. Exported browser-only interface:

```ts
compilerDraftContract(draft: ParserDraft): ContractResult
plannedPairNames(slug: string): { config: string; parser: string } | null
defaultGuidedOptions(): GuidedOptions
```

`compilerDraftContract` performs **UI-side validation only**, not backend engine/target verification.

### `PairProjectContract` shape v0.1

```json
{
  "schemaRevision": "0.1",
  "slug": "demo_firewall",
  "vendor": "Synthetic Vendor",
  "product": "Test Firewall",
  "receiver": {
    "protocols": ["udp", "tcp"],
    "port": 7501,
    "bindPolicy": "loopback",
    "messageLimit": 8192,
    "framing": "newline"
  },
  "input": { "format": "json" },
  "normalization": {
    "top_fields": [{"source": "src_ip", "normalized_name": "custom.source_ip", "data_type": "ip"}],
    "ns_fields": [{"source": "dst_port", "normalized_name": "custom.destination_port", "data_type": "port"}],
    "vendor_fields": [{"source": "action", "normalized_name": "custom.action", "data_type": "string"}]
  },
  "classification": {
    "rules": [
      {"sourceField": "action", "equals": "deny", "index": "Threat"},
      {"sourceField": "action", "equals": "allow", "index": "Session"}
    ],
    "defaultIndex": "Syslog"
  },
  "exportProfile": "host-customized-pair-draft"
}
```

**Notes:** These keys match the *proposed* R1.5 IR in the backend design docs, not necessarily a merged compiler schema. The backend session must contract-test and reconcile any differences before enabling Generate. UI currently permits compiler handoff only for an explicit `json` / `kv` format. Other parsing candidates remain usable solely as browser previews until the backend declares support.

### UI-side validation

- Parser ID matching `^[a-z][a-z0-9_]{2,47}$` and deterministic `customized_<slug>` pair names.
- UDP/TCP unique protocol choices; 1024–65535 integer port; message limit 1024–65536 bytes. **No claim that a port is free** on the real active target.
- Explicit typed mapping categories: `top_fields`, `ns_fields`, `vendor_fields`.
- UI `timestamp` becomes backend `date` plus `time_format: iso8601` / `timezone: UTC`. Unsupported `number` is blocked; type/name collisions are rejected. No invented official Stellar mapping dictionary.
- Ordered no-code classification conditions `sourceField` / `equals` → `Session`, `Threat`, `Syslog`, `Winlogevent` with a default index; duplicate conditions are rejected.
- Samples, extracted values, browser event results, vendor original Ruby and manually selected source strings are **not embedded** in the JSON configuration. Stored parser rule revisions remain local to the browser and exclude sample sets.

## Backend collaboration requirements

The backend implementation session can work independently now. When ready, coordinate the following contract, in this order:

1. **Schema parity:** backend `ParserProject v0.1` validator accepts the UI's `PairProjectContract` or returns an explicit field-by-field compatibility error. Do not silently transform or discard unsupported metadata.
2. **Security & authentication:** a separate authenticated private sample-upload/fixture API, size/time limits and secure isolated runtime. Do not automatically upload source samples simply because the user clicked Next or Preview.
3. **Adapter/capability response:** return supported format, receiver protocol, parser/routing type and manifest version. UI must not enable Generate until capability check and contract validation succeed.
4. **Generation endpoint:** confirm an actual API path, method, CSRF/auth mechanism, request and response. The canonical backend proposal is `POST /api/projects/:id/exports`; no endpoint has been implemented or assumed by this UI.
5. **Artifact response:** exact `customized_<slug>.conf`, extensionless `customized_<slug>`, SHA-256 manifest and validation statuses. Distinguish `DRAFT`, `SYNTAX_VALID`, `ENGINE_TESTED`, `TARGET_IMPORT_VERIFIED`, `PARTIAL`, `UNSUPPORTED`, `PENDING_EVIDENCE`.
6. **Native success gate:** only after pinned sandboxed Fluentd and actual target importer checks permit appropriate verified labels and actual two-file download. No production deploy or writes to `rickmodular` without separate authorization.
7. **Same HEAD integration tests:** render a guided project → server-side parser validation → sample fixture native execution → artifact checksums/download → full browser E2E. Keep customer data out of GitHub and screenshot/error artifacts.

## UI evidence and continuation

Primary sources:
- `src/guided/GuidedBuilder.tsx`: six connected editor steps, plain-language field selection, typed mapping, receiver/classification, test and guarded download.
- `src/guided/contract.ts`: UI-to-backend model and handoff preconditions.
- `src/guided/contract.test.ts`: deterministic contract/field validation tests.
- `tests/guided.spec.ts`: true Chromium actions for beginner journey, errors, privacy, shared Expert state and narrow viewports.
- Existing Workbench tests remain active in `tests/browser.spec.ts` / `e2e/workbench.spec.ts`.

**UI addition (2026-10-12):** field proposal review highlights the selected source token and structural capture positions in up to 20 sample events, including unmatched variants. The browser Web Worker remains authoritative for full-sample denominators. Highlighting is not native runtime evidence. See `src/guided/fieldHighlights.ts`, `src/guided/fieldHighlights.test.ts` and `tests/guided.spec.ts`.

**Next UI-only backlog (do not overlap backend session):** guided family-branch editor; multi-line boundary chooser; confirmed schema suggestions; explanation/recovery for parser field variants; saved project labels and test evidence; final API wiring only after backend contract agreed.

**Do not work on** Ruby fragment templates, native td-agent/Fluentd runner, IR schema/compiler implementation or deployment from this UI lane. The separate backend session owns those deliverables.
