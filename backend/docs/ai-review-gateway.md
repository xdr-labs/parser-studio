# P1-AP6 — Opt-in metadata-only integrated AI gateway (provider-neutral)

## Scope

Parser Studio has a review-only, **provider-neutral AI integration contract**, not an automatically enabled AI service. The feature remains **403 DISABLED** in normal backend startup. A trusted operator must provision a real provider adapter, an independent actor authorization callback, a **durable/atomic per-actor token-budget ledger**, and a metadata-only audit sink before the backend can construct the gateway. No provider SDK, token, credential, model URL, endpoint name or billing configuration is committed to this repository.

The read-only GET /api/v1/parser-pairs/ai/v0.1/capabilities reveals only fixed provider/model IDs and an **estimated output-token limit (32–1024, owner-configured)** after successful backend authorization; it contains no source log. POST /api/v1/parser-pairs/ai/v0.1/review requires exact root keys `contract`, `metadata`, `confirmedExternalTransfer=true`, and `confirmedEstimatedTokenBudget=true`. The metadata must be source-identity-bound, small and strictly enumerated: non-sensitive draft ID, source SHA-256, event count, exactly one bounded source format/body, and family/count distribution. All raw event strings, usernames, source IP values, credentials, field values, custom prompt templates and arbitrary client URLs are rejected (never proxied).

## Security and compliance gates

- A separate trusted server-side principal is resolved for both capability GET and review POST; no browser-supplied actor/tenant is trusted. The gateway is disabled if authorization, audit, token reserve/settle or provider implementation is missing or misconfigured.
- On each POST the owner-specific ledger reserves a maximum output-token budget **before** the metadata-only audit BEFORE event and before the provider sees any input. The provider is invoked only after both gates succeed. In-memory trial counters alone are insufficient for a production budget; caller's ledger must durably enforce rate/volume/cost policy across restarts and concurrent processes.
- The model prompt is generated **server-side from enumerated metadata only**; arbitrary user prompt instructions and raw log records are not forwarded. The optional provider receives only this server-constructed prompt and a bounded output-token setting. A 6.5-second wall timer signals abort; the trusted provider adapter must respect it and must separately enforce its own network egress timeouts/rate caps.
- The returned candidate passes the strict ParserRecipe v0.2 JSON schema, exact draft ID/source SHA/event count/family match, 32-KiB output size and no fabricated native/Stellar verification flags. Provider text/errors and customer-like strings are **not** returned in failure responses. **No returned stage is executed or compiled by this gateway**.
- Audit AFTER and durable budget settlement are required before success is returned. Any uncertain provider charge remains reserved for reconciliation; success is not returned on audit/ledger failure. Receipt contains only token counts, explicit metadata-only scope, REVIEW_ONLY recipe and provider/model identifier. Actual currency cost is not known without the operator's trusted provider billing system.

The gateway **does not** authorize real DP Apply, sensor sending, native user parser installation, tenant Interflow, or external logging. AI suggestions must be imported through the existing **local strict review → full-sample/holdout regression → explicit mapping approval** flow; no new AI field becomes executable automatically.

## Test coverage and operational status

The test suite uses only a test-owned simulated provider and quota/audit callbacks. Tests verify default disabled capability and POST, auth denial, schema-only prompt and no raw values, mandatory double consent, exact metadata format identity, atomic reservation ordering, audit failure, budget exhaustion, invalid/replayed candidate stages, inflated usage, tampered source SHA/native flags and accounting failure. No real LLM provider is called.

This independently runnable synthetic implementation lives in backend PR #4 and is not an authorization to configure a vendor model, persist actual user data, or use tenant credits. Before activating the integration, the owner must select a provider/account, approve data egress/privacy and retention, provision a bounded credential and durable quota ledger, and authorize actual tenant roles. Unsupported log families can continue using the **offline privacy-safe copy prompt**, which never makes automatic external calls.
