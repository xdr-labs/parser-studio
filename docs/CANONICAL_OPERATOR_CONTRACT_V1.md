# Canonical Operator Semantics v1

Status: **H1 incremental implementation**, not a claim of fully completed
Parser Correctness Architecture Hardening. Source contract:
`backend/src/canonical-operator-contract.ts`.

- Contract ID: `parser-studio.operator-semantics.v1`
- Application order: extract original source → normalize typed fields → apply
  reviewed enrichment → classify the normalized result. Classification never
  compares raw values before conversion.
- `equals`: ParserProject v0.1 serializes the comparison literal as a string;
  hence the normalized field **must have the type string**. Comparison is
  exact, case-sensitive and does not trim, coerce numbers/booleans, or discard
  leading zeros. Non-string equals conditions are rejected at project
  validation and reviewed draft adaptation, not promoted as a successful DRAFT.
- `exists`: applicable to any reviewed normalized type and means present and
  non-null. Numeric zero and boolean false are present. Absent/null are not.
- Duplicate normalized targets, reserved fields and source path constraints
  remain governed by existing backend schema/validation. This version does
  not authorize a new predicate grammar, regex engine or target API action.
- Native Ruby templates carry the exact contract marker and use `value ==
  rule['value']` for equals and `!value.nil?` for exists. Independent native
  execution must verify the intended behavior; a matching marker is never
  sufficient evidence of actual native conformity.
- Browser preview and HTTP compilation are not native verification; native
  Ruby conformance is not Stellar Cyber DP 7.0 import/receive verification.

Implementation: both browser and backend import the same pure, versioned
predicate/type module. Two authored corpora assert byte-for-byte reviewed
source examples and expected routing; generated Ruby is executed in the CI
Ruby environment for the native comparisons.

## H1 source path parity increment (stacked on H3, still DRAFT)

The same pure `canonical-operator-contract.ts` module defines
`sourcePaths.lookup = all-partitions-own-keys` with an eight-segment,
128-character, own-property-only source path grammar. A path such as
`a.b.c` can denote `a -> b -> c`, `a -> "b.c"`, `"a.b" -> c`, or
`"a.b.c"`. Exactly one resolved source value is required; a missing value
does not map, and competing interpretations **always fail closed** even
when a reviewed `source_path_kind` specifies a literal or nested selector.
This matches the behavior of `parserstudio_lookup` in both native templates,
which raises `Ambiguous source path` on collisions.

The browser now uses the same bounded partition algorithm rather than
prefering a literal root key or ignoring dotted intermediate keys. Field
suggestions exclude ambiguous paths; JSONata prompt generation independently
checks original source leaves **before** candidate filtering so the reason is
not lost. Source bytes and vendor records are never rewritten to disambiguate
a value. The browser preserves a `found` distinction for absent and null
fields; the native lookup returns Ruby `nil` for either, and both are
ineligible for `exists`.

Independent tests assert synthetic mixed, ambiguous, zero, false, null,
missing, literal and nested cases. A required Ruby CI test compares the
identical lookup method from both generated template sources with independent
truth. Local dev-atlas has no Ruby executable, so local tests alone cannot
certify Native conformance. This increment does **not** certify an isolated
Native runner, grammar-wide regex AST, Fluentd integration or Stellar DP 7.0.

Future H1 work: expand canonical semantics to extraction AST/regex grammar,
JSONata selectors, protocol-aware conditional field applicability, enrichment,
source-byte accounting and error-stage behavior without silently changing
legacy ParserProject/Recipe contracts.
