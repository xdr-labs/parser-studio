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

Future H1 work: expand canonical semantics to extraction AST/regex grammar,
JSONata selectors, protocol-aware conditional field applicability, enrichment,
source-byte accounting and error-stage behavior without silently changing
legacy ParserProject/Recipe contracts.
