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

## H1 portable regular expression AST increment (DRAFT)

A single pure, versioned `parser-studio.portable-regex-ast.v1` parser
(`backend/src/portable-regex.ts`) records sequence, alternation, named/noncapture
groups, character classes, anchors, reviewed escapes and bounded repetitions.
The shared browser/backend authoring gate now rejects unsupported lookaheads,
inline flags, malformed parentheses, duplicate captures, invalid escape syntax
and unsafe repetition limits before accepting a named-capture expression.
Names must be genuine parsed captures, not substring matches inside escaped
literals or classes. Existing conservative overlapping repetition checks remain
in force.

The AST is a **validation/inspection contract**, not an alternative matching
engine or assertion of full JS/Ruby equivalence. Independently authored
positive/negative ASCII and Unicode log fixtures are checked against JavaScript
and mandatory Native Ruby matching in CI. Existing Regex ParserRecipe v0.2 and
ParserProject authoring shapes are not expanded. No customer expression is
executed on a publicly accessible native service.

Unreviewed grammar families, error stage/byte-accounting contracts, Native
sandbox and actual Stellar DP 7.0 import remain separate acceptance gates.

## H1 typed-enrichment failure transaction (DRAFT)

The `enrichment` section of the versioned common operator contract now
records the sequence and failure handling already enforced by the generated
Ruby: extraction and typed normalization complete first; **any earlier
blocking error prevents enrichment execution**. On a valid event, ordered
enrichment runs transactionally against a copy of the normalized record.
Missing input, unsupported cast, invalid official Stellar destination,
assignment conflict, split/merge mismatch or a final contradictory protocol
pair invalidates the entire enrichment transaction. The generated Ruby reports
`parser_err_stage=enrichment` and retains only previously validated fields
from before enrichment. It never returns a partially written enrichment value.

The browser preview now follows the same rollback/skip behavior while retaining
its existing diagnostic-code and `stage=normalize` display schema for
compatibility. This UI stage string is **not** a native Ruby error stage; compare
the canonical operation and error code rather than asserting that the two
serialized stage labels have identical values. A mapping cast failure remains
a native `normalization` error even when reviewed enrichment was configured.

Independent positive/negative source truth covers source-not-found, mapping
type failure, invalid enriched official IP, and success, including a UTF-8
sample. The mandated CI Native Ruby test executes the exact compiled fragment
and requires the native diagnostic stage/field, preservation of valid
pre-enrichment fields, atomic rollback, and absence of raw or unrelated
source text. Both success and failure evidence remain `DRAFT` and do not
prove Fluentd or Stellar Cyber DP 7.0 target acceptance.
