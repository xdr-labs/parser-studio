# Mixed single-line JSON/KV/CEF/LEEF parser — bounded backend subset

## Contract and limits

ParserProject v0.1 accepts extraction format **mixed** with a mixedFormats array containing 2–4 distinct names selected only from JSON, KV, CEF and LEEF. The parser never guesses an additional family or tries a fallback based on failed parsing.

- JSON must begin with an object opening brace; a malformed object does not retry as KV.
- CEF starts with the CEF header and is parsed only as bounded CEF version zero.
- LEEF starts with its LEEF header and is parsed only as strict LEEF 1.0/2.0.
- KV starts with a valid property assignment and requires full, contiguous key=value token coverage.

Unknown or disallowed families, unsupported versions, malformed quoted KV, CSV, RFC3164/5424 wrappers and multiline fail closed. The parser emits one static extraction-error event rather than silently discarding source records or reporting a normal event. No dynamic Ruby, JSONata, regex or arbitrary code is allowed.

For a mixed input, the author explicitly supplies source-field mappings, where different family keys may have separate normalized destinations. Missing source fields are not invented. Classification remains rule-based and checked against the v0.1 typed schema. The generated CONF uses the same single receiving port for the sensor destination and parser listener. Production DP is not accessed.

## ParserRecipe v0.2

The strict typed v0.2 contract has sourceFormat=mixed and bodyFormat=mixed with an ordered dispatch_family stage containing precisely the declared family allowlist and mode=strict_prefix. It is compiler-checked for exact equivalence to the corresponding independently valid v0.1 project. A modified routing list, unknown operator, scripted fallback or other stage mismatch denies output.

## Fixed offline native verification

The independent public-synthetic v02_mixed fixture contains four positive events (JSON, KV, CEF, LEEF) across one compiled Ruby parser, all required to return exactly one matching normalized record and class, plus five negative events: unrecognized text, CSV, invalid CEF version, unclosed quoted KV and disallowed RFC3164. Full Native Ruby 3.2 / Fluentd 1.17.1 Parser Plugin callbacks and the generated CONF AST run under the existing bounded offline qualification. Existing v0.1 10-profile/23-golden fixture baseline remains unchanged.

These facts do NOT prove an arbitrary customer parser, real listener, proprietary Stellar loader, DP installation, sensor data receipt, Interflow or production readiness. No real E2E is executed.
