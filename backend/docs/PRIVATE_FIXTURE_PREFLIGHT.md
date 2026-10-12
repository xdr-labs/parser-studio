# Private golden fixture preflight — offline only (v0.1)

This is not a customer-log execution service, importer, uploader, renderer,
private storage service, or Stellar Cyber compatibility check. It only
validates the shape and bounds of one explicitly owner-approved local JSON
file. The public backend HTTP API does not read or receive these events.

## Operator-controlled file and permissions

- Fixed path relative to backend/: .tmp/private-fixtures/golden.json
- Directory mode 0700, owned by the executing user. It must already exist.
- JSON file: user-owned regular file, one hard link, mode 0600, maximum
  512 KiB. The reader opens the file with Linux O_NOFOLLOW and verifies the
  open file descriptor; it does not follow a final symlink.
- From backend/, after npm run build, run:
  node dist/scripts/preflight-private-golden.js
- Inputs may not specify another file path. No data is written or copied.
  The parent .tmp must also be an owner-owned real directory (not a symlink).
  An ignored .tmp directory prevents normal Git tracking.

## Input contract and exclusions

The root JSON object uses kind = parser-studio.private-golden.v0.1 and cases
containing between 1 and 32 entries. Every case has exactly:

- id: a short unique lowercase identifier
- projectSlug: a valid existing ParserProject slug
- rawEvent: a nonempty UTF-8 event with a 16 KiB maximum
- expectedTime: an explicit UTC ISO8601 second timestamp or null
- expectedRecord: an object of JSON scalars / safe nested object fields
  with maximum nesting depth of eight

Invalid UTF-8 is rejected without substituting the replacement character.
Unknown fields, unsafe destination names, duplicate case IDs, oversized or
empty input, arrays in expected records, NUL bytes and malformed timestamps
are rejected. Only fixed diagnostic codes and structural JSON pointers are
printed. Raw values, expected fields and private record contents never
appear in stdout, stderr, a new report, GitHub or any network call.

The in-memory synthetic tests use RFC5737 documentation-only IP addresses.
No real events, customer parser source, credentials or secrets are committed.

## Scope after PRIVATE_PREFLIGHT_OK

Success means ONLY that the operator-owned local JSON file is well formed,
bounded and permission protected. It does not prove consent, cleansing,
parser validity, native execution safety, Stellar Cyber support or release
readiness. The program intentionally does not run Ruby, spawn the native
Fluentd harness, create files or modify verification flags.

Before any future private replay, the user must approve the data and the
runtime must be independently hardened, isolated and auditable with retention
and cleanup policies. Do not send real logs to the current synthetic runner.
Actual Stellar Cyber import/application remains owner-operated and deferred.
