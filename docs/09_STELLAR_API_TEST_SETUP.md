# Stellar Cyber test API credentials — dev-atlas only

This is a **local-only** interactive credential setup for a test Stellar Cyber DP.
It does not call the vendor API, check connectivity, upload parsers, or change
any Stellar Cyber configuration. Real API verification remains a separate step.

## Setup

From an interactive SSH shell on `dev-atlas`:

```bash
cd /home/aella/parser-studio-api-config
python3 scripts/configure_stellar_test_api.py
```

Supply the three prompts locally:

1. **DP URL**: `https://<dp-hostname>` (the `/connect/api/v1` suffix is optional).
2. **Tenant ID**: the Stellar Cyber API `cust_id` value, not a display name.
3. **API Key**: a dedicated test user-scoped API key (paste directly, without `Bearer `).

The API key input is hidden. Do not provide credentials in chat, commit them,
paste them into CLI arguments, or put them in shared shell histories.
Use a dedicated least-privileged test key rather than a production key.

Credentials are stored only on the machine where the script runs:

```text
~/.config/parser-studio/stellar-test-api.json
```

If `XDG_CONFIG_HOME` is configured, the file is stored under
`$XDG_CONFIG_HOME/parser-studio/stellar-test-api.json`.

JSON keys are `dp_url`, `cust_id`, and `api_key`.
The directory uses mode `0700`; the file uses mode `0600`.
Writes are atomic, and pre-existing credentials are not replaced without a
confirmation. The script rejects unsafe paths and HTTP URLs.

**Important:** File-system permissions protect the plaintext API key from
other unprivileged users. This is **not encryption at rest**: processes under
the same Linux account and root can still read it. Never expose this file via
the web frontend, logs, Git, backups shared outside the host, or API responses.

## Check or rotate

```bash
python3 scripts/configure_stellar_test_api.py --status
python3 scripts/configure_stellar_test_api.py  # prompts before replacing saved key
```

`--status` does not print the key and does not validate the remote credentials.
Once configured, use the **read-only live API probe**:

```bash
python3 scripts/probe_stellar_test_api.py
python3 scripts/probe_stellar_test_api.py --json  # machine-readable redacted summary
```

The probe exchanges the User Scope API Key for a short-lived JWT using
`POST /connect/api/v1/access_token`, then only makes two tenant-scoped GETs:
`GET /connect/api/v1/custom_log_parsers?cust_id=...` and
`GET /connect/api/v1/custom_log_parsers/parsers?cust_id=...`.
TLS validation is enabled and HTTP redirects are rejected. The output contains
only status codes, response shape, and record counts — never the Key, JWT,
parser names, or raw server responses. The script uses the Python standard
library and never creates, edits, activates, or deletes a parser.

Parser create/update/delete required an approved nonproduction test target,
which the owner explicitly authorized for this POC. The verified API contract,
including the exact legacy filename pattern and the HTTP 422/400 diagnostic
sequence, is documented in [POC Parser API CRUD Evidence](10_STELLAR_POC_API_CRUD_EVIDENCE.md).

**Verified on the authorized POC:** User Scope JWT exchange and both GETs 200,
POST with a legacy JSON/CONF multipart pair 200, PUT 200 with version 1.0.1
confirmed by GET, DELETE 200, and a final GET with no test parser residue.
Neither modular-parser activation nor sensor/runtime parsing was verified.

To inspect the CRUD test workflow safely without executing an API call:

```bash
python3 scripts/test_stellar_parser_crud.py
```

Running it with `--execute` **changes the live POC** and requires explicit
approval for that DP and tenant. The CLI targets exactly the authorized POC,
creates a unique throwaway name, checks port collisions, and attempts cleanup
with read-back. Do not copy tenant-specific response data into GitHub or logs.

## Local tests

```bash
python3 -m unittest discover -s tests -p 'test_*.py' -v
```
