# Configure a Test DP + Modular Sensor (operator input)

This config is NOT collected through ChatGPT or the Parser Studio browser.
Use a trusted interactive SSH terminal on dev-atlas under the normal
backend OS account (aella, not sudo):

    cd /home/aella/parser-studio-backend
    python3 backend/scripts/configure-target.py

The script prompts for:

1. DP HTTPS URL — origin only, e.g. https://dp-lab.example.local
   or https://192.168.10.20:8443 (no URL path, query or credentials)
2. Tenant ID — associated with this API Key
3. DP User Scope API Key — hidden terminal input (getpass)
4. Modular Sensor IP — numeric IP address
5. Sensor log-ingest port — actual sensor receiver port
6. UDP or TCP — protocol the sensor accepts

**One port, not two:** the value entered for the sensor log-ingest port
is recorded as the SAME parser listener port for later CONF generation.
The setup script only stores configuration; it does not generate or
deploy a CONF file. For example, UDP sensor port 6800 requires the
subsequently generated CONF source port to be 6800.
The UI must use the same number for both values and reject any mismatch.
For RFC5424 Syslog parser configurations the port must be 6800 or higher.
An older private profile where preferred_listener_port is null is
compatible: this means "inherit the saved sensor port" rather than
"choose a second independent port". The user's saved settings are not
silently edited or redeployed by this correction.

## Location and security

File saved on dev-atlas only, OUTSIDE the repository:

    /home/aella/.parser-studio-secrets/connection.json

Private directory is mode 0700 and file is mode 0600. This path is not
inside any Git worktree. The existing backend/.tmp directory on dev-atlas
has group-writable development permissions (0775), so it is deliberately
NOT used to store an API Key. Do not change permissions of that shared
development directory to work around secret storage.

Setup is atomic and refuses unsafe symlinks, hardlinks, existing file
permissions and group/world-writable parent directories. Re-running asks
for explicit yes before replacing the existing profile. Cancellation
leaves the previous profile intact.

Verify format, presence and file permissions WITHOUT echoing the
URL, Tenant, Sensor IP or API Key:

    python3 backend/scripts/configure-target.py --check

API Keys are stored in plaintext in this owner-only file, not encrypted.
Use a dedicated revocable TEST-ONLY User Scope API Key, with machine disk
encryption and access controls. Do not paste a key into this chat, GitHub,
shell command arguments or screenshots. Do not upload this private file.

## Read-only DP verification (requires separate operator execution)

An independent scope-limited verifier is available. It is OFFLINE by
default and does not read the private profile without --execute.

From the existing dev-atlas SSH terminal:

    cd /home/aella/parser-studio-backend
    python3 backend/scripts/verify-target-readonly.py --execute

This command is restricted to the owner-approved POC origin, with system
CA/TLS certificate verification and redirects disabled. It performs
exactly POST /connect/api/v1/access_token to exchange the User Scope Key
for a JWT, followed by tenant-scoped GET /custom_log_parsers and
GET /custom_log_parsers/parsers. It does NOT call parser POST/PUT/DELETE,
read Interflow/customer events, probe other URL paths, or send UDP/TCP
packets to a sensor.

The terminal displays only HTTP status codes, parser-list record counts,
and numbers of distinct valid ports (if returned). No Key, JWT, parsed
event, existing parser name or raw vendor body is displayed or saved.
HTTP 403, missing/invalid responses or TLS/network failure are reported
as NOT VERIFIED, never PASS. A successful GET only verifies that this
credential can read the selected tenant's two inventory API responses;
it does not prove parser write privileges, specific listener availability,
sensor reachability or actual runtime parsing.

The standard test suite exercises all allowable requests and security
errors entirely OFFLINE with fake tokens/GET replies:

    python3 -m unittest discover -s backend/scripts -p test_verify_target_readonly.py -q

The owner independently ran the read-only command on dev-atlas
and reported JWT HTTP 200 PASS, tenant Custom Parser list HTTP 200
(4 rows with 4 distinct reported ports), and Parser catalogue HTTP 200
(441 rows with 441 distinct reported ports), no mutations/sensor sends.
Only the operator-supplied redacted status and counts are evidence of
real API readability. These two lists may overlap.

### Read-only parser listener port comparison (optional)

The existing read-only CLI can also inspect actual numeric ports from
the two authorized GETs. It never prints customer parser names or raw
response JSON and does not store the inventory or reserve a port:

    python3 backend/scripts/verify-target-readonly.py --execute --suggest-port

A preferred user-overridden parser listener port can be checked with:

    python3 backend/scripts/verify-target-readonly.py --execute --check-port 23000

For Syslog, the default candidate range is 6800–30000, and the report returns
CANDIDATE_REQUIRES_TARGET_RECHECK, KNOWN_COLLISION or
INCOMPLETE_EVIDENCE. Parsing fails closed for missing/invalid source ports
or unexpected tenant metadata. Even if a proposed port was not observed in
the readable catalogue, server-side local reservations, sensor mappings,
simultaneous changes and Fluentd runtime binding are still UNVERIFIED.
The suggested listener port IS the port that must also be used as the
sensor UDP/TCP ingest destination when the actual parser is applied.
If it differs from the sensor port already saved, the operator must
explicitly select and configure the new common port in both places
before any upload or test. This proposal is NOT a socket reservation
and does not automatically change the private profile or deployed CONF.

Live connection verification is separate from the native/parser runtime
qualification and full User E2E gate.

## Verification and deployment boundaries

The script performs ZERO HTTP requests, ZERO UDP/TCP sensor sends, ZERO
parser uploads and ZERO port reservations. It does not change running
backend configuration or automatically load a key, validate permissions,
grant a deployment approval or enable general auto-apply.
automatic_apply_enabled and port_verified remain false.

The main backend/src/server.ts does NOT automatically read the profile.
An independently authorized backend operator will later connect a secure
target adapter with validated TLS/egress and explicit owner permissions
before any real sensor/DP testing.

Any existing POC User Scope Key stored elsewhere on dev-atlas is NOT
read or imported automatically by this script. Enter a separate dedicated
revocable test-only key through the trusted SSH session after approval.
