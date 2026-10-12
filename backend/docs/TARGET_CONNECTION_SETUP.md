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
7. Preferred parser CONF listener port — optional (Enter to skip)

The SENSOR INGEST destination port and the generated CONF parser listener
port may be different and require later target-side mapping and collision
validation.

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
