# P1-AP5 — Isolated, optional real Drain3 template mining

## Dependency and provenance

Uses the independently verified MIT-licensed logpai/Drain3 0.9.11 distribution with Python 3.12 and **hash-pinned** drain3==0.9.11, cachetools==4.2.1, and jsonpickle==1.5.1. Versions and source hashes are recorded in scripts/drain3-requirements.txt. The dependency is not enabled by normal backend startup. Installed public packages are used unmodified, not copied into this repository.

Original project: https://github.com/logpai/Drain3 (MIT), https://pypi.org/project/drain3/0.9.11/.

## Trusted server-side runtime

The TypeScript module src/drain3-worker.ts accepts an explicitly configured absolute, server-owned Python interpreter path and starts a one-shot child process (scripts/drain3_offline_worker.py). The Python process enforces a 3-second CPU budget, 256 MiB address-space ceiling, zero file-writing allowance, and limited open descriptors before importing Drain3. Node applies a 5-second wall-clock timeout, 48-KiB output cap, and concurrent process bound of two, terminating excess/wedged children without executing a shell.

The worker uses isolated Python startup flags, a minimized environment, no persistence handler, no Python bytecode generation, and a runtime-denied Python socket constructor. These are defense-in-depth restrictions, **not** a claimed OS-level network namespace/seccomp or multitenant sandboxing proof. This code does not send data to an AI provider, store events, load credentials, or execute user-supplied code/Regex.

Input accepts only 1–500 one-line training records and up to 500 separate holdout records, each <=2,048 UTF-8 bytes, no NUL/CR/LF, and total input <=64 KiB. The output is strictly checked: fixed cluster IDs, count/line-index partition, and bounded token-class templates. Arbitrary literal words, usernames, IPs, and exception text are never returned. Training and holdout remain separate; holdout calls inference-only TemplateMiner.match() and does not update templates.

This is actual Drain3 clustering, but **not an engine-certified custom parser**: sanitized cluster shapes are candidates for manual review, with native parser and Stellar DP flags FALSE. High holdout-match count does not establish normalized-field extraction accuracy.

## Explicit opt-in API

The data-free GET /api/v1/parser-pairs/patterns/drain3/capabilities is also denied by default and requires the same independent owner authentication. Clients must check this GET first, then separately obtain explicit user consent **before** any raw sample POST.

POST /api/v1/parser-pairs/patterns/drain3 is **403 disabled by default**. It is enabled only when a trusted Python interpreter and independent backend authorization are injected. Each call additionally requires confirmed:true and exactly the keys contract, training, holdout, confirmed. No unauthenticated request body is processed by the worker; denials and exceptions return only fixed error codes.

An opt-in call transfers explicitly selected raw log samples from the browser to the same-origin **private Parser Studio backend**, so the UI must explain the transfer and require a separately unchecked consent control. This API is not an external LLM connection. Automatic uploads and production-target operations remain disabled.

## Tests and qualification

The backend test/drain3-worker.test.ts executes the real pinned package on public-synthetic examples with independent holdouts, asserts exact counts, redacted output, denial of oversized/forged input and missing runtime, and default-deny and authorized local HTTP behavior. One observed holdout result is 1/2; this is not a generalized accuracy statistic.

CI installs Python 3.12 via actions/setup-python@v5 and the exact hash-locked pip dependency set before running bash scripts/qualify.sh. The local venv under backend/.tmp/ is ignored by Git and does not affect production startup. No DP API/loader, sensor delivery, Interflow, or real-user E2E was performed.

Remaining: explicit UI user consent and no-loss mapping review; optional provider integration with auditable privacy/rate/cost limits; actual authorized target E2E. These are separate acceptance gates.
