# 2026-11-13 Owner-approved Synthetic POC Ruby Template

The owner approved the following exact template SHA-256 for PR #307:

`95d2bdc6466d1d82f728aec7c0fc2ac222f1afd49a9bcbdf10f17f1ee6c88a2c`

The approval is limited to the `KNOWN_TEMPLATES` allowlist for synthetic,
disposable POC writes. It does **not** authorize production or live sensor
deployment, management API activation, new tenants, or other releases.

The generated Ruby template was reviewed in the independent audit
[`20261113-final-independent-audit.md`](20261113-final-independent-audit.md),
and its digest was independently reproduced by CI Node 22.23.4 and local
Node 24.21.0. Older owner-approved template digests remain unchanged.

After this approval, the following gates continue to apply unchanged:
- 127.0.0.1-only receiver, fixed disposable test naming and port range
- null output sink and synthetic-fixture-only project identity
- strict manifest, hash, byte-level recompile and source verification
- owner and tenant authorization and no arbitrary Ruby injection

The original independent audit report records the pre-approval failure state;
refer to GitHub Actions for final exact-head CI and merge evidence.
