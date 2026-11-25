# 2026-11-25 Owner-approved Ruby Template and Template Set (PR #316)

The owner approved the following two exact SHA-256 values for PR #316 on 2026-11-25. They are the values of the
generated Ruby of commit `2f85c6af2bb3bc484adf4f730437206ddef7765e`:

| Value | SHA-256 | Constant |
|---|---|---|
| POC reviewed-template hash | `2b65c2706ebe7855cfd5a8a2086404bf5fda1ca65483c2d65437f9911dfd1466` | `KNOWN_TEMPLATES` (`backend/src/stellar-legacy-plan.ts`), `APPROVED_CURRENT_TEMPLATE_SHA256` (`backend/test/poc-template-approval.test.ts`), the proof assertion in `backend/test/stellar-legacy-plan.test.ts` |
| Template-set digest | `bb653102732e01001b5a30d4ac05b14917bb43dbe84eb484c88c409b261e0e8a` | `APPROVED_TEMPLATE_SET_SHA256` (`backend/test/template-set-approval.test.ts`), parts in `contracts/ruby-template-set.v1.json` |

Before the approval the same 64-character values were computed from the source, not copied from a document:

- CI on Node 22: the two approval tests printed them as the actual values at `d4e98cb` (run 45565260140) and at
  `cba1fbf` (run 45578740010).
- Locally on Node 24: the same two tests printed them at `cba1fbf` and at `2f85c6a`.

The generated Ruby did not change between `b2b800d` and `2f85c6a`: the commits after `b2b800d` touch
`src/guided/`, a browser-only preview in `src/parser.ts`, one verification script, tests and documents; nothing
under `backend/`, `contracts/` or `runtime/` changed, and the committed manifest
`contracts/ruby-template-set.v1.json` is in sync with the templates and the compiler at `2f85c6a`.

What the generated Ruby changes against the previous approval (`4efddd8b...`, `16824f8e...` of PR #314) and how it
was verified is recorded in the verification documents of this pull request, in particular
[`20261124-phase3-q31-unmapped-fields-fortinet-cef.md`](20261124-phase3-q31-unmapped-fields-fortinet-cef.md)
(unmapped source fields are kept as vendor fields under their original names),
[`20261125-h2-d2-pri-cef-g5.md`](20261125-h2-d2-pri-cef-g5.md) and the earlier Phase 2 and Phase 3 records of
2026-11-21 to 2026-11-24. Older owner-approved template digests remain in `KNOWN_TEMPLATES` unchanged.

The approval of the POC hash is limited to the `KNOWN_TEMPLATES` allowlist for synthetic, disposable POC writes.
It does **not** authorize production or live sensor deployment, management API activation, new tenants, or other
releases. The gates of the previous approvals
([`20261117-owner-template-approval.md`](20261117-owner-template-approval.md)) continue to apply unchanged.

With the same decision the owner approved the main merge of PR #316 after every required CI check passes, and the
update of the Development Preview (not production) with a browser check on the deployed site. The installation,
reception and indexing test on Stellar Cyber is done by the owner and is not part of this record.

Any later change of a Ruby template changes these values and needs a new owner review.
