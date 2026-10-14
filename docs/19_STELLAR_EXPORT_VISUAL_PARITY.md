# Parser Studio — Stellar Data Exporter visual parity

Approved direction: use the Auto Parser single-workspace mockup with input, color-highlighted source results, extracted field table, missing regions and contextual Improve with AI panel. The two creation paths remain Auto Parser and ChatGPT Assisted Parser. Whole-log AI fallback and selected-region correction are in the product roadmap; visual-theme work does not claim they are fully implemented.

**Design authority:** `xdr-labs/stellar-data-exporter`, `origin/main:app/static/styles.css` inspected 2026-10-14. Use its actual Inter/system typography, orange `#f05b29` primary, gold `#f8ae41`, charcoal `#231f20`, navy `#11131a`, background `#f5f5f6`, white panels, border `#dfdddf`, green `#138a63`, red `#c83f4d`, radius 8–14px, light card shadows, white header with orange top border, and responsive stacked layout. Do not retain the purple/teal colors of the initial image mockup.

**Semantic highlight policy:** green means proven parsed span, amber means residual/uncertain, blue `#3549a5` means the user's selection; status colors must not be confused with primary CTA orange. Full-log fallback is offered on RAW_ONLY; selected-area repair on PARTIAL, wrong or user-requested changes. Do not claim false completion or silently overwrite accepted fields.

**Implementation phase 1:** `src/guided/stellarExportTheme.css` is an additive scoped visual layer on the existing two-path UI; source CSS and logo files from Stellar Data Exporter are not copied. Phase 2 requires dedicated Auto Parser result layout, exact byte-range selection, AI copy/paste validation, browser screenshots, responsive checks, and backend integration. Preserve existing UI WIP and do not merge/deploy without verification.
