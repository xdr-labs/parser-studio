/// <reference lib="webworker" />
import type { ParserDraft } from './model';
import { preview } from './parser';
import { accountResidualRegions, type ResidualRegion } from './guided/residualProvenance';

type PreviewRequest = { raw: string; draft: ParserDraft; residualRegions?: undefined };
type ResidualRequest = { raw: string; draft: ParserDraft; residualRegions: ResidualRegion[][] };

self.onmessage = (event: MessageEvent<PreviewRequest | ResidualRequest>) => {
  try {
    const { raw, draft, residualRegions } = event.data;
    // Residual provenance runs a candidate's regular expression, so it stays in this isolated worker too.
    if (residualRegions) self.postMessage({ accounting: accountResidualRegions(raw, draft, residualRegions) });
    else self.postMessage({ suite: preview(raw, draft) });
  } catch {
    self.postMessage({ error: 'Preview execution failed; no compatibility claims can be made.' });
  }
};
