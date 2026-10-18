/// <reference lib="webworker" />
import type { ParserDraft } from './model';
import { preview } from './parser';

self.onmessage = (event: MessageEvent<{ raw: string; draft: ParserDraft }>) => {
  try {
    self.postMessage({ suite: preview(event.data.raw, event.data.draft) });
  } catch {
    self.postMessage({ error: 'Preview execution failed; no compatibility claims can be made.' });
  }
};
