import {test,expect} from './support/downloadSink';

// Map Fields on a parser the Auto Parser built for several event types (independent audit of e8d8d26, finding A-1).
// Each event type has its own field matches (event profiles). The screen counted only the matches shared by every
// type, so it said "Matched to Stellar 0 ... Left out of output 28" and "NO MAPPING RULE" for fields the generated
// parser maps and keeps. The summary, the source tree and a list per event type now show what the parser does.
// Chromium with the real backend and Multi-Pass service. SYNTHETIC lines.
const SAMPLE=[
  '<134>Nov 25 09:10:01 gw-a fwd: srcip=10.44.7.21 dstip=198.51.100.77 srcport=51522 dstport=8443 action=permit',
  '{"ts":"2026-11-25T09:10:04Z","sensor":"brisa-3","src_ip":"10.9.8.7","dst_ip":"203.0.113.40","bytes":1820}',
  'CEF:0|Tavora|Sentinel|4.2|1007|Policy hit|6|src=10.3.3.3 dst=203.0.113.9 spt=40112 dpt=22 act=blocked',
].join('\n');

test.skip(
  process.env.PARSER_STUDIO_LIVE_BACKEND!=='1' || process.env.PARSER_STUDIO_TEST_MULTIPASS!=='1',
  'Requires the exact-pinned loopback authoring backend and the Multi-Pass preview service.'
);

test('Map Fields shows the field matches of every event type of a multi-type parser',async({page})=>{
  test.setTimeout(180_000);
  await page.goto('/');
  await page.getByLabel('Auto Parser raw logs').fill(SAMPLE);
  await page.getByRole('button',{name:'Analyze Logs'}).click();
  await expect(page.getByLabel('Beginner analysis summary')).toContainText('3 of 3 log events structurally parsed',{timeout:30_000});
  const review=page.getByRole('button',{name:'Review Fields',exact:true}).last();
  await expect(review).toBeEnabled({timeout:30_000});
  await review.click();
  await page.getByRole('button',{name:'Map Fields',exact:true}).last().click();

  // The preview of the Syslog key=value event holds official fields, so the summary cannot say that nothing is matched.
  await page.getByLabel('Mapping event type').selectOption('rfc3164_kv');
  const preview=page.locator('.final-event-accounting + pre');
  await expect(preview).toContainText('"srcip": "10.44.7.21"');
  const summary=page.getByLabel('Field mapping summary');
  await expect(summary).not.toContainText('Matched to Stellar0');
  await expect(summary).toContainText('Left out of output0');

  // One event type at a time, with the screen of a single-type parser (see map-fields-event-type-manual).
  await expect(page.getByLabel('Mapping by event type')).toContainText('3 event types');
  await expect(page.getByLabel('Mapping event type').locator('option')).toHaveCount(3);

  // No field of the first event is reported without a rule: each one is matched or kept under its original name.
  await expect(page.getByText('NO MAPPING RULE')).toHaveCount(0);
});
