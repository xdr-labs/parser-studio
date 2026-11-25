import {test,expect,type Page} from './support/downloadSink';
import {mkdirSync,writeFileSync} from 'node:fs';
import {readFile} from 'node:fs/promises';

// Manual mapping on a parser the Auto Parser built for several event types (owner decision of 2026-11-25): the
// user chooses an event type on Map Fields and adds, changes and removes its field matches by hand, without
// ChatGPT; the other event types keep theirs, a destination cannot be written twice in one event, and the
// downloaded parser follows the edits. Chromium with the real backend and Multi-Pass service; with MAP_TYPES_OUT
// set, the downloaded Ruby parser and the lines to run it on are written there for the Ruby 2.4.9 runner.
// SYNTHETIC lines.
const SAMPLE=[
  '<134>Nov 25 09:10:01 gw-a fwd: srcip=10.44.7.21 dstip=198.51.100.77 srcport=51522 dstport=8443 action=permit',
  '{"ts":"2026-11-25T09:10:04Z","sensor":"brisa-3","src_ip":"10.9.8.7","dst_ip":"203.0.113.40","bytes":1820}',
  'CEF:0|Tavora|Sentinel|4.2|1007|Policy hit|6|src=10.3.3.3 dst=203.0.113.9 spt=40112 dpt=22 act=blocked',
];
const RUNTIME=[
  '{"ts":"2026-11-25T09:11:00Z","sensor":"brisa-4","src_ip":"2001:db8::7","dst_ip":"2001:db8::40","bytes":7}',
  'CEF:0|Tavora|Sentinel|4.2|1008|Policy miss|3|src=10.3.3.4 dst=203.0.113.10 spt=40113 dpt=443 act=allowed',
];

test.skip(
  process.env.PARSER_STUDIO_LIVE_BACKEND!=='1' || process.env.PARSER_STUDIO_TEST_MULTIPASS!=='1',
  'Requires the exact-pinned loopback authoring backend and the Multi-Pass preview service.'
);

/** The number of the editor row whose source field is `source` (-1 when there is none). */
async function row(page:Page,source:string):Promise<number>{
  const inputs=page.getByLabel('Field mapping editor').locator('input[aria-label^="Source field "]');
  for(let index=0;index<await inputs.count();index++){
    const value=await inputs.nth(index).inputValue();
    if(value===source||value.endsWith('.'+source))
      return Number((await inputs.nth(index).getAttribute('aria-label'))!.slice('Source field '.length));
  }
  return -1;
}
async function choose(page:Page,type:string){
  await page.getByLabel('Mapping event type').selectOption(type);
  await expect(page.getByLabel('Mapping event type')).toHaveValue(type);
}

test('the field matches of one event type are added, changed and removed by hand; the parser follows',async({page})=>{
  test.setTimeout(240_000);
  await page.goto('/');
  await page.getByLabel('Auto Parser raw logs').fill(SAMPLE.join('\n'));
  await page.getByRole('button',{name:'Analyze Logs'}).click();
  await expect(page.getByLabel('Beginner analysis summary')).toContainText('3 of 3 log events structurally parsed',{timeout:30_000});
  const review=page.getByRole('button',{name:'Review Fields',exact:true}).last();
  await expect(review).toBeEnabled({timeout:30_000});
  await review.click();
  await page.getByRole('button',{name:'Map Fields',exact:true}).last().click();

  await expect(page.getByLabel('Mapping by event type')).toContainText('3 event types');
  const editor=page.getByLabel('Field mapping editor');
  const stellar=(index:number)=>editor.getByLabel('Stellar field '+index,{exact:true});

  // View: the JSON type shows its own matches, not those of the CEF type.
  await choose(page,'json');
  expect(await row(page,'src_ip')).toBeGreaterThanOrEqual(0);
  expect(await row(page,'dpt')).toBe(-1);
  await expect(stellar(await row(page,'dst_ip'))).toHaveValue('dstip');

  // Remove: src_ip is no longer matched to srcip.
  await editor.getByLabel('Remove normalization '+await row(page,'src_ip'),{exact:true}).click();
  await expect.poll(()=>row(page,'src_ip')).toBe(-1);
  // The chosen event type stays while its matches are edited.
  await expect(page.getByLabel('Mapping event type')).toHaveValue('json');
  await expect.poll(()=>row(page,'dst_ip')).toBeGreaterThanOrEqual(0);

  // Change: dst_ip now goes to the official srcip (free after the removal).
  await stellar(await row(page,'dst_ip')).fill('srcip');
  await expect(stellar(await row(page,'dst_ip'))).toHaveValue('srcip');

  // A destination cannot be written twice in one event: sensor cannot go to srcip as well.
  const sensor=await row(page,'sensor');
  if(sensor>=0){
    await stellar(sensor).fill('srcip');
    await expect(page.getByLabel('Event type mapping refusal')).toContainText('same Stellar Cyber field');
    // The text stays as typed beside the reason; the parser is not changed until the name is free.
    await expect(stellar(await row(page,'sensor'))).toHaveValue('srcip');
    await stellar(await row(page,'sensor')).fill('sensor');
    // Choosing an official field also took its value type (IP address); the name of a vendor field does not set one.
    await editor.getByLabel('Value type '+await row(page,'sensor'),{exact:true}).selectOption('string');
    await expect(page.getByLabel('Event type mapping refusal')).toHaveCount(0);
  }

  // Add: bytes gets a match by hand (an automatic vendor match of it is removed first), then a name of its own.
  if(await row(page,'bytes')>=0){
    await editor.getByLabel('Remove normalization '+await row(page,'bytes'),{exact:true}).click();
    await expect.poll(()=>row(page,'bytes')).toBe(-1);
  }
  await page.getByLabel('Source fields').getByRole('button',{name:'bytes',exact:true}).click();
  await page.getByRole('button',{name:'Keep as vendor field'}).click();
  await expect.poll(()=>row(page,'bytes')).toBeGreaterThanOrEqual(0);
  // Typed key by key: on the way the text is empty and then equals a name that is taken (the vendor name "sensor"); nothing typed
  // is lost and the name arrives (final audit F-3).
  const typed=stellar(await row(page,'bytes'));
  await typed.fill('');
  await typed.pressSequentially('sensor_bytes');
  await expect(stellar(await row(page,'bytes'))).toHaveValue('sensor_bytes');
  await expect(page.getByLabel('Event type mapping refusal')).toHaveCount(0);

  // The other event types keep their matches, and the edits of the JSON type stay.
  await choose(page,'cef');
  await expect(stellar(await row(page,'dpt'))).toHaveValue('dstport');
  await expect(stellar(await row(page,'src'))).toHaveValue('srcip');
  expect(await row(page,'dst_ip')).toBe(-1);
  await choose(page,'json');
  await expect(stellar(await row(page,'dst_ip'))).toHaveValue('srcip');
  expect(await row(page,'src_ip')).toBe(-1);
  await expect(stellar(await row(page,'bytes'))).toHaveValue('sensor_bytes');

  await page.getByRole('button',{name:'Create Parser',exact:true}).last().click();
  await page.getByText(/Run Final Test/).first().click();
  const download=page.getByText(/Download parser logic/).first();
  await expect(download).toBeVisible({timeout:60_000});
  const [file]=await Promise.all([page.waitForEvent('download'),download.click()]);
  const ruby=await readFile(await file.path(),'utf8');
  expect(ruby.length).toBeGreaterThan(1000);
  if(process.env.MAP_TYPES_OUT){
    const dir=process.env.MAP_TYPES_OUT+'/map_types';
    mkdirSync(dir,{recursive:true});
    writeFileSync(dir+'/parser.rb',ruby);
    writeFileSync(dir+'/runtime.lines',[...SAMPLE,...RUNTIME].join('\n')+'\n');
  }
});
