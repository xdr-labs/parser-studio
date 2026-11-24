import {test,expect,type Page} from './support/downloadSink';
import {mkdirSync,writeFileSync} from 'node:fs';
import {readFile} from 'node:fs/promises';

// Auto Parser journeys in Chromium with the real backend and Multi-Pass service, down to the parser logic file:
// - owner decision D-2: RFC 5424 messages that only claim CEF (`CEF : 3 alerts today`) are read with their envelope,
//   kept whole as text and reported as not completely parsed (never as CEF, never FULL);
// - a bare PRI before CEF (`<189>CEF:0|`, FortiGate `<189>CEF: 0|`) is read as CEF with the PRI kept.
// With D2_PRI_OUT set, each downloaded Ruby parser and the lines to run it on are written to <D2_PRI_OUT>/<case> for
// the Ruby 2.4.9 runner. SYNTHETIC lines.
const H5='<134>1 2026-11-24T10:00:00Z host1 app 123 - - ';
const CASES={
  d2:{sample:[H5+'service restarted',H5+'CEF : 3 alerts today'],
    runtime:[H5+'CEF :0|A|B|1|2|n|3|x',H5+'LEEF : 2 events',H5+'CEF : 12 alerts today',H5+'service stopped']},
  pri_cef:{sample:[
    '<189>CEF:0|Fortinet|Fortigate|v6.0.3|00013|traffic:forward close|3|src=10.1.100.11 spt=54190 dst=52.53.140.235 dpt=443 act=close',
    '<189>CEF: 0|Fortinet|Fortigate|v6.0.3|00013|traffic:forward accept|3|src=10.1.100.12 spt=58843 dst=52.53.140.236 dpt=443 act=accept'],
  runtime:['<190>CEF:0|Fortinet|Fortigate|v6.0.3|00014|traffic:forward deny|4|src=10.1.100.13 spt=1234 dst=52.53.140.237 dpt=80 act=deny msg=a\\=b',
    '<0>CEF: 0|Fortinet|Fortigate|v6.0.3|00013|traffic:forward close|3|src=10.1.100.14 spt=40000 dst=52.53.140.238 dpt=8443 act=close']},
} as const;

test.skip(
  process.env.PARSER_STUDIO_LIVE_BACKEND!=='1' || process.env.PARSER_STUDIO_TEST_MULTIPASS!=='1',
  'Requires the exact-pinned loopback authoring backend and the Multi-Pass preview service.'
);

async function createAndDownload(page:Page,name:keyof typeof CASES){
  await page.getByRole('button',{name:'Review Fields',exact:true}).last().click();
  await page.getByRole('button',{name:'Map Fields',exact:true}).last().click();
  await page.getByRole('button',{name:'Create Parser',exact:true}).last().click();
  await page.getByText(/Run Final Test/).first().click();
  const download=page.getByText(/Download parser logic/).first();
  await expect(download).toBeVisible({timeout:60_000});
  const [file]=await Promise.all([page.waitForEvent('download'),download.click()]);
  const ruby=await readFile(await file.path(),'utf8');
  expect(ruby.length).toBeGreaterThan(1000);
  if(process.env.D2_PRI_OUT){
    const dir=process.env.D2_PRI_OUT+'/'+name;
    mkdirSync(dir,{recursive:true});
    writeFileSync(dir+'/parser.rb',ruby);
    writeFileSync(dir+'/runtime.lines',[...CASES[name].sample,...CASES[name].runtime].join('\n')+'\n');
  }
}

test('D-2: RFC 5424 messages that only claim CEF are not completely parsed, so nothing is generated from them alone',async({page})=>{
  test.setTimeout(120_000);
  await page.goto('/');
  await page.getByLabel('Auto Parser raw logs').fill([H5+'CEF : 3 alerts today',H5+'CEF :0|A|B|1|2|n|3|x'].join('\n'));
  await page.getByRole('button',{name:'Analyze Logs'}).click();
  const summary=page.getByLabel('Beginner analysis summary');
  await expect(summary).toContainText('0 of 2 log events structurally parsed',{timeout:30_000});
  await expect(summary.getByRole('heading',{name:'Part of this event still needs parsing'})).toBeVisible();
  await expect(summary.locator('mark').first()).toHaveText('CEF : 3 alerts today');
  await expect(summary.getByRole('button',{name:'Fix with ChatGPT'})).toBeVisible();
  await expect(page.getByRole('button',{name:'Review Fields',exact:true}).last()).toBeDisabled();
});

test('D-2: with a plain message in the sample, the parser keeps such messages whole with their envelope',async({page})=>{
  test.setTimeout(180_000);
  await page.goto('/');
  await page.getByLabel('Auto Parser raw logs').fill(CASES.d2.sample.join('\n'));
  await page.getByRole('button',{name:'Analyze Logs'}).click();
  await expect(page.getByLabel('Beginner analysis summary')).toContainText('1 of 2 log events structurally parsed',{timeout:30_000});
  // Owner rule (2026-11-22): a parser is created for the readable events; the other one stays marked.
  await page.getByRole('button',{name:/Continue with readable events/}).click();
  await createAndDownload(page,'d2');
});

test('a bare PRI before CEF (<189>CEF:0| and <189>CEF: 0|) is read as CEF with the PRI',async({page})=>{
  test.setTimeout(180_000);
  await page.goto('/');
  await page.getByLabel('Auto Parser raw logs').fill(CASES.pri_cef.sample.join('\n'));
  await page.getByRole('button',{name:'Analyze Logs'}).click();
  await expect(page.getByLabel('Beginner analysis summary')).toContainText('2 of 2 log events structurally parsed',{timeout:30_000});
  await createAndDownload(page,'pri_cef');
});
