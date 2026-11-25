import {test,expect,type Page} from './support/downloadSink';
import {mkdirSync,writeFileSync} from 'node:fs';
import {readFile} from 'node:fs/promises';

// The offer "Create the parser for the readable events" follows the verdicts the Auto Parser goes on with: the
// server analysis and the first scan, not the browser preview alone (2026-11-25). Before, the offer kept events the
// journey then refused (an RFC 5424 line with VERSION 2, a Syslog line whose free text needs a rule), and the sample
// of readable events stopped again with no way forward. Chromium with the real backend and Multi-Pass service, down
// to the parser logic file. With READABLE_GATE_OUT set, each downloaded Ruby parser and every original line of its
// sample are written to <READABLE_GATE_OUT>/<case> for the Ruby 2.4.9 runner. SYNTHETIC lines.
const V=(version:number,n:number)=>'<165>'+version+' 2026-11-13T10:00:0'+n+'Z edge fw 12'+n+' ID'+n+' - srcip=10.1.1.'+n+
  ' dstip=203.0.113.'+(8+n)+' srcport=100'+n+' dstport=443 action=allow';
const CASES={
  versions:[V(1,1),V(2,2),V(12,3)],
  free_text:[
    '<38>Nov 13 10:00:00 host1 sshd[1234]: Failed password for root from 203.0.113.5 port 22 ssh2',
    '<134>Nov 13 10:00:01 host2 myfw: srcip=10.1.1.1 dstip=203.0.113.9 srcport=1000 dstport=443 action=allow',
    '<134>Nov 13 10:00:02 host2 myfw: srcip=10.2.2.2 dstip=203.0.113.10 srcport=2000 dstport=80 action=deny'],
} as const;

test.skip(
  process.env.PARSER_STUDIO_LIVE_BACKEND!=='1' || process.env.PARSER_STUDIO_TEST_MULTIPASS!=='1',
  'Requires the exact-pinned loopback authoring backend and the Multi-Pass preview service.'
);

async function analyze(page:Page,lines:readonly string[]){
  await page.goto('/');
  await page.getByLabel('Auto Parser raw logs').fill(lines.join('\n'));
  await page.getByRole('button',{name:'Analyze Logs'}).click();
  await expect(page.getByLabel('Beginner analysis summary')).toContainText('log events structurally parsed',{timeout:30_000});
}

async function createAndDownload(page:Page,name:keyof typeof CASES){
  const review=page.getByRole('button',{name:'Review Fields',exact:true}).last();
  await expect(review).toBeEnabled({timeout:30_000});
  await review.click();
  await page.getByRole('button',{name:'Map Fields',exact:true}).last().click();
  await page.getByRole('button',{name:'Create Parser',exact:true}).last().click();
  await page.getByText(/Run Final Test/).first().click();
  const download=page.getByText(/Download parser logic/).first();
  await expect(download).toBeVisible({timeout:60_000});
  const [file]=await Promise.all([page.waitForEvent('download'),download.click()]);
  const ruby=await readFile(await file.path(),'utf8');
  expect(ruby.length).toBeGreaterThan(1000);
  if(process.env.READABLE_GATE_OUT){
    const dir=process.env.READABLE_GATE_OUT+'/'+name;
    mkdirSync(dir,{recursive:true});
    writeFileSync(dir+'/parser.rb',ruby);
    writeFileSync(dir+'/runtime.lines',CASES[name].join('\n')+'\n');
  }
}

test('an RFC 5424 line with VERSION 2 is not offered as read completely; the parser is created for the VERSION 1 event',async({page})=>{
  test.setTimeout(180_000);
  await analyze(page,CASES.versions);
  const offer=page.getByLabel('Readable events',{exact:true});
  await expect(offer).toContainText('1 of 3 events were read completely',{timeout:15_000});
  await expect(offer.getByRole('button',{name:'Continue with readable events'})).toHaveText('Create the parser for the 1 readable event');
  // The screen does not say that the user cannot go on while it offers a way to go on.
  await expect(page.getByText('will not let you continue')).toHaveCount(0);
  await expect(page.getByText('Resolve the events marked above before continuing')).toHaveCount(0);
  await offer.getByRole('button',{name:'Continue with readable events'}).click();
  await expect(page.getByLabel('Auto Parser raw logs')).toHaveValue(CASES.versions[0]);
  await expect(page.getByLabel('Events not covered by this parser')).toContainText('This parser covers 1 of your 3 events');
  await expect(page.getByLabel('Beginner analysis summary')).toContainText('1 of 1 log event structurally parsed',{timeout:30_000});
  await createAndDownload(page,'versions');
});

test('a Syslog line whose free text needs a rule is left out; the parser is created for the key=value events',async({page})=>{
  test.setTimeout(180_000);
  await analyze(page,CASES.free_text);
  const offer=page.getByLabel('Readable events',{exact:true});
  await expect(offer).toContainText('2 of 3 events were read completely',{timeout:15_000});
  await expect(offer.getByRole('button',{name:'Continue with readable events'})).toHaveText('Create the parser for the 2 readable events');
  await expect(page.getByText('will not let you continue')).toHaveCount(0);
  await offer.getByRole('button',{name:'Continue with readable events'}).click();
  await expect(page.getByLabel('Auto Parser raw logs')).toHaveValue(CASES.free_text.slice(1).join('\n'));
  await expect(page.getByLabel('Beginner analysis summary')).toContainText('2 of 2 log events structurally parsed',{timeout:30_000});
  await createAndDownload(page,'free_text');
});

test('a sample that cannot go on and has no readable event still says so',async({page})=>{
  await analyze(page,[CASES.versions[1],CASES.versions[2]]);
  await expect(page.getByLabel('Readable events',{exact:true})).toHaveCount(0);
  await expect(page.getByText('Resolve the events marked above before continuing')).toBeVisible();
  await expect(page.getByRole('button',{name:'Review Fields',exact:true}).last()).toBeDisabled();
});
