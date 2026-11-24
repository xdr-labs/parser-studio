import {test,expect,type Page} from './support/downloadSink';
import {mkdirSync,writeFileSync} from 'node:fs';
import {readFile} from 'node:fs/promises';

// G-5 in Chromium with the real backend and Multi-Pass service: key=value and JSON logs with source fields called
// __proto__, constructor and prototype (and a dotted key) go through the Auto Parser to the parser logic. With
// G5_OUT set, each downloaded Ruby parser and the lines to run it on are written to <G5_OUT>/<case> for the Ruby
// 2.4.9 runner, which checks that every value is kept under a name that gives the source name back. SYNTHETIC lines.
const CASES={
  kv:{sample:['src_ip=10.0.0.1 dst_ip=10.0.0.9 action=allow __proto__=p1 constructor=c1 prototype=r1',
    'src_ip=10.0.0.2 dst_ip=10.0.0.9 action=deny __proto__=p2 constructor=c2 prototype=r2'],
  runtime:['src_ip=10.0.0.3 dst_ip=10.0.0.8 action=allow __proto__=p3 constructor=c3 prototype=r3 parserstudio_key___proto__=x3']},
  json:{sample:['{"src_ip":"10.0.0.1","action":"allow","__proto__":"p1","constructor":{"name":"c1"},"a.b":"d1","a":{"b":"n1"}}',
    '{"src_ip":"10.0.0.2","action":"deny","__proto__":"p2","constructor":{"name":"c2"},"a.b":"d2","a":{"b":"n2"}}'],
  runtime:['{"src_ip":"10.0.0.3","action":"allow","__proto__":"p3","constructor":{"name":"c3"},"a.b":"d3","a":{"b":"n3"},"prototype":"r3"}']},
} as const;

test.skip(
  process.env.PARSER_STUDIO_LIVE_BACKEND!=='1' || process.env.PARSER_STUDIO_TEST_MULTIPASS!=='1',
  'Requires the exact-pinned loopback authoring backend and the Multi-Pass preview service.'
);

async function journey(page:Page,name:keyof typeof CASES){
  await page.goto('/');
  await page.getByLabel('Auto Parser raw logs').fill(CASES[name].sample.join('\n'));
  await page.getByRole('button',{name:'Analyze Logs'}).click();
  await expect(page.getByLabel('Beginner analysis summary')).toContainText('2 of 2 log events structurally parsed',{timeout:30_000});
  await page.getByRole('button',{name:'Review Fields',exact:true}).last().click();
  await page.getByRole('button',{name:'Map Fields',exact:true}).last().click();
  await page.getByRole('button',{name:'Create Parser',exact:true}).last().click();
  await page.getByText(/Run Final Test/).first().click();
  const download=page.getByText(/Download parser logic/).first();
  await expect(download).toBeVisible({timeout:60_000});
  const [file]=await Promise.all([page.waitForEvent('download'),download.click()]);
  const ruby=await readFile(await file.path(),'utf8');
  expect(ruby.length).toBeGreaterThan(1000);
  if(process.env.G5_OUT){
    const dir=process.env.G5_OUT+'/'+name;
    mkdirSync(dir,{recursive:true});
    writeFileSync(dir+'/parser.rb',ruby);
    writeFileSync(dir+'/runtime.lines',[...CASES[name].sample,...CASES[name].runtime].join('\n')+'\n');
  }
}

test('G-5: key=value fields named __proto__, constructor and prototype are parsed and kept',async({page})=>{
  test.setTimeout(180_000);
  await journey(page,'kv');
});

test('G-5: JSON members named __proto__ and constructor, and a dotted key, are parsed and kept',async({page})=>{
  test.setTimeout(180_000);
  await journey(page,'json');
});
