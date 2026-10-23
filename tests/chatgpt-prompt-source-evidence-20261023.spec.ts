import {test,expect} from '@playwright/test';
import {createHash} from 'node:crypto';

const fixtures=[
  {
    name:'Zeek',
    source:['#separator \\x09','#fields\tts\tuid\tid.orig_h\tid.resp_h\tproto',
       '1760832000.000\tCw01\t192.0.2.10\t198.51.100.3\ttcp',
       '1760832001.000\tCw02\t192.0.2.11\t198.51.100.4\tudp'].join('\n'),
    physical:4,header:2,logical:2,code:'ZEEK_DECLARED',
  },
  {
    name:'W3C',
    source:['#Version: 1.0','#Fields: date time c-ip cs-method cs-uri-stem sc-status',
      '2026-10-23 12:11:13 192.0.2.10 GET /login 403'].join('\n'),
    physical:3,header:2,logical:1,code:'W3C_DECLARED',
  },
] as const;

for(const item of fixtures){
  test(item.name+' data events differ from original physical records in a safe manually copied prompt',async({page})=>{
    const js:string[]=[],outside:string[]=[];
    page.on('pageerror',err=>js.push(err.message));
    await page.goto('/');
    page.on('request',req=>{if(/^https?:/.test(req.url())&&!req.url().startsWith(new URL(page.url()).origin+'/'))outside.push(req.url())});
    await page.getByLabel('Auto Parser raw logs').fill(item.source);
    await page.getByRole('button',{name:'Analyze Logs',exact:true}).click();
    await expect(page.getByLabel('Beginner analysis summary')).toContainText(item.logical+' event',{timeout:25000});
    await page.getByRole('button',{name:'ChatGPT Assisted Parser',exact:true}).click();
    await expect(page.getByLabel('ChatGPT local sample logs')).toHaveValue(item.source);
    await page.getByRole('button',{name:'Prepare ChatGPT Prompt'}).click();
    const prompt=page.getByLabel('ChatGPT copyable prompt');
    await expect(prompt).toBeVisible({timeout:25000});
    const text=await prompt.inputValue();
    expect(text).toContain('"schema":"'+item.code+'"');
    expect(text).toContain('"headerLines":'+item.header);
    expect(text).toContain('"logicalDataRows":'+item.logical);
    expect(text).toContain('not the logical data-event count ('+item.logical+')');
    expect(text).toContain('Respond REVIEW_REQUIRED:');
    expect(text).toContain('no deployable recipe');
    const meta=text.match(/\{"projectId":"([^"]+)","sourceHash":"([a-f0-9]{64})","sourceCount":(\d+)\}/);
    expect(meta).not.toBeNull();
    expect(Number(meta![3])).toBe(item.physical);
    expect(meta![2]).toBe(createHash('sha256').update(item.source).digest('hex'));
    await page.getByLabel('ChatGPT result JSON').fill('REVIEW_REQUIRED: Original header-dependent source needs separate schema/data review, not a generated parser.');
    await page.getByRole('button',{name:'Check ChatGPT Result'}).click();
    await expect(page.getByRole('region',{name:'ChatGPT result review'})).toContainText('diagnosis, not a parser recipe');
    await expect(page.getByLabel('ChatGPT created parser files')).toHaveCount(0);
    expect(js).toEqual([]);expect(outside).toEqual([]);
  });
}

test('normal JSON prompt contains local grammar evidence, and unchanged baseline does not claim untested holdout',async({page})=>{
  const raw='{"timestamp":"2026-10-23T12:11:13Z","src_ip":"192.0.2.10","action":"deny"}';
  await page.goto('/?workspace=chatgpt');
  await page.getByLabel('ChatGPT local sample logs').fill(raw);
  await page.getByRole('button',{name:'Prepare ChatGPT Prompt'}).click();
  const input=page.getByLabel('ChatGPT copyable prompt');
  await expect(input).toBeVisible({timeout:25000});
  const prompt=await input.inputValue();
  expect(prompt).toContain('"body":"json"');
  expect(prompt).toContain('"unrecognizedSourceRecords":0');
  const marker='----- BEGIN VALIDATED BASELINE RECIPE -----\n';
  const end='\n----- END VALIDATED BASELINE RECIPE -----';
  const a=prompt.indexOf(marker),b=prompt.indexOf(end,a+marker.length);
  expect(a).toBeGreaterThan(-1);expect(b).toBeGreaterThan(a);
  const baseline=JSON.parse(prompt.slice(a+marker.length,b));
  await page.getByLabel('ChatGPT result JSON').fill(JSON.stringify(baseline));
  await page.getByRole('button',{name:'Check ChatGPT Result'}).click();
  await expect(page.getByLabel('ChatGPT result ready for testing')).toContainText('accepted for testing',{timeout:20000});
  await page.getByRole('button',{name:'Apply Fix & Create Parser Files'}).click();
  const files=page.getByLabel('ChatGPT created parser files');
  await expect(files).toContainText('Parser files created successfully',{timeout:23000});
  await expect(files).toContainText('No different holdout examples were tested');
  await expect(files).not.toContainText('additional examples passed');
});

test('unsupported freeform Snort syntax stays unrecognized instead of making up grammar',async({page})=>{
  const snort='10/23-12:11:13 [**] [1:1000:0] Snort Alert [**] {TCP} 192.0.2.10:5123 -> 198.51.100.5:443';
  await page.goto('/?workspace=chatgpt');
  await page.getByLabel('ChatGPT local sample logs').fill(snort);
  await page.getByRole('button',{name:'Prepare ChatGPT Prompt'}).click();
  const prompt=page.getByLabel('ChatGPT copyable prompt');
  await expect(prompt).toContainText('"unrecognizedSourceRecords":1',{timeout:20000});
  await expect(prompt).toContainText('Never invent a vendor grammar');
});
