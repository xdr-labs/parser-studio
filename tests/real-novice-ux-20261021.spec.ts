import {test,expect} from '@playwright/test';

test('a new user gets one Auto analysis path and real extracted fields without an advanced mode',async({page})=>{
  const pageErrors:string[]=[];
  page.on('pageerror',error=>pageErrors.push(error.message));
  await page.goto('/');
  await expect(page.getByRole('button',{name:'Tools & Diagnostics'})).toHaveCount(0);
  await expect(page.getByLabel('Deeper local log analysis',{exact:true})).toHaveCount(0);
  await expect(page.getByRole('button',{name:'Analyze Logs',exact:true})).toBeDisabled();
  const source=[
    '{"timestamp":"2026-10-21T11:12:13Z","src_ip":"192.0.2.10","dst_ip":"198.51.100.20","dst_port":443,"action":"allow"}',
    '{"timestamp":"2026-10-21T11:12:14Z","src_ip":"192.0.2.11","dst_ip":"198.51.100.20","dst_port":22,"action":"deny"}',
  ].join('\n');
  await page.getByLabel('Auto Parser raw logs').fill(source);
  await page.getByRole('button',{name:'Analyze Logs',exact:true}).click();
  const analysis=page.getByLabel('Beginner analysis summary');
  await expect(analysis).toContainText('2 of 2 log events structurally parsed',{timeout:20000});
  await expect(page.getByRole('button',{name:'Review Fields',exact:true})).toBeEnabled({timeout:10000});
  await page.getByRole('button',{name:'Review Fields',exact:true}).click();
  await expect(page.getByLabel('Review Fields stage')).toBeVisible();
  await expect(page.getByLabel('Browser-only event inspector')).toContainText('192.0.2.10');
  await page.getByRole('button',{name:'Map Fields',exact:true}).click();
  await expect(page.getByLabel('Map Fields stage')).toBeVisible();
  expect(pageErrors).toEqual([]);
});

test('real log input, not an unrelated EXAMPLE-FW sample, is used for a reviewed ChatGPT request',async({page,context})=>{
  await context.grantPermissions(['clipboard-read','clipboard-write']);
  await page.goto('/?workspace=chatgpt');
  const source=[
    'date=2026-10-21 time=11:12:13 device_id=fw01 action=blocked srcip=192.0.2.21 dstip=198.51.100.40',
    'date=2026-10-21 time=11:12:14 device_id=fw01 action=allowed srcip=192.0.2.22 dstip=198.51.100.41',
  ].join('\n');
  await page.getByLabel('ChatGPT local sample logs').fill(source);
  await expect(page.getByLabel('ChatGPT redacted examples')).toHaveCount(0);
  await expect(page.getByRole('button',{name:'Use current logs as an editable copy'})).toHaveCount(0);
  await expect(page.getByRole('alert').filter({hasText:'The ChatGPT prompt includes your original log text'})).toBeVisible();
  await expect(page.getByRole('button',{name:'Prepare ChatGPT Prompt'})).toBeEnabled();
  await page.getByRole('button',{name:'Prepare ChatGPT Prompt'}).click();
  const prompt=page.getByLabel('ChatGPT copyable prompt');
  await expect(prompt).toBeVisible({timeout:20000});
  const text=await prompt.inputValue();
  expect(text).toContain('device_id=fw01');
  expect(text).toContain(source);
  expect(text).not.toContain('EXAMPLE-FW');
  expect(text).not.toContain('If projectId is null');
  expect(text).not.toContain('projectId":null');
  expect(text).toContain('draft-demo_firewall');
  await page.getByRole('button',{name:'Copy Prompt',exact:true}).click();
  expect(await page.evaluate(()=>navigator.clipboard.readText())).toBe(text);
  // This is a real user-supplied ChatGPT diagnostic, not a valid importable JSON recipe.
  await page.getByLabel('ChatGPT result JSON').fill(
    'A backend-compatible ParserRecipe v0.2 cannot be generated safely from projectId: null.');
  await page.getByRole('button',{name:'Check ChatGPT Result'}).click();
  await expect(page.getByRole('region',{name:'ChatGPT result review'}))
    .toContainText('ChatGPT returned a diagnosis, not a parser recipe');
  await expect(page.getByLabel('ChatGPT created parser files')).toHaveCount(0);
});

test('unrecognized free-form security text has a visible recovery path without a second analysis button',async({page})=>{
  await page.goto('/');
  await page.getByLabel('Auto Parser raw logs').fill(
    '10/21-10:12:01.123456 [**] [1:2010935:3] Suspicious Access [**] {TCP} 192.0.2.4:50000 -> 198.51.100.10:443');
  await page.getByRole('button',{name:'Analyze Logs',exact:true}).click();
  const summary=page.getByLabel('Beginner analysis summary');
  await expect(summary).toBeVisible({timeout:20000});
  await expect(page.getByLabel('Deeper local log analysis',{exact:true})).toHaveCount(0);
  const status=await summary.innerText();
  expect(status).toMatch(/log event|source value|need/i);
  await expect(page.getByRole('button',{name:'Review Fields',exact:true})).toBeVisible();
});
