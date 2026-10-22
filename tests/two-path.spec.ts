import {test,expect} from '@playwright/test';

test('Parser Studio exposes exactly two parser creation methods, never old Wizard or Workbench',async({page})=>{
  await page.goto('/');
  const nav=page.getByRole('complementary',{name:'Parser Studio navigation'});
  await expect(nav).toBeVisible();
  await expect(nav.locator('button.rail-link')).toHaveCount(2);
  await expect(nav.getByRole('button',{name:'Auto Parser',exact:true})).toBeVisible();
  await expect(nav.getByRole('button',{name:'ChatGPT Assisted Parser',exact:true})).toBeVisible();
  await expect(page.getByRole('button',{name:'Ask ChatGPT about an unfamiliar log'})).toHaveCount(0);
  await expect(page.getByRole('main',{name:'Auto Parser v2'})).toBeVisible();
  await expect(page.getByLabel('Auto Parser raw logs')).toBeVisible();
  await expect(page.getByLabel('No-code Parser Guided Builder')).toHaveCount(0);
  await expect(page.getByRole('button',{name:/Edit Details|Expert Workbench|Advanced Wizard/})).toHaveCount(0);
  await expect(page.getByLabel('Optional privacy-safe AI recipe exchange')).toHaveCount(0);
  await expect(page.getByLabel('Optional integrated AI review')).toHaveCount(0);
  await nav.getByRole('button',{name:'ChatGPT Assisted Parser',exact:true}).click();
  await expect(page.getByRole('main',{name:'ChatGPT Assisted Parser',exact:true})).toBeVisible();
  await expect(page.getByLabel('ChatGPT redacted examples')).toHaveCount(0);
  await expect(page.getByRole('alert').filter({hasText:'The ChatGPT prompt includes your original log text'})).toBeVisible();
  await expect(page.getByRole('button',{name:/Edit Details|Expert Workbench/})).toHaveCount(0);
  await nav.getByRole('button',{name:'Auto Parser',exact:true}).click();
  await expect(page.getByRole('main',{name:'Auto Parser v2'})).toBeVisible();
});

test('previous Guided and Expert deep links cannot reveal retired authoring pages',async({page})=>{
  test.setTimeout(60_000);
  for(const old of ['guided','expert','workbench','library','schema']){
    await page.goto('/?workspace='+old);
    await expect(page.getByRole('main',{name:'Auto Parser v2'})).toBeVisible();
    await expect(page.getByRole('complementary',{name:'Parser Studio navigation'})
      .locator('button.rail-link')).toHaveCount(2);
    await expect(page.getByRole('main',{name:'No-code Parser Guided Builder'})).toHaveCount(0);
    await expect(page.getByRole('region',{name:'Parser pipeline rules'})).toHaveCount(0);
  }
  await page.goto('/?workspace=chatgpt');
  await expect(page.getByRole('main',{name:'ChatGPT Assisted Parser',exact:true})).toBeVisible();
});

test('ChatGPT Assisted displays a warning and includes the actual logs only in a manually copied prompt',async({page})=>{
  const original='SECRET_SOURCE_ID_12345 unrecognized original log';
  const requests:string[]=[];
  page.on('request',req=>requests.push(req.url()));
  await page.route('**/api/v1/parser-pairs/capabilities',route=>
    route.fulfill({status:503,contentType:'application/json',
      body:JSON.stringify({error:'BACKEND_UNAVAILABLE'})}));
  await page.goto('/?workspace=chatgpt');
  await page.getByLabel('ChatGPT local sample logs').fill(original);
  await page.getByLabel('ChatGPT desired fields').fill('Extract the timestamp and action if known.');
  await expect(page.getByLabel('ChatGPT redacted examples')).toHaveCount(0);
  await expect(page.getByRole('alert').filter({hasText:'The ChatGPT prompt includes your original log text'})).toBeVisible();
  await expect(page.getByRole('button',{name:'Prepare ChatGPT Prompt'})).toBeEnabled();
  await page.getByRole('button',{name:'Prepare ChatGPT Prompt'}).click();
  await expect(page.getByLabel('ChatGPT prepared prompt')).toBeVisible();
  const prompt=await page.getByLabel('ChatGPT copyable prompt').inputValue();
  expect(prompt).toContain(original);
  expect(prompt).toContain('BEGIN ORIGINAL LOG SOURCE');
  expect(prompt).toContain('REVIEW_ONLY');
  expect(prompt).toContain('untrusted data');
  expect(prompt).not.toContain('projectId":null');
  expect(requests.some(url=>/chatgpt\.com|openai\.com|api\.openai\.com/.test(url))).toBe(false);
  await page.getByLabel('ChatGPT result JSON').fill('{"op":"eval","ruby":"EXECUTE"}');
  await page.getByRole('button',{name:'Check ChatGPT Result'}).click();
  await expect(page.getByRole('region',{name:'ChatGPT result review'}))
    .toContainText('ChatGPT result rejected');
  await expect(page.getByLabel('ChatGPT created parser files')).toHaveCount(0);
});

test('editing the original source revokes the old prompt and rebuilds the correct source identity',async({page})=>{
  await page.goto('/?workspace=chatgpt');
  const logs=page.getByLabel('ChatGPT local sample logs');
  await logs.fill('action=deny src_ip=192.0.2.20');
  const prepare=page.getByRole('button',{name:'Prepare ChatGPT Prompt'});
  await expect(prepare).toBeEnabled();
  await prepare.click();
  await expect(page.getByLabel('ChatGPT prepared prompt')).toBeVisible();
  await expect(page.getByLabel('ChatGPT copyable prompt')).toContainText('src_ip=192.0.2.20');
  await logs.fill('action=deny src_ip=192.0.2.21');
  await expect(page.getByLabel('ChatGPT prepared prompt')).toHaveCount(0);
  await expect(prepare).toBeEnabled();
  await prepare.click();
  const prompt=page.getByLabel('ChatGPT copyable prompt');
  await expect(prompt).toContainText('src_ip=192.0.2.21');
  await expect(prompt).not.toContainText('src_ip=192.0.2.20');
  await expect(prompt).toHaveJSProperty('readOnly',false);
  await expect(page.getByLabel('ChatGPT redacted examples')).toHaveCount(0);
});

test('mobile viewport preserves both creation paths and has no horizontal overflow',async({page})=>{
  await page.setViewportSize({width:390,height:844});
  await page.goto('/');
  const nav=page.getByRole('complementary',{name:'Parser Studio navigation'});
  await expect(nav.locator('button.rail-link')).toHaveCount(2);
  await expect(page.getByRole('main',{name:'Auto Parser v2'})).toBeVisible();
  const initial=await page.evaluate(()=>({
    viewport:innerWidth,width:document.documentElement.scrollWidth,
  }));
  expect(initial.width).toBeLessThanOrEqual(initial.viewport+1);
  await nav.getByRole('button',{name:'ChatGPT Assisted Parser',exact:true}).click();
  await expect(page.getByRole('main',{name:'ChatGPT Assisted Parser',exact:true})).toBeVisible();
  const next=await page.evaluate(()=>({
    viewport:innerWidth,width:document.documentElement.scrollWidth,
  }));
  expect(next.width).toBeLessThanOrEqual(next.viewport+1);
});
