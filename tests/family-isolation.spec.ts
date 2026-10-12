import {expect,test} from '@playwright/test';

const mixed=[
  '{"action":"allow","src_ip":"198.51.100.10","dst_port":443,"private":"CUSTOMER_SECRET"}',
  'action=deny src_ip=203.0.113.10 dst_port=22 user=PRIVATE_USER',
  '{"action":"deny","src_ip":"192.0.2.15","dst_port":80,"private":"SECOND_PRIVATE"}',
].join('\n');

test('mixed JSON/KV events can be reviewed as two non-destructive browser-only families',async({page})=>{
  let backendCalls=0;
  page.on('request',request=>{
    if(request.url().includes('/api/v1/'))backendCalls++;
  });
  await page.goto('/');
  await page.getByLabel('Guided raw sample logs').fill(mixed);
  await page.getByRole('button',{name:/2\. Extract Fields/}).click();
  await page.getByRole('group',{name:'Guided format'}).getByRole('button',{name:'JSON',exact:true}).click();
  const coverage=page.getByLabel('Sample format distribution');
  await expect(coverage).toContainText('JSON');
  await expect(coverage).toContainText('Key / Value');
  const scope=page.getByLabel('Local family isolation workspace');
  await scope.locator('summary').click();
  const button=scope.getByRole('button',{name:'Preview Selected Family Locally'});
  const select=scope.getByLabel('Family for isolated browser preview');
  await expect(select).toHaveValue('json');
  await expect(button).toBeEnabled();
  expect(backendCalls).toBe(0);
  await button.click();
  const result=page.getByLabel('Isolated family browser result');
  await expect(result).toContainText('JSON · Browser-only Family Preview');
  await expect(result).toContainText('2 selected of 3 original events');
  await expect(result).toContainText('1 other-family events preserved');
  await expect(result).toContainText('Normalized 2');
  await expect(result).toContainText('Failed 0');
  await expect(page.getByLabel('Isolated event diagnostics')).toContainText('Original line 1');
  await expect(page.getByLabel('Isolated event diagnostics')).toContainText('Original line 3');
  await expect(result).not.toContainText('CUSTOMER_SECRET');
  await expect(result).not.toContainText('SECOND_PRIVATE');
  expect(backendCalls).toBe(0);

  await select.selectOption('kv');
  await expect(result).toHaveCount(0);
  await button.click();
  await expect(page.getByLabel('Isolated family browser result')).toContainText('Key / Value · Browser-only Family Preview');
  await expect(page.getByLabel('Isolated family browser result')).toContainText('1 selected of 3 original events');
  await expect(page.getByLabel('Isolated family browser result')).toContainText('2 other-family events preserved');
  await expect(page.getByLabel('Isolated family browser result')).not.toContainText('PRIVATE_USER');
  expect(backendCalls).toBe(0);

  await page.getByRole('button',{name:/1\. Import Logs/}).click();
  await expect(page.getByLabel('Guided raw sample logs')).toHaveValue(mixed);
  await page.getByRole('button',{name:/2\. Extract Fields/}).click();
  await expect(page.getByRole('group',{name:'Guided format'}).getByRole('button',{name:'JSON',exact:true}))
    .toHaveAttribute('aria-pressed','true');
  const storage=await page.evaluate(()=>JSON.stringify(localStorage));
  expect(storage).not.toContain('CUSTOMER_SECRET');
  expect(storage).not.toContain('PRIVATE_USER');
});

test('isolated preview evidence is invalidated after the sample changes',async({page})=>{
  await page.goto('/');
  await page.getByLabel('Guided raw sample logs').fill(mixed);
  await page.getByRole('button',{name:/2\. Extract Fields/}).click();
  await page.getByLabel('Local family isolation workspace').locator('summary').click();
  await page.getByRole('button',{name:'Preview Selected Family Locally'}).click();
  await expect(page.getByLabel('Isolated family browser result')).toBeVisible();

  await page.getByRole('button',{name:/1\. Import Logs/}).click();
  await page.getByLabel('Guided raw sample logs').fill('{"action":"deny","src_ip":"192.0.2.3","dst_port":53}');
  await page.getByRole('button',{name:/2\. Extract Fields/}).click();
  await expect(page.getByLabel('Isolated family browser result')).toHaveCount(0);
});

test('one-family input has no misleading split-workspace suggestion',async({page})=>{
  await page.goto('/');
  await page.getByLabel('Guided raw sample logs').fill(
    '{"action":"allow","src_ip":"192.0.2.1","dst_port":80}\n'+
    '{"action":"deny","src_ip":"192.0.2.2","dst_port":22}',
  );
  await page.getByRole('button',{name:/2\. Extract Fields/}).click();
  await page.getByRole('group',{name:'Guided format'}).getByRole('button',{name:'JSON',exact:true}).click();
  await expect(page.getByLabel('Sample format distribution')).toContainText('JSON 2');
  await expect(page.getByLabel('Local family isolation workspace')).toHaveCount(0);
});

test('unknown-only events cannot silently become an exportable isolated family',async({page})=>{
  await page.goto('/');
  await page.getByLabel('Guided raw sample logs').fill(
    'raw message with no parseable fields here\n\nunknown syntax please ignore me',
  );
  await page.getByRole('button',{name:/2\. Extract Fields/}).click();
  await expect(page.getByLabel('Sample format distribution')).toContainText('Unrecognized');
  await expect(page.getByLabel('Local family isolation workspace')).toHaveCount(0);
});


test('mixed-family review remains keyboard-operated and exposes status with text, not color alone',async({page})=>{
  await page.goto('/');
  await page.getByLabel('Guided raw sample logs').fill(mixed);
  const stage=page.getByRole('button',{name:/2\. Extract Fields/});
  await stage.focus();
  await page.keyboard.press('Enter');
  await expect(page.locator('.guided-content-head h2')).toHaveText('Which fields do you need to extract?');
  const format=page.getByRole('group',{name:'Guided format'}).getByRole('button',{name:'JSON',exact:true});
  await format.focus();
  await page.keyboard.press('Enter');
  await expect(format).toHaveAttribute('aria-pressed','true');
  const container=page.getByLabel('Local family isolation workspace');
  const summary=container.locator('summary');
  await summary.focus();
  await page.keyboard.press('Enter');
  await expect(container).toHaveAttribute('open','');
  const button=container.getByRole('button',{name:'Preview Selected Family Locally'});
  await expect(button).toBeEnabled();
  await button.focus();
  await page.keyboard.press('Enter');
  const evidence=page.getByLabel('Isolated family browser result');
  await expect(evidence).toBeVisible();
  await expect(evidence).toContainText('Failed 0');
  await expect(evidence.getByLabel('Isolated event diagnostics')).toContainText('PASS');
  await expect(evidence).not.toContainText('CUSTOMER_SECRET');
});
