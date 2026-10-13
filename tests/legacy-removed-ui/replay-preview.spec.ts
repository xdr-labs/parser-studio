import { expect, test } from '@playwright/test';

test('synthetic log preview continuously mutates timestamp IP username URL until Stop, with zero sensor sends',async({page})=>{
  let apiCalls=0;
  page.on('request',request=>{if(request.url().includes('/api/v1/parser-pairs/'))apiCalls++;});
  await page.goto('/?workspace=guided');
  await page.getByLabel('Guided raw sample logs').fill(JSON.stringify({
    timestamp:'2020-01-02T03:04:05Z',
    action:'deny',src_ip:'10.0.0.1',username:'private.user',
    url:'https://sensitive.internal.example/secret',
  }));
  await page.getByRole('button',{name:/2\. Extract Fields/}).click();
  await page.getByRole('button',{name:'JSON',exact:true}).click();
  await page.getByRole('button',{name:/6\. Generate Files/}).click();
  await page.locator('.guided-replay-preview summary').click();
  const status=page.locator('.guided-replay-status');
  await expect(status).toContainText('Sensor deliveries 0 events');
  await page.getByLabel('Replay preview rate').selectOption('5');
  await page.getByRole('button',{name:'Start Local Replay'}).click();
  const output=page.getByLabel('Local synthetic replay output');
  await expect(output).toContainText('https://example.test/replay/');
  await expect(output).toContainText('demo_user_');
  await expect(output).toContainText('202');
  await expect(output).not.toContainText('10.0.0.1');
  await expect(output).not.toContainText('private.user');
  await expect(output).not.toContainText('sensitive.internal.example');
  await expect(status).toContainText('Running locally');
  await expect.poll(async()=>{
    const text=await status.textContent();
    return Number(/Locally generated (\d+) events/.exec(text??'')?.[1]??0);
  }).toBeGreaterThanOrEqual(2);
  await page.getByRole('button',{name:'Stop Local Replay'}).click();
  await expect(status).toContainText('Stopped');
  const value=Number(/Locally generated (\d+) events/.exec((await status.textContent())??'')?.[1]??0);
  await page.waitForTimeout(350); // More than one 5 events/s interval, ensure clean stop.
  expect(Number(/Locally generated (\d+) events/.exec((await status.textContent())??'')?.[1]??0)).toBe(value);
  expect(apiCalls).toBe(0);
});

test('unsupported preview format fails visibly and never pretends to start replay to a sensor',async({page})=>{
  await page.goto('/?workspace=guided');
  await page.getByRole('button',{name:/2\. Extract Fields/}).click();
  await page.getByRole('button',{name:'Regex',exact:true}).click();
  await page.getByRole('button',{name:/6\. Generate Files/}).click();
  await page.locator('.guided-replay-preview summary').click();
  await page.getByRole('button',{name:'Start Local Replay'}).click();
  await expect(page.locator('.guided-replay-preview [role="alert"]')).toContainText('Cannot start local replay');
  await expect(page.locator('.guided-replay-status')).toContainText('Sensor deliveries 0 events');
  await expect(page.getByRole('button',{name:'Stop Local Replay'})).toHaveCount(0);
});

test('changing source sample invalidates previously running local synthetic preview',async({page})=>{
  await page.goto('/?workspace=guided');
  await page.getByLabel('Guided raw sample logs').fill('{"timestamp":"2020-01-02T03:04:05Z","src_ip":"10.0.0.2"}');
  await page.getByRole('button',{name:/2\. Extract Fields/}).click();
  await page.getByRole('button',{name:'JSON',exact:true}).click();
  await page.getByRole('button',{name:/6\. Generate Files/}).click();
  await page.locator('.guided-replay-preview summary').click();
  await page.getByRole('button',{name:'Start Local Replay'}).click();
  await expect(page.locator('.guided-replay-status')).toContainText('Running locally');
  await page.getByRole('button',{name:/1\. Import Logs/}).click();
  await page.getByLabel('Guided raw sample logs').fill('{"timestamp":"2020-01-02T03:04:05Z","src_ip":"10.0.0.3"}');
  await page.getByRole('button',{name:/6\. Generate Files/}).click();
  await page.locator('.guided-replay-preview summary').click();
  await expect(page.locator('.guided-replay-status')).toContainText('Locally generated 0 events');
  await expect(page.locator('.guided-replay-status')).toContainText('Stopped');
  await expect(page.getByLabel('Local synthetic replay output')).toHaveCount(0);
});

test('all provided single-line JSON samples rotate in order and stop when leaving export step', async({page}) => {
  const events = [
    '{"action":"allow","timestamp":"2020-01-02T03:04:05Z","src_ip":"10.0.0.1","user":"alpha"}',
    '{"action":"deny","timestamp":"2020-01-02T03:04:06Z","src_ip":"10.0.0.2","user":"beta"}',
    '{"action":"alert","timestamp":"2020-01-02T03:04:07Z","src_ip":"10.0.0.3","user":"gamma"}',
  ].join('\n');
  let apiCalls = 0;
  page.on('request', request => { if (request.url().includes('/api/v1/parser-pairs/')) apiCalls++; });
  await page.goto('/?workspace=guided');
  await page.getByLabel('Guided raw sample logs').fill(events);
  await page.getByRole('button', { name: /2\. Extract Fields/ }).click();
  await page.getByRole('button', { name: 'JSON', exact:true }).click();
  await page.getByRole('button', { name: /6\. Generate Files/ }).click();
  await page.locator('.guided-replay-preview summary').click();
  await page.getByLabel('Replay preview rate').selectOption('2');
  await page.getByRole('button', { name: 'Start Local Replay' }).click();
  const status = page.locator('.guided-replay-status');
  const output = page.getByLabel('Local synthetic replay output');
  await expect(status).toContainText('Source 1/3 (line 1)');
  await expect(output).toContainText('"action":"allow"');
  await expect.poll(async () => await status.textContent(), { timeout: 6000 })
    .toContain('Source 2/3 (line 2)');
  await expect(output).toContainText('"action":"deny"');
  await expect.poll(async () => await status.textContent(), { timeout: 6000 })
    .toContain('Source 3/3 (line 3)');
  await expect.poll(async () => await status.textContent(), { timeout: 6000 })
    .toContain('Source 1/3 (line 1)');
  await expect(status).toContainText('Sensor deliveries 0 events');
  await page.getByRole('button', { name: /5\. Test & Fix/ }).click();
  await page.getByRole('button', { name: /6\. Generate Files/ }).click();
  await page.locator('.guided-replay-preview summary').click();
  await expect(status).toContainText('Stopped');
  expect(apiCalls).toBe(0);
});

test('invalid later log record rejects all replay before any partial output or network call', async({page})=>{
  let apiCalls=0;
  page.on('request', request=>{ if(request.url().includes('/api/v1/parser-pairs/'))apiCalls++; });
  await page.goto('/?workspace=guided');
  await page.getByLabel('Guided raw sample logs').fill('{"action":"allow"}\naction=deny');
  await page.getByRole('button', { name:/2\. Extract Fields/ }).click();
  await page.getByRole('button', { name:'JSON', exact:true }).click();
  await page.getByRole('button', { name:/6\. Generate Files/ }).click();
  await page.locator('.guided-replay-preview summary').click();
  await page.getByRole('button',{name:'Start Local Replay'}).click();
  await expect(page.locator('.guided-replay-status')).toContainText('Locally generated 0 events');
  await expect(page.locator('.guided-replay-status')).toContainText('Stopped');
  await expect(page.locator('.guided-replay-preview [role="alert"]')).toContainText('Cannot start local replay');
  await expect(page.getByLabel('Local synthetic replay output')).toHaveCount(0);
  expect(apiCalls).toBe(0);
});
