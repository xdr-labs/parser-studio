import { expect, test } from '@playwright/test';

test('synthetic log preview continuously mutates timestamp IP username URL until Stop, with zero sensor sends',async({page})=>{
  let apiCalls=0;
  page.on('request',request=>{if(request.url().includes('/api/v1/parser-pairs/'))apiCalls++;});
  await page.goto('/');
  await page.getByLabel('Guided raw sample logs').fill(JSON.stringify({
    timestamp:'2020-01-02T03:04:05Z',
    action:'deny',src_ip:'10.0.0.1',username:'private.user',
    url:'https://sensitive.internal.example/secret',
  }));
  await page.getByRole('button',{name:/2\. 필드 추출/}).click();
  await page.getByRole('button',{name:'JSON',exact:true}).click();
  await page.getByRole('button',{name:/6\. 파일 생성/}).click();
  await page.locator('.guided-replay-preview summary').click();
  const status=page.locator('.guided-replay-status');
  await expect(status).toContainText('실제 센서 전송 0건');
  await page.getByLabel('Replay preview rate').selectOption('5');
  await page.getByRole('button',{name:'로컬 반복 생성 시작'}).click();
  const output=page.getByLabel('Local synthetic replay output');
  await expect(output).toContainText('https://example.test/replay/');
  await expect(output).toContainText('demo_user_');
  await expect(output).toContainText('202');
  await expect(output).not.toContainText('10.0.0.1');
  await expect(output).not.toContainText('private.user');
  await expect(output).not.toContainText('sensitive.internal.example');
  await expect(status).toContainText('로컬 생성 중');
  await expect.poll(async()=>{
    const text=await status.textContent();
    return Number(/로컬 생성 (\d+)건/.exec(text??'')?.[1]??0);
  }).toBeGreaterThanOrEqual(2);
  await page.getByRole('button',{name:'로컬 반복 생성 중지'}).click();
  await expect(status).toContainText('중지됨');
  const value=Number(/로컬 생성 (\d+)건/.exec((await status.textContent())??'')?.[1]??0);
  await page.waitForTimeout(350); // More than one 5 events/s interval, ensure clean stop.
  expect(Number(/로컬 생성 (\d+)건/.exec((await status.textContent())??'')?.[1]??0)).toBe(value);
  expect(apiCalls).toBe(0);
});

test('unsupported preview format fails visibly and never pretends to start replay to a sensor',async({page})=>{
  await page.goto('/');
  await page.getByRole('button',{name:/2\. 필드 추출/}).click();
  await page.getByRole('button',{name:'Regex',exact:true}).click();
  await page.getByRole('button',{name:/6\. 파일 생성/}).click();
  await page.locator('.guided-replay-preview summary').click();
  await page.getByRole('button',{name:'로컬 반복 생성 시작'}).click();
  await expect(page.locator('.guided-replay-preview [role="alert"]')).toContainText('합성 로그 생성 실패');
  await expect(page.locator('.guided-replay-status')).toContainText('실제 센서 전송 0건');
  await expect(page.getByRole('button',{name:'로컬 반복 생성 중지'})).toHaveCount(0);
});

test('changing source sample invalidates previously running local synthetic preview',async({page})=>{
  await page.goto('/');
  await page.getByLabel('Guided raw sample logs').fill('{"timestamp":"2020-01-02T03:04:05Z","src_ip":"10.0.0.2"}');
  await page.getByRole('button',{name:/2\. 필드 추출/}).click();
  await page.getByRole('button',{name:'JSON',exact:true}).click();
  await page.getByRole('button',{name:/6\. 파일 생성/}).click();
  await page.locator('.guided-replay-preview summary').click();
  await page.getByRole('button',{name:'로컬 반복 생성 시작'}).click();
  await expect(page.locator('.guided-replay-status')).toContainText('로컬 생성 중');
  await page.getByRole('button',{name:/1\. 로그 가져오기/}).click();
  await page.getByLabel('Guided raw sample logs').fill('{"timestamp":"2020-01-02T03:04:05Z","src_ip":"10.0.0.3"}');
  await page.getByRole('button',{name:/6\. 파일 생성/}).click();
  await page.locator('.guided-replay-preview summary').click();
  await expect(page.locator('.guided-replay-status')).toContainText('로컬 생성 0건');
  await expect(page.locator('.guided-replay-status')).toContainText('중지됨');
  await expect(page.getByLabel('Local synthetic replay output')).toHaveCount(0);
});
