import {test,expect} from '@playwright/test';

const first='relay: {"event_type":"threat","message":"로그인 실패","src_ip":"198.51.100.1"} [end]';
const second='relay: {"event_type":"threat","message":"認証失敗","src_ip":"198.51.100.2"} [end]';
const raw=first+'\n'+second;

test('beginner explicitly marks a prefix and suffix without rewriting UTF-8 sample',async({page})=>{
  await page.goto('/');
  const input=page.getByLabel('Auto Parser raw logs');
  await input.fill(raw);
  const panel=page.locator('details[aria-label="Mark a forwarding prefix or suffix"]');
  await expect(panel).toBeVisible();
  await panel.locator('summary').click();
  await input.evaluate((element:HTMLTextAreaElement)=>{
    element.focus();element.setSelectionRange(0,'relay: '.length);
  });
  await panel.getByRole('button',{name:'Mark selected prefix'}).click();
  await expect(panel.getByLabel('Declared literal prefix')).toHaveValue('relay: ');

  await input.evaluate((element:HTMLTextAreaElement)=>{
    const line=element.value.split('\n')[0]!;
    element.focus();element.setSelectionRange(line.length-' [end]'.length,line.length);
  });
  await panel.getByRole('button',{name:'Mark selected suffix'}).click();
  await expect(panel.getByLabel('Declared literal suffix')).toHaveValue(' [end]');
  const status=panel.getByLabel('Manual boundary coverage');
  await expect(status).toContainText('Matched 2 of 2 events');
  await expect(status).toContainText('Not matched 0');
  await expect(panel.getByLabel('Manually unwrapped log preview')).toHaveValue(
    '{"event_type":"threat","message":"로그인 실패","src_ip":"198.51.100.1"}'
  );
  await panel.getByLabel('Manual boundary event').selectOption('1');
  await expect(panel.getByLabel('Manually unwrapped log preview'))
    .toContainText('認証失敗');
  await expect(input).toHaveValue(raw);
  // A review-only interpretation may not claim export or native verification.
  await expect(panel).toContainText('Review only:');
  await expect(panel).toContainText('This does not rewrite the original logs');
  await panel.getByRole('button',{name:'Clear marks'}).click();
  await expect(panel.getByLabel('Declared literal prefix')).toHaveValue('');
  await expect(input).toHaveValue(raw);
});

test('different forwarding envelopes remain unmodified and clearly unscored',async({page})=>{
  const source='relay: action=deny src=192.0.2.1 [end]\n'+
    'another-relay: action=allow src=192.0.2.2 [end]';
  await page.goto('/');
  const input=page.getByLabel('Auto Parser raw logs');
  await input.fill(source);
  const panel=page.locator('details[aria-label="Mark a forwarding prefix or suffix"]');
  await panel.locator('summary').click();
  await panel.getByLabel('Declared literal prefix').fill('relay: ');
  await panel.getByLabel('Declared literal suffix').fill(' [end]');
  await expect(panel.getByLabel('Manual boundary coverage')).toContainText('Matched 1 of 2 events');
  await expect(panel.getByLabel('Manual boundary coverage')).toContainText('Not matched 1');
  await panel.getByLabel('Manual boundary event').selectOption('1');
  await expect(panel.getByLabel('Manually unwrapped log preview'))
    .toHaveValue('another-relay: action=allow src=192.0.2.2 [end]');
  await expect(input).toHaveValue(source);
  // Changing input invalidates any previous markings.
  await input.fill('action=allow src=192.0.2.3');
  await expect(panel.getByLabel('Declared literal prefix')).toHaveValue('');
  await expect(panel.getByLabel('Declared literal suffix')).toHaveValue('');
});

test('invalid mid-log selections do not silently create a forwarder rule',async({page})=>{
  await page.goto('/');
  const input=page.getByLabel('Auto Parser raw logs');
  await input.fill(raw);
  const panel=page.locator('details[aria-label="Mark a forwarding prefix or suffix"]');
  await panel.locator('summary').click();
  await input.evaluate((element:HTMLTextAreaElement)=>{
    element.focus();element.setSelectionRange(8,13);
  });
  await panel.getByRole('button',{name:'Mark selected prefix'}).click();
  await expect(panel.getByLabel('Manual boundary marking status'))
    .toContainText('A prefix must begin at the start');
  await expect(panel.getByLabel('Declared literal prefix')).toHaveValue('');
  await expect(input).toHaveValue(raw);
});

test('explicit relay hostname recognizes changing Syslog wrappers without auto-guessing',async({page})=>{
  const logs=[
    '<134>Oct 19 10:02:03 relay01 fwd: {"message":"로그인 실패","event_type":"threat"}',
    '<134>Oct 19 10:02:04 relay01 fwd: {"message":"認証失敗","event_type":"user"}',
  ].join('\n');
  await page.goto('/');
  const input=page.getByLabel('Auto Parser raw logs');
  await input.fill(logs);
  const panel=page.locator('details[aria-label="Mark a forwarding prefix or suffix"]');
  await panel.locator('summary').click();
  const relay=panel.getByLabel('Declared forwarding hosts');
  await expect(relay).toHaveValue('');
  await relay.fill('relay01');
  const counts=panel.getByLabel('Declared relay coverage');
  await expect(counts).toContainText('Recognized forwarding headers: 2 of 2');
  await expect(counts).toContainText('Needs review: 0');
  await expect(panel.getByLabel('Declared relay body')).toHaveValue(
    '{"message":"로그인 실패","event_type":"threat"}');
  await panel.getByLabel('Declared relay event').selectOption('1');
  await expect(panel.getByLabel('Declared relay body')).toContainText('認証失敗');
  await expect(input).toHaveValue(logs);
  await relay.fill('unknown-host');
  await expect(counts).toContainText('Recognized forwarding headers: 0 of 2');
  await expect(panel.getByLabel('Declared relay body')).toContainText('relay01 fwd:');
  await expect(input).toHaveValue(logs);
});

test('declared nested forwarding headers abstain when user hop budget is too low',async({page})=>{
  const raw='<134>Oct 19 10:02:03 relay01 fwd: '+
    '<134>Oct 19 10:02:04 relay02 fwd: {"message":"用户认证失败"}';
  await page.goto('/');
  const input=page.getByLabel('Auto Parser raw logs');
  await input.fill(raw);
  const panel=page.locator('details[aria-label="Mark a forwarding prefix or suffix"]');
  await panel.locator('summary').click();
  await panel.getByLabel('Declared forwarding hosts').fill('relay01,relay02');
  await expect(panel.getByLabel('Declared relay coverage'))
    .toContainText('Recognized forwarding headers: 0 of 1');
  await panel.getByLabel('Declared forwarder hop limit').selectOption('2');
  await expect(panel.getByLabel('Declared relay coverage'))
    .toContainText('Recognized forwarding headers: 1 of 1');
  await expect(panel.getByLabel('Declared relay body')).toContainText('用户认证失败');
  await expect(input).toHaveValue(raw);
});
