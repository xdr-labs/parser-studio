import {test,expect} from '@playwright/test';

test('novice marks a fixed wrapper without modifying multilingual source or certifying a parser',async({page})=>{
  const events=[
    'RELAY: {"event_type":"threat","message":"로그인 실패"} END',
    'RELAY: {"event_type":"user","message":"認証失敗"} END',
  ];
  const raw=events.join('\n');
  await page.goto('/');
  const input=page.getByLabel('Auto Parser raw logs');
  await input.fill(raw);
  const panel=page.locator('details[aria-label="Manually mark a log prefix or postfix"]');
  await expect(panel).toBeVisible();
  await panel.locator('summary').click();

  await input.evaluate((element:HTMLTextAreaElement)=>element.setSelectionRange(0,7));
  await panel.getByRole('button',{name:'Mark selection as prefix'}).click();
  const firstLineEnd=events[0]!.length;
  await input.evaluate((element:HTMLTextAreaElement,end)=>
    element.setSelectionRange(end-4,end),firstLineEnd);
  await panel.getByRole('button',{name:'Mark selection as postfix'}).click();

  await expect(panel.getByLabel('Literal boundary review status'))
    .toContainText('Exact boundary matches: 2 source events');
  const samples=panel.getByLabel('Marked payload examples');
  await expect(samples).toContainText('로그인 실패');
  await expect(samples).toContainText('認証失敗');
  await expect(samples).toContainText('Payload bytes');
  await expect(panel).toContainText('Source-only review');
  await expect(input).toHaveValue(raw);

  // An inconsistent wrapper is not guessed or silently trimmed.
  const changed=raw.replace('RELAY: {"event_type":"user"','OTHER: {"event_type":"user"');
  await input.fill(changed);
  await expect(panel.getByLabel('Literal boundary review status'))
    .toContainText('Cannot apply the selected literal wrapper consistently');
  await expect(input).toHaveValue(changed);
  await panel.getByRole('button',{name:'Clear marks'}).click();
  await expect(panel.getByLabel('Literal boundary review status'))
    .toContainText('No manual boundaries selected');
});
