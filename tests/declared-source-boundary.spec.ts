import {test,expect} from '@playwright/test';

const prefix='전달:';
const suffix=':END';
const original=[
  prefix+'{"event_type":"threat","message":"로그인 실패"}'+suffix,
  prefix+'{"event_type":"user","message":"認証に失敗"}'+suffix,
].join('\n');

test('novice marks exact multilingual prefix and suffix without changing source or certifying export',async({page})=>{
  await page.goto('/');
  const source=page.getByLabel('Auto Parser raw logs');
  await source.fill(original);
  const panel=page.locator('details[aria-label="Review manually marked prefix and suffix"]');
  await expect(panel).toBeVisible();
  await panel.locator('summary').click();
  await expect(panel.getByLabel('Exact forwarder prefix')).toBeVisible();

  await source.evaluate((node,count)=>(node as HTMLTextAreaElement)
    .setSelectionRange(0,count),prefix.length);
  await panel.getByRole('button',{name:'Mark highlighted prefix'}).click();
  await expect(panel.getByLabel('Exact forwarder prefix')).toHaveValue(prefix);
  await expect(source).toHaveValue(original);

  const firstEnd=original.indexOf('\n');
  await source.evaluate((node,selection)=>(node as HTMLTextAreaElement)
    .setSelectionRange(selection.end-selection.size,selection.end),
    {end:firstEnd,size:suffix.length});
  await panel.getByRole('button',{name:'Mark highlighted suffix'}).click();
  await expect(panel.getByLabel('Exact forwarder suffix')).toHaveValue(suffix);
  const result=panel.getByLabel('Exact source boundary comparison');
  await expect(result).toContainText('2 of 2 events match exact selected text');
  await expect(panel.getByLabel('Source payload examples')).toContainText('Detected inner format: json');
  await expect(panel.getByLabel('Source payload examples')).toContainText('로그인 실패');
  await expect(panel.getByLabel('Source payload examples')).toContainText('認証に失敗');
  await expect(panel).toContainText('Parser export not verified');
  await expect(panel).toContainText('not included in generated Ruby/CONF files');
  await expect(source).toHaveValue(original);
});

test('invalid and inconsistent boundary marks stay explicit review-only',async({page})=>{
  await page.goto('/');
  const source=page.getByLabel('Auto Parser raw logs');
  await source.fill('FW:{"action":"deny"}:END\nFW:{"action":"allow"}:DIFFERENT');
  const panel=page.locator('details[aria-label="Review manually marked prefix and suffix"]');
  await panel.locator('summary').click();
  await panel.getByLabel('Exact forwarder prefix').fill('FW:');
  await panel.getByLabel('Exact forwarder suffix').fill(':END');
  await expect(panel.getByLabel('Exact source boundary comparison'))
    .toContainText('1 of 2 events match exact selected text');
  await expect(panel).toContainText('Review event lines 2');
  await expect(panel).not.toContainText('Exact markers match every sample.');
  // HTML input controls do not allow line-break markers; the standalone
  // grammar has explicit invalid-control and UTF-8 negative tests.
  await panel.getByRole('button',{name:'Clear both marks'}).click();
  await expect(panel.getByLabel('Exact source boundary comparison')).toHaveCount(0);
  await expect(source).toHaveValue('FW:{"action":"deny"}:END\nFW:{"action":"allow"}:DIFFERENT');
});
