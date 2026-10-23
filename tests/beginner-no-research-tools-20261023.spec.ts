import {test,expect} from '@playwright/test';

test('first-time Auto Parser keeps only actionable options, not research-only grouping tools',async({page})=>{
  await page.goto('/');
  await expect(page.getByRole('main',{name:'Auto Parser v2'})).toBeVisible();
  await expect(page.getByLabel('Private text grouping tool')).toHaveCount(0);
  await expect(page.getByLabel('Known log shape matcher')).toHaveCount(0);
  await expect(page.getByRole('button',{name:'Group Similar Unknown Shapes'})).toHaveCount(0);
  await expect(page.getByLabel('Manually mark a log prefix or postfix')).toBeVisible();
  await expect(page.getByLabel('Python test sender',{exact:true})).toBeVisible();
  await expect(page.getByLabel('Existing parser review and import')).toBeVisible();
  await expect(page.getByRole('button',{name:'Analyze Logs',exact:true})).toBeDisabled();
  await page.getByLabel('Auto Parser raw logs').fill(
    '{"event_type":"alert","src_ip":"192.0.2.1","dst_ip":"198.51.100.2","action":"deny"}');
  await page.getByRole('button',{name:'Analyze Logs',exact:true}).click();
  await expect(page.getByLabel('Beginner analysis summary'))
    .toContainText('1 of 1 log event parsed completely',{timeout:20000});
  await expect(page.getByLabel('Private text grouping tool')).toHaveCount(0);
  await expect(page.getByLabel('Known log shape matcher')).toHaveCount(0);
});
