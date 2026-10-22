import {test,expect} from '@playwright/test';

test('new user cannot skip required analysis, but reaches normal review without advanced mode',async({page})=>{
  await page.goto('/');
  await expect(page.locator('body')).toContainText('AUTO PARSER · GUIDED MODE');
  await expect(page.getByRole('button',{name:'Tools & Diagnostics'})).toHaveCount(0);
  await expect(page.getByLabel('Deeper local log analysis',{exact:true})).toHaveCount(0);

  await page.getByRole('button',{name:/Map Fields/}).click();
  await expect(page.getByLabel('Add Logs stage')).toBeVisible();
  await expect(page.locator('.beginner-navigation-hint')).toContainText('Start with Add Logs');

  await page.getByRole('button',{name:/Create Parser/}).click();
  await expect(page.getByLabel('Add Logs stage')).toBeVisible();
  await expect(page.locator('.beginner-navigation-hint')).toContainText('Analyze the sample');

  const sample=[
    '{"src_ip":"192.0.2.10","dst_ip":"198.51.100.10","dst_port":443,"action":"allow"}',
    '{"src_ip":"192.0.2.11","dst_ip":"198.51.100.11","dst_port":22,"action":"deny"}',
  ].join('\n');
  await page.getByLabel('Auto Parser raw logs').fill(sample);
  await page.getByRole('button',{name:'Analyze Logs',exact:true}).click();
  const review=page.getByRole('button',{name:'Review Fields',exact:true});
  await expect(review).toBeEnabled({timeout:20000});
  await review.click();
  await expect(page.getByLabel('Review Fields stage')).toBeVisible();

  await page.getByRole('button',{name:/Create Parser/}).click();
  await expect(page.getByLabel('Map Fields stage')).toBeVisible();
  await expect(page.locator('.beginner-navigation-hint')).toContainText('moved you to Map Fields');
});

test('the single Analyze Logs workflow retains beginner contextual help',async({page})=>{
  await page.goto('/');
  await expect(page.getByRole('button',{name:'Tools & Diagnostics'})).toHaveCount(0);
  await expect(page.getByLabel('Deeper local log analysis',{exact:true})).toHaveCount(0);
  const help=page.getByRole('button',{name:'Help: Add Logs'});
  await help.click();
  await expect(page.getByRole('tooltip')).toContainText('changing values from fixed text');
  await expect(page.getByRole('button',{name:'Analyze Logs',exact:true})).toBeDisabled();
  await page.getByLabel('Auto Parser raw logs').fill('{"action":"deny","src_ip":"192.0.2.10"}');
  await expect(page.getByRole('button',{name:'Analyze Logs',exact:true})).toBeEnabled();
  await page.getByRole('button',{name:'Analyze Logs',exact:true}).click();
  await expect(page.getByLabel('Beginner analysis summary')).toBeVisible({timeout:20000});
  await expect(page.getByLabel('Deeper local log analysis',{exact:true})).toHaveCount(0);
});