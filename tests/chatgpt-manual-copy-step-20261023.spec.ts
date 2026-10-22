import {test,expect} from '@playwright/test';

test('ChatGPT Assisted displays all three steps even before the user creates a prompt',async({page,context})=>{
  await context.grantPermissions(['clipboard-read','clipboard-write']);
  await page.goto('/?workspace=chatgpt');
  await expect(page.getByRole('heading',{name:'1. Prepare your logs'})).toBeVisible();
  const copyStep=page.getByLabel('ChatGPT copy step');
  await expect(copyStep).toBeVisible();
  await expect(copyStep.getByRole('heading',{name:'2. Copy to ChatGPT'})).toBeVisible();
  await expect(copyStep).toContainText('Nothing is sent automatically');
  await expect(page.getByRole('heading',{name:'3. Paste the ChatGPT result'})).toBeVisible();
  await expect(page.getByLabel('ChatGPT prepared prompt')).toHaveCount(0);

  const source='date=2026-10-23 time=08:20:00 srcip=192.0.2.20 dstip=198.51.100.21 action=deny user=demo-analyst';
  await page.getByLabel('ChatGPT local sample logs').fill(source);
  await expect(page.getByRole('alert').filter({hasText:'The ChatGPT prompt includes your original log text'})).toBeVisible();
  await page.getByRole('button',{name:'Prepare ChatGPT Prompt'}).click();
  await expect(copyStep).toHaveCount(0);
  const prepared=page.getByLabel('ChatGPT prepared prompt');
  await expect(prepared.getByRole('heading',{name:'2. Copy to ChatGPT'})).toBeVisible();
  const prompt=page.getByLabel('ChatGPT copyable prompt');
  await expect(prompt).toHaveValue(/date=2026-10-23 time=08:20:00/);
  await prepared.getByRole('button',{name:'Copy Prompt'}).click();
  expect(await page.evaluate(()=>navigator.clipboard.readText())).toBe(await prompt.inputValue());
  await expect(page.getByRole('heading',{name:'3. Paste the ChatGPT result'})).toBeVisible();
});
