import {test,expect} from '@playwright/test';

const a='{"action":"allow","src_ip":"192.0.2.10","dst_port":443}';
const b='{"action":"deny","src_ip":"198.51.100.20","dst_port":8443}';

test('browser-local versions retain original logs, compare snapshots and restore earlier experiments',async({page})=>{
  const apiWrites:string[]=[];
  page.on('request',request=>{
    if(request.method()!=='GET'&&request.url().includes('/api/'))
      apiWrites.push(new URL(request.url()).pathname);
  });
  await page.goto('/');
  await page.getByLabel('Auto Parser raw logs').fill(a);
  await page.getByRole('button',{name:'Local Versions',exact:true}).click();
  const history=page.getByLabel('Local Versions workspace');
  await expect(history).toBeVisible();
  await history.getByLabel('Local version name').fill('Baseline V1');
  await history.getByRole('button',{name:'Save Version'}).click();
  await expect(history).toContainText('Baseline V1');
  await expect(history).toContainText('1/30 saved');
  await expect(history.getByRole('status')).toContainText('Saved in this browser only');
  expect(apiWrites).toEqual([]);

  await page.getByLabel('Auto Parser raw logs').fill(b);
  await history.getByLabel('Local version name').fill('Experiment V2');
  await history.getByRole('button',{name:'Save Version'}).click();
  await expect(history).toContainText('2/30 saved');
  await history.getByLabel('Compare version A').selectOption({label:'Baseline V1'});
  await history.getByLabel('Compare version B').selectOption({label:'Experiment V2'});
  await expect(history.getByLabel('Local version differences')).toContainText('Log sample changed');
  await expect(history.getByLabel('Local version differences')).toContainText('1 differing line positions');
  await history.getByLabel('Compare version B').selectOption({label:'Current working copy (unsaved)'});
  await expect(history.getByLabel('Local version differences')).toContainText('Log sample changed');

  page.on('dialog',dialog=>dialog.accept());
  await history.getByRole('button',{name:'Restore'}).filter({hasText:'Restore'}).first().click();
  // Version rows appear newest first; first is Experiment V2, which matches current. Restore Baseline by row.
  await history.getByText('Baseline V1',{exact:true}).locator('..').locator('..')
    .getByRole('button',{name:'Restore'}).click();
  await expect(page.getByLabel('Auto Parser raw logs')).toHaveValue(a);
  await expect(history).toContainText('Before restore');

  // Refresh loses the unsaved working copy, but never the explicitly saved versions.
  await page.reload();
  await page.getByRole('button',{name:'Local Versions',exact:true}).click();
  const reloaded=page.getByLabel('Local Versions workspace');
  await expect(reloaded).toContainText('Baseline V1');
  await expect(reloaded).toContainText('Experiment V2');
  await reloaded.getByText('Experiment V2',{exact:true}).locator('..').locator('..')
    .getByRole('button',{name:'Restore'}).click();
  await expect(page.getByLabel('Auto Parser raw logs')).toHaveValue(b);
  expect(apiWrites).toEqual([]);
  await expect(page.getByRole('complementary',{name:'Parser Studio navigation'})
    .locator('button.rail-link')).toHaveCount(2);
});

test('a browser-only version never synchronizes to a second browser profile',async({browser})=>{
  const one=await browser.newContext();
  const two=await browser.newContext();
  try{
    const first=await one.newPage();
    await first.goto('/');
    await first.getByLabel('Auto Parser raw logs').fill(a);
    await first.getByRole('button',{name:'Local Versions',exact:true}).click();
    await first.getByLabel('Local version name').fill('Local profile only');
    await first.getByRole('button',{name:'Save Version'}).click();
    await expect(first.getByLabel('Saved local versions')).toContainText('Local profile only');
    const second=await two.newPage();
    await second.goto('/');
    await second.getByRole('button',{name:'Local Versions',exact:true}).click();
    await expect(second.getByLabel('Saved local versions')).toContainText('No versions saved yet');
    await expect(second.getByLabel('Saved local versions')).not.toContainText('Local profile only');
  }finally{await one.close();await two.close();}
});

test('saved version can be deleted without changing current logs',async({page})=>{
  await page.goto('/');
  await page.getByLabel('Auto Parser raw logs').fill(a);
  await page.getByRole('button',{name:'Local Versions',exact:true}).click();
  const history=page.getByLabel('Local Versions workspace');
  await history.getByLabel('Local version name').fill('Disposable');
  await history.getByRole('button',{name:'Save Version'}).click();
  await expect(history.getByLabel('Saved local versions')).toContainText('Disposable');
  page.on('dialog',dialog=>dialog.accept());
  await history.getByRole('button',{name:'Delete local version Disposable'}).click();
  await expect(history).toContainText('No versions saved yet');
  await expect(page.getByLabel('Auto Parser raw logs')).toHaveValue(a);
});

test('multiple field-mapping experiments remain independently restorable from local history',async({page})=>{
  await page.goto('/');
  const source='{"src_ip":"192.0.2.10","action":"allow","dst_port":443}';
  await page.getByLabel('Auto Parser raw logs').fill(source);
  await page.getByRole('button',{name:'Analyze Logs'}).click();
  await expect(page.getByLabel('Beginner analysis summary')).toContainText('1 of 1 log event parsed completely');
  await page.getByRole('button',{name:'Review Fields',exact:true}).click();
  await page.getByRole('button',{name:'Map Fields',exact:true}).click();
  const field=page.getByLabel('Map Fields stage').getByLabel('Stellar field 0');
  await expect(field).toBeVisible();
  const original=await field.inputValue();
  await page.getByRole('button',{name:'Local Versions',exact:true}).click();
  const history=page.getByLabel('Local Versions workspace');
  await history.getByLabel('Local version name').fill('Mapped V1');
  await history.getByRole('button',{name:'Save Version'}).click();
  await expect(history).toContainText('Mapped V1');
  await field.fill('custom.experimented_target');
  await history.getByLabel('Local version name').fill('Mapped V2');
  await history.getByRole('button',{name:'Save Version'}).click();
  await history.getByLabel('Compare version A').selectOption({label:'Mapped V1'});
  await history.getByLabel('Compare version B').selectOption({label:'Mapped V2'});
  await expect(history.getByLabel('Local version differences')).toContainText('Field mappings');
  await expect(history.getByLabel('Local version differences')).toContainText('Mappings added: 0 · removed: 0 · edited: 1');
  page.on('dialog',dialog=>dialog.accept());
  await history.getByText('Mapped V1',{exact:true}).locator('..').locator('..')
    .getByRole('button',{name:'Restore'}).click();
  await expect(page.getByLabel('Auto Parser raw logs')).toHaveValue(source);
  await page.getByRole('button',{name:'Analyze Logs'}).click();
  await page.getByRole('button',{name:'Review Fields',exact:true}).click();
  await page.getByRole('button',{name:'Map Fields',exact:true}).click();
  await expect(page.getByLabel('Map Fields stage').getByLabel('Stellar field 0')).toHaveValue(original);
  await history.getByText('Mapped V2',{exact:true}).locator('..').locator('..')
    .getByRole('button',{name:'Restore'}).click();
  await page.getByRole('button',{name:'Analyze Logs'}).click();
  await page.getByRole('button',{name:'Review Fields',exact:true}).click();
  await page.getByRole('button',{name:'Map Fields',exact:true}).click();
  await expect(page.getByLabel('Map Fields stage').getByLabel('Stellar field 0'))
    .toHaveValue('custom.experimented_target');
});
