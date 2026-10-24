import {test,expect} from '@playwright/test';

test('Auto Parser offers only source-driven creation, not legacy parser import or inspection',async({page})=>{
 await page.goto('/');
 await expect(page.getByRole('main',{name:'Auto Parser v2'})).toBeVisible();
 for(const removed of [
  'Existing parser review and import',
  'Offline Project JSON review',
  'Existing parser file inspection',
  'Existing parser pair review',
 ]){
  await expect(page.getByLabel(removed,{exact:true})).toHaveCount(0);
 }
 await expect(page.getByText('Open or inspect an existing parser',{exact:true})).toHaveCount(0);
 await expect(page.getByRole('button',{name:'Analyze Logs',exact:true})).toBeDisabled();
 await page.getByLabel('Auto Parser raw logs').fill('action=deny src=192.0.2.10');
 await page.getByRole('button',{name:'Analyze Logs',exact:true}).click();
 await expect(page.getByLabel('Beginner analysis summary')).toBeVisible({timeout:20000});
 await expect(page.getByLabel('Existing parser review and import')).toHaveCount(0);
});
