import {expect,type Page} from '@playwright/test';

// The sender belongs to the generated parser, not the initial log editor.
// Keep all offline Python sender tests on the same real authoring journey.
export async function generatePythonSenderForSample(page:Page,source:string,csvColumns?:string):Promise<void>{
  await page.goto('/');
  await expect(page.getByLabel('Python test sender',{exact:true})).toHaveCount(0);
  await page.getByLabel('Auto Parser raw logs').fill(source);
  await page.getByRole('button',{name:'Analyze Logs',exact:true}).click();
  if(csvColumns){
    const csv=page.getByLabel('Review CSV column names');
    await expect(csv).toBeVisible({timeout:20000});
    await csv.getByLabel('Reviewed CSV column names').fill(csvColumns);
    const confirm=csv.getByRole('button',{name:'I Confirm These CSV Column Names'});
    await expect(confirm).toBeEnabled();
    await confirm.click();
  }
  const review=page.getByRole('button',{name:'Review Fields',exact:true});
  await expect(review).toBeEnabled({timeout:30000});
  await review.click();
  await page.getByLabel('Review Fields stage').getByRole('button',{name:'Map Fields'}).click();
  const map=page.getByLabel('Map Fields stage');
  const create=map.getByRole('button',{name:'Create Parser',exact:true});
  await expect(create).toBeEnabled({timeout:20000});
  await create.click();
  await page.getByRole('button',{name:'Create Parser Files'}).click();
  await expect(page.getByLabel('Generated parser files'))
    .toContainText('Parser files created successfully',{timeout:20000});
  await expect(page.getByRole('group',{name:'Python test sender'})).toBeVisible();
}
