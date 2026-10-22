import {test,expect} from '@playwright/test';

// Official Stellar 7.0 field suggestions are reviewed at Map Fields in the
// current two-path UI, rather than inside the retired advanced diagnostics.
test('source fields remain intact while the current mapping review uses Stellar 7.0 only',async({page})=>{
  const raw='src_ip=192.0.2.10 dst_port=443 action=deny custom=PRIVATE_VALUE';
  await page.goto('/');
  await page.getByLabel('Auto Parser raw logs').fill(raw);
  await page.getByRole('button',{name:'Analyze Logs',exact:true}).click();
  const review=page.getByRole('button',{name:'Review Fields',exact:true});
  await expect(review).toBeEnabled({timeout:20000});
  await review.click();
  const inspector=page.getByLabel('Browser-only event inspector');
  await expect(inspector).toContainText('192.0.2.10');
  await expect(inspector).toContainText('PRIVATE_VALUE');
  await page.getByLabel('Review Fields stage').getByRole('button',{name:'Map Fields'}).click();
  const mapping=page.getByLabel('Map Fields stage');
  await expect(mapping).toBeVisible();
  await expect(mapping).toContainText('Stellar field dictionary 7.0.xs');
  await expect(mapping.getByLabel('Recommended field matches')).not.toContainText('PRIVATE_VALUE');
  await mapping.getByRole('button',{name:'Back to Review Fields'}).click();
  await page.getByLabel('Review Fields stage').getByRole('button',{name:'Back to Logs'}).click();
  await expect(page.getByLabel('Auto Parser raw logs')).toHaveValue(raw);
  await expect(page.getByLabel('Deeper local log analysis',{exact:true})).toHaveCount(0);
});
