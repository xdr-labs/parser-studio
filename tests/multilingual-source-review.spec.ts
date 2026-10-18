import {test,expect} from '@playwright/test';
import {readFileSync} from 'node:fs';
type SourceFixture={raw:string;event_type:string;message:string;user:string;location:string};
const fixtures=JSON.parse(readFileSync(
  new URL('../fixtures/multilingual-security-logs.json',import.meta.url),'utf8'
)) as SourceFixture[];

test('multilingual event values survive Auto Parser review and source-type comparison',async({page})=>{
  const original=fixtures.map(item=>item.raw).join('\n');
  await page.goto('/');
  await page.getByRole('button',{name:'Advanced Tools & Diagnostics'}).click();
  const input=page.getByLabel('Auto Parser raw logs');
  await input.fill(original);
  await expect(input).toHaveValue(original);
  await expect(page.getByLabel('Automatic event accounting'))
    .toContainText('3/3 events analyzed locally');

  const review=page.getByRole('button',{name:'Review Detected Results'});
  await expect(review).toBeEnabled();
  await review.click();
  await expect(page.getByLabel('Review Fields stage')).toBeVisible();

  const compare=page.locator('details[aria-label="Compare fields across log types"]');
  await expect(compare).toBeVisible();
  await compare.locator('summary').click();
  await expect(compare.getByLabel('Structural source coverage')).toContainText('Sample events 3');
  await expect(compare.getByLabel('Structural source coverage')).toContainText('Groups 3');
  await expect(compare.getByLabel('Log type comparison 1')).toContainText('Event type: threat');
  await expect(compare.getByLabel('Log type comparison 2')).toContainText('Event type: user');
  await expect(compare.getByLabel('Log type comparison 3')).toContainText('Event type: asset');
  await expect(compare).toContainText('Source review only:');

  const inspector=page.getByLabel('Browser-only event inspector');
  await expect(inspector).toContainText(fixtures[0]!.message);
  await page.getByLabel('Auto Parser review event').selectOption({index:1});
  await expect(inspector).toContainText(fixtures[1]!.message);
  await page.getByLabel('Auto Parser review event').selectOption({index:2});
  await expect(inspector).toContainText(fixtures[2]!.message);
  // Only the author changes the log input. The comparison does not
  // translate, filter or mutate any original source event.
  await page.getByRole('button',{name:'Back to Logs'}).click();
  await expect(input).toHaveValue(original);
});
