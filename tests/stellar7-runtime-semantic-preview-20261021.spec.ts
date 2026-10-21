import {test,expect} from '@playwright/test';

// A deliberately invalid 7.0 SHA-256 is a valid JSON string, but is NOT a
// valid official hash. This must not become a successful mapped parser event.
test('manual Stellar 7.0 official hash selection never turns invalid source values into successful normalized events',async({page})=>{
  test.skip(process.env.PARSER_STUDIO_SCOPED_AUTHORING_E2E!=='1',
    'Requires isolated real authoring Backend and Python Multi-Pass.');
  test.setTimeout(45_000);
  const source=[{sha256:'a'.repeat(32)},{sha256:'b'.repeat(32)}]
    .map(item=>JSON.stringify(item)).join('\n');
  const errors:string[]=[];
  page.on('pageerror',error=>errors.push(error.message));
  await page.goto('/');
  await page.getByRole('button',{name:'Advanced Tools & Diagnostics'}).click();
  const input=page.getByLabel('Auto Parser raw logs');
  await input.fill(source);
  await expect(page.getByLabel('Automatic event accounting'))
    .toContainText('2/2 events analyzed locally');
  await page.getByRole('button',{name:'Review Detected Results'}).click();
  await page.getByLabel('Review Fields stage').getByRole('button',{name:'Map Fields'}).click();
  const stage=page.getByLabel('Map Fields stage');
  await expect(stage).toBeVisible();
  const rows=stage.locator('article.normalization-map-row');
  const index=await rows.evaluateAll(items=>items.findIndex(item=>
    (item.querySelector('input[aria-label^="Source field"]') as HTMLInputElement)?.value==='sha256'));
  expect(index).toBeGreaterThanOrEqual(0);
  const row=rows.nth(index);
  await row.getByRole('button',{name:'Choose Stellar field'}).click();
  const picker=page.getByLabel('Stellar field chooser');
  await picker.getByRole('textbox',{name:'Search Stellar field list'}).fill('sha256');
  await picker.locator('div.normalization-catalog-results > div')
    .filter({has:page.locator('strong',{hasText:/^sha256$/})})
    .getByRole('button',{name:'Use',exact:true}).click();
  await expect(row).toContainText('Matched to Stellar');
  await expect(stage.getByLabel('Field mapping checks')).toContainText('A sample value does not fit the selected value type');
  await expect(stage.getByLabel('Field changes only')).toContainText('Not emitted');
  await expect(stage.getByLabel('Normalization review event')).toContainText('Needs attention');
  await expect(stage.getByRole('button',{name:'Create Parser',exact:true})).toBeDisabled();
  await stage.getByRole('button',{name:'Back to Review Fields'}).click();
  await page.getByLabel('Review Fields stage').getByRole('button',{name:'Back to Logs'}).click();
  await expect(input).toHaveValue(source);
  expect(errors).toEqual([]);
});
