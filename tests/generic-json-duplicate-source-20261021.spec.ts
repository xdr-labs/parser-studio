import {test,expect} from '@playwright/test';

// Authored protocol fixtures. These are not manufacturer originals and
// cannot establish target loader or sensor integration compatibility.
const rejected=[
  'vendor_test {"src_ip":"192.0.2.11","src_ip":"198.51.100.9"}',
  'vendor_test {"user":{"name":"one","name":"two"}}',
  '<134>1 2026-10-21T00:01:02Z gateway {"action":"one","action":"two"}',
];

test('duplicate JSON fields inside a recognized generic wrapper never become a generated success',async({page})=>{
  test.skip(process.env.PARSER_STUDIO_SCOPED_AUTHORING_E2E!=='1',
    'Needs the exact-head local Multi-Pass and offline compiler source.');
  test.setTimeout(90_000);
  const errors:string[]=[];
  page.on('pageerror',error=>errors.push(error.message));
  for(const raw of rejected){
    await page.goto('/');
    const source=page.getByLabel('Auto Parser raw logs');
    await source.fill(raw);
    await expect(source).toHaveValue(raw);
    await page.getByRole('button',{name:'Analyze Logs',exact:true}).click();
    await expect(source).toHaveValue(raw);
    const recovered=page.getByLabel('Parse problem inspector')
      .getByRole('button',{name:'Use extracted fields'});
    // The supported repair click must not bypass the strict JSON source guard.
    if(await recovered.count())await recovered.click();
    await expect(page.getByRole('button',{name:'Review Fields',exact:true})).toBeDisabled();
    await expect(page.getByRole('button',{name:'Create Parser Files'})).toHaveCount(0);
  }
  expect(errors).toEqual([]);
});

test('separate JSON objects with the same member names remain reviewable without changing source',async({page})=>{
  test.skip(process.env.PARSER_STUDIO_SCOPED_AUTHORING_E2E!=='1',
    'Needs the exact-head local Multi-Pass and offline compiler source.');
  test.setTimeout(60_000);
  const raw='vendor_test {"left":{"k":"one"},"right":{"k":"two"}}';
  await page.goto('/');
  const source=page.getByLabel('Auto Parser raw logs');
  await source.fill(raw);
  await expect(source).toHaveValue(raw);
  await page.getByRole('button',{name:'Analyze Logs',exact:true}).click();
  await expect(source).toHaveValue(raw);
  // An unknown vendor text prefix needs the existing explicit "Use extracted
  // fields" review action; it must not be mislabeled as auto-parsed.
  await expect(page.getByLabel('Beginner analysis summary')).toContainText(
    '0 of 1 log event parsed completely');
  const recovery=page.getByLabel('Parse problem inspector')
    .getByRole('button',{name:'Use extracted fields'});
  await expect(recovery).toBeVisible();
  await recovery.click();
  await expect(page.getByLabel('Beginner analysis summary')).toContainText(
    '1 of 1 log event parsed completely');
  await expect(page.getByRole('button',{name:'Review Fields',exact:true})).toBeEnabled();
  await expect(source).toHaveValue(raw);
});
