import {test,expect} from '@playwright/test';

test('first-time user sees one guided path, contextual help, and no empty technical counters',async({page})=>{
  await page.goto('/');

  await expect(page.getByText('AUTO PARSER · GUIDED MODE')).toBeVisible();
  await expect(page.getByRole('heading',{name:/Paste security logs/})).toBeVisible();
  await expect(page.getByLabel('Automatic event accounting')).toHaveCount(0);
  await expect(page.getByText('Run Local Multi-Pass Source Preview')).toHaveCount(0);
  await expect(page.getByText('Real Drain3 pattern mining')).toHaveCount(0);

  const addHelp=page.getByRole('button',{name:'Help: Add Logs'});
  await addHelp.click();
  await expect(addHelp.getByRole('tooltip')).toContainText('Two or more examples');

  const mapStep=page.getByRole('button',{name:/Map Fields/});
  await expect(mapStep).toHaveClass(/locked/);
  await mapStep.click();
  await expect(page.getByLabel('Add Logs stage')).toBeVisible();
  await expect(page.getByRole('status')).toContainText('Start with Add Logs');
});

test('single Analyze path shows contextual tools without the removed advanced-mode switch',async({page})=>{
  await page.goto('/');
  await expect(page.getByRole('button',{name:'Advanced Tools & Diagnostics'})).toHaveCount(0);
  await expect(page.getByLabel('Troubleshooting tools guidance')).toHaveCount(0);
  await expect(page.getByLabel('Deeper local log analysis',{exact:true})).toHaveCount(0);
  await expect(page.getByLabel('Existing parser review and import').locator('summary'))
    .toContainText('Open or inspect an existing parser');
  await expect(page.getByLabel('Private text grouping tool')).toHaveCount(0);
  await expect(page.getByLabel('Known log shape matcher')).toHaveCount(0);
  await expect(page.getByLabel('Python test sender',{exact:true})).toBeVisible();
  await expect(page.getByLabel('Manually mark a log prefix or postfix')).toBeVisible();
  await expect(page.getByLabel('Multi-line event boundary tool')).toHaveCount(0);
  await expect(page.getByText('Run Local Multi-Pass Source Preview')).toHaveCount(0);
  await expect(page.getByRole('button',{name:'Help: Group similar text logs'})).toHaveCount(0);
});
