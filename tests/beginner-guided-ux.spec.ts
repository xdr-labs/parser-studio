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

test('troubleshooting mode explains when each optional tool should be used without leading with internal engine names',async({page})=>{
  await page.goto('/');
  await page.getByRole('button',{name:'Advanced Tools & Diagnostics'}).click();

  await expect(page.getByLabel('Troubleshooting tools guidance')).toBeVisible();
  await expect(page.getByText('Deeper local log analysis',{exact:true})).toBeVisible();
  await expect(page.getByLabel('Existing parser review and import').locator('summary')).toContainText('Open or inspect an existing parser');
  await expect(page.getByLabel('Multi-line event boundary tool').locator('summary')).toContainText('Check where multi-line events begin and end');
  await expect(page.getByLabel('Private text grouping tool').locator('summary')).toContainText('Group similar text logs');
  await expect(page.getByLabel('Known log shape matcher').locator('summary')).toContainText('Find a similar known log shape');

  await expect(page.getByText('Run Local Multi-Pass Source Preview')).toHaveCount(0);
  await expect(page.getByText('Explicit local request only')).toHaveCount(0);
  await expect(page.getByText('Optional · Real Drain3 pattern mining')).toHaveCount(0);
  await expect(page.getByText('Advanced · Review Existing Parser or Project')).toHaveCount(0);

  const groupingHelp=page.getByRole('button',{name:'Help: Group similar text logs'});
  await groupingHelp.click();
  await expect(groupingHelp.getByRole('tooltip')).toContainText('free-form text logs');
});
