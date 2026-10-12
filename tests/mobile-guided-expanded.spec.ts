import { expect, test } from '@playwright/test';

/** Combined mobile check covers only frontend surfaces; no native parser or target calls. */
test('390px mobile Guided path retains access to expanded parser controls without horizontal overflow',async({page})=>{
  await page.setViewportSize({width:390,height:844});
  await page.goto('/?workspace=guided');
  const width=async(stage:string)=>{
    const metrics=await page.evaluate(()=>({
      page:document.documentElement.scrollWidth,viewport:window.innerWidth,
    }));
    expect(metrics.page,stage).toBeLessThanOrEqual(metrics.viewport+1);
  };
  await expect(page.getByLabel('Synthetic starter template')).toBeVisible();
  await page.getByLabel('Synthetic starter template').selectOption('rfc5424_leef');
  await page.getByRole('button',{name:'Apply Synthetic Template'}).click();
  await width('sample upload & template');

  await page.getByRole('button',{name:/2\. Extract Fields/}).click();
  await expect(page.getByLabel('RFC5424 message body format')).toBeVisible();
  await expect(page.getByLabel('RFC5424 message body format')).toHaveValue('leef');
  await width('format selection and event list');

  await page.getByRole('button',{name:/3\. Map Fields/}).click();
  await expect(page.getByLabel('Source field 0')).toBeVisible();
  await page.locator('.guided-schema-guide summary').click();
  await expect(page.getByRole('button',{name:'Fetch Backend Schema (GET)'})).toBeVisible();
  await width('mapping cards, metadata, schema guide');

  await page.getByRole('button',{name:/4\. Receive & Classify/}).click();
  await expect(page.getByLabel('Sample classification preview')).toBeVisible();
  await width('transport, classification and preview');

  await page.getByRole('button',{name:/5\. Test & Fix/}).click();
  await expect(page.getByRole('button',{name:'Run Full Browser Test'})).toBeVisible();
  await width('test lab');

  await page.getByRole('button',{name:/6\. Generate Files/}).click();
  await page.locator('.guided-pair-inspect summary').click();
  await expect(page.getByLabel('Inspect pair CONF')).toBeVisible();
  await expect(page.getByLabel('Inspect pair Ruby fragment')).toBeVisible();
  await width('draft export and read-only pair inspection');
  await expect(page.locator('.guided-inspector')).toContainText('Stellar Ingestion');
});
