import { expect, test } from '@playwright/test';

test('no-code classification honors exact dotted KV source fields and explains matched rule', async ({page}) => {
  await page.goto('/');
  await page.getByLabel('Guided raw sample logs').fill(
    'event.action=deny src_ip=198.51.100.10\n' +
    'event.action=allow src_ip=203.0.113.12',
  );
  await page.getByRole('button',{name:/2\. Extract Fields/}).click();
  await page.getByRole('button',{name:'Key / Value',exact:true}).click();
  await page.getByRole('button',{name:/4\. Receive & Classify/}).click();
  await page.getByLabel('Rule field 0').fill('event.action');
  await page.getByLabel('Rule value 0').fill('deny');
  const routes=page.getByLabel('Sample classification preview');
  await expect(routes.locator('.guided-routing-row')).toHaveCount(2);
  await expect(routes.locator('.guided-routing-row').first()).toContainText('Threat');
  await expect(routes.locator('.guided-routing-row').first()).toContainText('Condition 1');
  await expect(routes.locator('.guided-routing-row').first()).toContainText('Condition Matched');
  await expect(routes.locator('.guided-routing-row').nth(1)).toContainText('Default');
  await expect(page.getByText(/Actual stellar_log_index routing requires independent Fluentd engine validation/)).toBeVisible();
});
