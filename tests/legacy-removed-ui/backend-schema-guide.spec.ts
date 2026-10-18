import { expect, test } from '@playwright/test';

const pattern = String.raw`^[A-Za-z_][A-Za-z0-9_-]*(\.[A-Za-z_][A-Za-z0-9_-]*)*$`;
const schema = {
  $schema: 'http://json-schema.org/draft-07/schema#',
  $id: 'urn:xdr-labs:parser-project:v0.1',
  properties: {
    schemaRevision: { const: '0.1' },
    sourceCategory: { enum: ['network', 'endpoint', 'cloud', 'application', 'other'] },
    extraction: { properties: { format: { enum: ['json','kv','csv','syslog_rfc5424','cef','leef'] } } },
    receiver: { properties: {
      protocols: { items: { enum: ['udp','tcp'] } },
      port: { type:'integer', minimum:1, maximum:65535 },
      messageLengthLimit: { type:'integer', minimum:256, maximum:65536 },
    } },
  },
  $defs: {
    mapping: { propertyNames: { pattern, maxLength:128 } },
    fieldRule: { properties: {
      normalized_name: { pattern, maxLength:128 },
      data_type: { enum:['string','integer','ip','port','boolean','date'] },
    } },
  },
};

test('explicit local backend schema guide shows supported types, not an official field dictionary', async ({ page }) => {
  let count = 0;
  await page.route('**/api/v1/parser-pairs/schema', async (route) => {
    count++;
    expect(route.request().method()).toBe('GET');
    expect(route.request().postData()).toBeNull();
    await route.fulfill({ status:200, contentType:'application/json', body:JSON.stringify(schema) });
  });
  await page.goto('/?workspace=guided');
  await page.getByLabel('Guided raw sample logs').fill('{"src_ip":"198.51.100.200","action":"allow"}');
  await page.getByRole('button', { name: /3\. Map Fields/ }).click();
  await page.locator('.guided-schema-guide summary').click();
  expect(count).toBe(0);
  const guide = page.getByLabel('Backend authoring schema guide');
  await expect(guide).toContainText('not an official field dictionary');
  await guide.getByRole('button', { name: 'Fetch Backend Schema (GET)' }).click();
  const result = page.getByLabel('Verified backend schema summary');
  await expect(result).toContainText('ParserProject 0.1');
  await expect(result).toContainText('json · kv · csv');
  await expect(result).toContainText('string · integer · ip · port · boolean · date');
  await expect(result).toContainText('1–65535');
  await expect(result).not.toContainText('198.51.100.200');
  expect(count).toBe(1);
});

test('unsupported future backend schema never appears as verified guidance', async ({ page }) => {
  await page.route('**/api/v1/parser-pairs/schema', async (route) =>
    route.fulfill({ status:200, contentType:'application/json',
      body: JSON.stringify({ ...schema, $id: 'urn:unknown:parser-studio:v2' }) }));
  await page.goto('/?workspace=guided');
  await page.getByRole('button', { name: /3\. Map Fields/ }).click();
  await page.locator('.guided-schema-guide summary').click();
  await page.getByRole('button', { name: 'Fetch Backend Schema (GET)' }).click();
  await expect(page.locator('.guided-schema-guide [role="alert"]')).toContainText('Unsupported');
  await expect(page.getByLabel('Verified backend schema summary')).toHaveCount(0);
});
