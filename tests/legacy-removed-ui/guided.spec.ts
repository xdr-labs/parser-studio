import { expect, test } from '@playwright/test';
import { readFile } from 'node:fs/promises';

test('the legacy six-step no-code builder remains accessible in Edit Details', async ({ page }) => {
  await page.goto('/?workspace=guided');
  await expect(page.getByRole('main', { name: 'No-code Parser Guided Builder' })).toBeVisible();
  await expect(page.getByRole('heading', { name: /Build a custom parser/ })).toBeVisible();
  await expect(page.locator('.guided-step')).toHaveCount(6);
  await expect(page.getByRole('heading', { name: 'Which logs are you parsing?' })).toBeVisible();
  await expect(page.locator('.guided-inspector')).toContainText('Stellar Ingestion');
  await expect(page.locator('.guided-inspector')).toContainText('Unverified');
  await expect(page.locator('footer')).toContainText('Fluentd & Stellar: NOT VERIFIED');
  await page.screenshot({ path: test.info().outputPath('guided-start-desktop.png'), fullPage: true });
});

test('nondeveloper can select a token, test a field proposal and keep JSON family intact', async ({ page }) => {
  await page.goto('/?workspace=guided');
  await page.getByRole('button', { name: 'Next Step' }).click();
  await expect(page.getByRole('heading', { name: 'Which fields do you need to extract?' })).toBeVisible();
  await page.getByRole('button', { name: 'JSON', exact: true }).click();
  const raw = page.getByLabel('Guided selectable raw event');
  await raw.evaluate((element) => {
    const node = element.firstChild!;
    const value = 'DEMO-FW';
    const text = node.textContent!;
    const start = text.indexOf(value);
    if (start < 0) throw new Error('Synthetic fixture unavailable');
    const range = document.createRange();
    range.setStart(node, start);
    range.setEnd(node, start + value.length);
    window.getSelection()?.removeAllRanges();
    window.getSelection()?.addRange(range);
    element.dispatchEvent(new MouseEvent('mouseup', { bubbles: true }));
  });
  await expect(page.getByLabel('Guided proposed field name')).toHaveValue('device');
  await expect(page.getByRole('button', { name: 'Apply Field Rule' })).toBeDisabled();
  await page.getByRole('button', { name: 'Test Across All Samples' }).click();
  await expect(page.getByRole('status')).toContainText('2 / 3 matching events');
  await page.getByRole('button', { name: 'Apply Field Rule' }).click();
  await expect(page.getByRole('button', { name: 'JSON', exact: true })).toHaveAttribute('aria-pressed', 'true');
  await page.getByRole('button', { name: 'Next Step' }).click();
  await expect(page.locator('.guided-map-card')).toHaveCount(4);
  await expect(page.getByRole('combobox', { name: 'Source field 3' })).toHaveValue('device');
  await page.getByRole('button', { name: 'Save Draft' }).click();
  const revisions = await page.evaluate(() => JSON.stringify(localStorage));
  expect(revisions).not.toContain('DEMO-FW');
  expect(revisions).toContain('custom.device');
});

test('complete six UI stages, execute browser test, download typed contract but never unverified pair', async ({ page }) => {
  await page.goto('/?workspace=guided');
  await page.getByLabel('Guided parser name').fill('Synthetic Firewall');
  await page.getByLabel('Guided vendor').fill('Fictitious Network Lab');
  await page.getByLabel('Parser ID').fill('sample_fw');
  await page.getByRole('button', { name: 'Next Step' }).click();
  await page.getByRole('button', { name: 'JSON', exact: true }).click();
  await page.getByRole('button', { name: 'Next Step' }).click();
  await page.getByRole('combobox', { name: 'Mapping group 2' }).selectOption('ns_fields');
  await page.getByRole('button', { name: 'Next Step' }).click();
  await expect(page.getByRole('heading', { name: 'How are logs received and classified?' })).toBeVisible();
  await page.getByLabel('Receiving port').fill('7512');
  await expect(page.getByLabel('UDP receiver')).toBeChecked();
  await expect(page.getByLabel('TCP receiver')).toBeChecked();
  await expect(page.getByLabel('Rule class 0')).toHaveValue('Threat');
  await page.getByRole('button', { name: 'Next Step' }).click();
  await page.getByRole('button', { name: 'Run Full Browser Test' }).click();
  await expect(page.locator('.guided-test-metrics')).toContainText('Input Events');
  await expect(page.locator('.guided-test-metrics')).toContainText('3');
  await expect(page.getByText('Test engine: browser-preview')).toBeVisible();
  await page.getByRole('button', { name: 'Next Step' }).click();
  await expect(page.getByRole('heading', { name: 'Which parser files will be generated?' })).toBeVisible();
  await expect(page.getByText('customized_sample_fw.conf')).toBeVisible();
  await expect(page.getByText('customized_sample_fw', { exact: true })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Generate 2 Parser Files (Backend Required)' })).toBeDisabled();
  await expect(page.getByText('UI input checks passed.')).toBeVisible();
  const download = page.waitForEvent('download');
  await page.getByRole('button', { name: 'Download Project JSON for Backend' }).click();
  const file = await download;
  const project = JSON.parse(await readFile(await file.path(), 'utf-8'));
  expect(file.suggestedFilename()).toBe('parser-project-sample_fw.json');
  expect(project.schemaRevision).toBe('0.1');
  expect(project.slug).toBe('sample_fw');
  expect(project.receiver.port).toBe(7512);
  expect(project.receiver.protocols).toEqual(['udp', 'tcp']);
  expect(project.classification.rules[0].index).toBe('threat');
  expect(project.normalization.topFields.src_ip.data_type).toBe('ip');
  expect(project.extraction.format).toBe('json');
  expect(JSON.stringify(project)).not.toContain('DEMO-FW');
  expect(JSON.stringify(project)).not.toContain('198.51.100.10');
});

test('invalid port and output name block project contract handoff', async ({ page }) => {
  await page.goto('/?workspace=guided');
  await page.getByLabel('Parser ID').fill('../unsafe');
  await page.getByRole('button', { name: /4\. Receive & Classify/ }).click();
  await page.getByLabel('Receiving port').fill('22');
  await page.getByLabel('UDP receiver').uncheck();
  await page.getByLabel('TCP receiver').uncheck();
  await page.getByRole('button', { name: /6\. Generate Files/ }).click();
  await expect(page.locator('.guided-contract-errors').first()).toContainText('Parser ID');
  await expect(page.locator('.guided-contract-errors').first()).toContainText('Receiving port');
  await expect(page.getByRole('button', { name: 'Download Project JSON for Backend' })).toBeDisabled();
  await expect(page.getByRole('button', { name: 'Generate 2 Parser Files (Backend Required)' })).toBeDisabled();
});

test('guided draft and expert editor share rules, samples and local revision state', async ({ page }) => {
  await page.goto('/?workspace=guided');
  await page.getByLabel('Guided vendor').fill('Shared Draft Vendor');
  await page.getByRole('button', { name: 'Open Expert Workbench' }).click();
  await expect(page.getByRole('heading', { name: 'Parser pipeline' })).toBeVisible();
  await expect(page.locator('.input-row input')).toHaveValue('Shared Draft Vendor');
  await page.getByRole('button', { name: 'Edit Details' }).click();
  await expect(page.getByLabel('Guided vendor')).toHaveValue('Shared Draft Vendor');
  await page.getByRole('button', { name: /4\. Receive & Classify/ }).click();
  await page.getByLabel('Receiving port').fill('7588');
  await page.getByRole('button', { name: 'Save Draft' }).click();
  await page.getByRole('button', { name: 'Parser Library' }).click();
  await expect(page.locator('.revision-card')).toHaveCount(1);
  await page.locator('.revision-card').click();
  await expect(page.getByRole('heading', { name: 'Which logs are you parsing?' })).toBeVisible();
  await page.getByRole('button', { name: /4\. Receive & Classify/ }).click();
  await expect(page.getByLabel('Receiving port')).toHaveValue('7588');
  await expect(page.getByLabel('Guided raw sample logs')).toHaveCount(0);
  await expect(page.locator('footer')).toContainText('Dataset 0');
});

test('small-screen guided mode never hides validation or overflows browser width', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto('/?workspace=guided');
  await expect(page.getByRole('main', { name: 'No-code Parser Guided Builder' })).toBeVisible();
  await page.getByRole('button', { name: /4\. Receive & Classify/ }).click();
  await expect(page.getByLabel('Receiving port')).toBeVisible();
  await page.getByRole('button', { name: /6\. Generate Files/ }).click();
  await expect(page.getByRole('button', { name: 'Generate 2 Parser Files (Backend Required)' })).toBeDisabled();
  const width = await page.evaluate(() => ({ content: document.documentElement.scrollWidth, viewport: window.innerWidth }));
  expect(width.content).toBeLessThanOrEqual(width.viewport + 1);
  await page.screenshot({ path: test.info().outputPath('guided-mobile.png'), fullPage: true });
});

test('ordered no-code event classification previews the reason per sample without native claims', async ({ page }) => {
  await page.goto('/?workspace=guided');
  await page.getByRole('button', { name: /4\. Receive & Classify/ }).click();
  await expect(page.locator('.guided-routing-row')).toHaveCount(3);
  await expect(page.locator('.guided-routing-row').nth(0)).toContainText('Session');
  await expect(page.locator('.guided-routing-row').nth(0)).toContainText('action = allow');
  await expect(page.locator('.guided-routing-row').nth(1)).toContainText('Threat');
  await expect(page.locator('.guided-routing-row').nth(2)).toContainText('Threat');
  await page.getByLabel('Rule value 1').fill('not-allow');
  await page.getByLabel('Default classification').selectOption('Winlogevent');
  await expect(page.locator('.guided-routing-row').nth(0)).toContainText('Winlogevent');
  await expect(page.locator('.guided-routing-row').nth(0)).toContainText('Default');
  await expect(page.locator('.guided-routing-row').nth(1)).toContainText('Threat');
  await expect(page.getByText('Actual stellar_log_index routing requires independent Fluentd engine validation')).toBeVisible();
});


test('no-code classification shows per-event rule reason and fallback without claiming native routing', async ({ page }) => {
  await page.goto('/?workspace=guided');
  await page.getByRole('button', { name: /4\. Receive & Classify/ }).click();
  const routes = page.getByLabel('Sample classification preview');
  await expect(routes.locator('.guided-routing-row')).toHaveCount(3);
  await expect(routes.locator('.guided-routing-row').nth(0)).toContainText('Session');
  await expect(routes.locator('.guided-routing-row').nth(0)).toContainText('action = allow · Condition 2');
  await expect(routes.locator('.guided-routing-row').nth(1)).toContainText('Threat');
  await expect(routes.locator('.guided-routing-row').nth(1)).toContainText('action = deny · Condition 1');

  await page.getByLabel('Rule value 0').fill('block');
  await expect(routes.locator('.guided-routing-row').nth(1)).toContainText('Syslog');
  await expect(routes.locator('.guided-routing-row').nth(1)).toContainText('Applied default event category');
  await page.getByLabel('Default classification').selectOption('Winlogevent');
  await expect(routes.locator('.guided-routing-row').nth(1)).toContainText('Winlogevent');
  await expect(page.getByText('Actual stellar_log_index routing requires independent Fluentd engine validation.')).toBeVisible();
  await page.screenshot({ path: test.info().outputPath('guided-routing-preview.png'), fullPage: true });
});

test('malformed sample remains explicitly unclassified instead of being silently routed', async ({ page }) => {
  await page.goto('/?workspace=guided');
  await page.getByLabel('Guided raw sample logs').fill('a log message with no structured fields');
  await page.getByRole('button', { name: /4\. Receive & Classify/ }).click();
  const routes = page.getByLabel('Sample classification preview');
  await expect(routes.locator('.guided-routing-row')).toHaveCount(1);
  await expect(routes.locator('.guided-routing-row').first()).toContainText('Unclassified');
  await expect(routes.locator('.guided-routing-row').first()).toContainText('Extraction Failed');
  await expect(routes.locator('.guided-routing-row').first()).not.toContainText('Syslog');
});


test('visual field review highlights actual capture spans and keeps failed variants visible', async ({ page }) => {
  await page.goto('/?workspace=guided');
  await page.getByRole('button', { name: 'Next Step' }).click();
  await page.getByRole('button', { name: 'JSON', exact: true }).click();
  const raw = page.getByLabel('Guided selectable raw event');
  await raw.evaluate((element) => {
    const node = element.firstChild!;
    const token = 'DEMO-FW';
    const start = node.textContent?.indexOf(token) ?? -1;
    if (start < 0) throw new Error('Synthetic token not found');
    const range = document.createRange();
    range.setStart(node, start);
    range.setEnd(node, start + token.length);
    window.getSelection()?.removeAllRanges();
    window.getSelection()?.addRange(range);
    element.dispatchEvent(new MouseEvent('mouseup', { bubbles: true }));
  });
  await expect(raw.locator('mark.guided-selected-token')).toHaveText('DEMO-FW');
  await page.getByRole('button', { name: 'Test Across All Samples' }).click();
  await expect(page.getByRole('status')).toContainText('2 / 3 matching events');
  const review = page.getByLabel('Field match examples');
  await expect(review.locator('.guided-match-row')).toHaveCount(3);
  await expect(review.locator('.guided-match-status.matched')).toHaveCount(2);
  await expect(review.locator('.guided-match-status.unmatched')).toHaveCount(1);
  await expect(review.locator('mark.guided-match-highlight')).toHaveCount(2);
  await expect(review).toContainText('They do not prove native Fluentd support or official metadata mapping.');

  await page.getByRole('button', { name: 'Apply Field Rule' }).click();
  await page.getByRole('button', { name: 'Save Draft' }).click();
  const persisted = await page.evaluate(() => JSON.stringify(localStorage));
  expect(persisted).not.toContain('DEMO-FW');
  expect(persisted).not.toContain('198.51.100.10');
});

test('nondeveloper can group pretty JSON samples by blank lines without leaking native export readiness', async ({ page }) => {
  await page.goto('/?workspace=guided');
  const sample = [
    '{',
    '  "action":"allow",',
    '  "src_ip":"198.51.100.25",',
    '  "dst_port":443',
    '}',
    '',
    '{"action":"deny","src_ip":"203.0.113.4","dst_port":22}',
  ].join('\n');
  await page.getByLabel('Guided raw sample logs').fill(sample);
  await page.getByRole('button', { name: /Separate events using blank lines/ }).click();
  await expect(page.locator('.guided-boundary-count')).toContainText('Logical events 2');
  await expect(page.locator('.guided-boundary-count')).toContainText('Nonempty source lines 6');
  await expect(page.getByText(/Blank-line grouping is preview-only unless/)).toBeVisible();
  await page.getByRole('button', { name: 'Next Step' }).click();
  await page.getByRole('button', { name: 'JSON', exact: true }).click();
  await expect(page.locator('.guided-event-option')).toHaveCount(2);
  await expect(page.getByLabel('Guided selectable raw event')).toContainText('"src_ip":"198.51.100.25"');
  await page.getByRole('button', { name: /6\. Generate Files/ }).click();
  await expect(page.locator('.guided-contract-errors').first()).toContainText('Blank-line grouping is browser-only');
  await expect(page.getByRole('button', { name: 'Generate 2 Parser Files (Backend Required)' })).toBeDisabled();
  await expect(page.getByRole('button', { name: 'Download Project JSON for Backend' })).toBeDisabled();
});

test('only explicitly selected TCP LF LF JSON framing enables a reviewed DRAFT contract',async({page})=>{
  const pretty=[
    '{',
    '  "action":"allow",',
    '  "src_ip":"192.0.2.14",',
    '  "dst_port":443',
    '}',
    '',
    '{',
    '  "action":"deny",',
    '  "src_ip":"198.51.100.17",',
    '  "dst_port":22',
    '}',
    '',
  ].join('\n');
  await page.goto('/?workspace=guided');
  await page.getByLabel('Guided raw sample logs').fill(pretty);
  await page.getByRole('button',{name:/Separate events using blank lines/}).click();
  await page.getByRole('button',{name:/2\. Extract Fields/}).click();
  await page.getByRole('button',{name:'JSON',exact:true}).click();
  await page.getByRole('button',{name:/6\. Generate Files/}).click();
  await expect(page.locator('.guided-contract-errors').first())
    .toContainText('Blank-line grouping is browser-only');
  await expect(page.getByRole('button',{name:'Download Project JSON for Backend'}))
    .toBeDisabled();
  await page.getByRole('button',{name:/4\. Receive & Classify/}).click();
  const transport=page.getByLabel('TCP JSON event framing');
  await expect(transport).toHaveValue('newline');
  await transport.selectOption('blank_line_json');
  await expect(page.getByText(/Requires JSON, only TCP enabled/)).toBeVisible();
  await page.getByRole('button',{name:/6\. Generate Files/}).click();
  await expect(page.locator('.guided-contract-errors').first()).toContainText(
    'requires explicit JSON format, one TCP protocol only');
  await page.getByRole('button',{name:/4\. Receive & Classify/}).click();
  await page.getByLabel('UDP receiver').uncheck();
  await page.getByRole('button',{name:/6\. Generate Files/}).click();
  await expect(page.getByText('UI input checks passed.')).toBeVisible();
  await expect(page.getByRole('button',{name:'Download Project JSON for Backend'}))
    .toBeEnabled();
  const download=page.waitForEvent('download');
  await page.getByRole('button',{name:'Download Project JSON for Backend'}).click();
  const artifact=await download;
  const exported=JSON.parse(await readFile(await artifact.path(),'utf8'));
  expect(exported.receiver).toMatchObject({
    protocols:['tcp'],tcpFraming:'blank_line_json',
    port:7501,
  });
  expect(exported.receiver).not.toHaveProperty('delimiter');
  expect(exported.extraction).toEqual({format:'json'});
  expect(JSON.stringify(exported)).not.toContain('192.0.2.14');
  expect(JSON.stringify(exported)).not.toContain('198.51.100.17');
});
test('changing back to single-line mode restores original per-line preview and survives local revision save', async ({ page }) => {
  await page.goto('/?workspace=guided');
  await page.getByLabel('Guided raw sample logs').fill('{"action":"allow"}\ncontinuation text\n\n{"action":"deny"}');
  await page.getByRole('button', { name: /Separate events using blank lines/ }).click();
  await expect(page.locator('.guided-boundary-count')).toContainText('Logical events 2');
  await page.getByRole('button', { name: /One line = one event/ }).click();
  await expect(page.locator('.guided-boundary-count')).toContainText('Logical events 3');
  await page.getByRole('button', { name: /Separate events using blank lines/ }).click();
  await page.getByRole('button', { name: 'Save Draft' }).click();
  await page.getByRole('button', { name: 'Parser Library' }).click();
  await page.locator('.revision-card').click();
  await expect(page.getByRole('button', { name: /Separate events using blank lines/ })).toHaveAttribute('aria-pressed', 'true');
  await expect(page.getByLabel('Guided raw sample logs')).toHaveValue('');
});
