import { expect, test } from '@playwright/test';
import { readFile } from 'node:fs/promises';

test('guided builder is the default six-step no-code experience', async ({ page }) => {
  await page.goto('/');
  await expect(page.getByRole('main', { name: 'No-code Parser Guided Builder' })).toBeVisible();
  await expect(page.getByRole('heading', { name: /파서를 직접 만들어 보세요/ })).toBeVisible();
  await expect(page.locator('.guided-step')).toHaveCount(6);
  await expect(page.getByRole('heading', { name: '어떤 로그를 처리할까요?' })).toBeVisible();
  await expect(page.locator('.guided-inspector')).toContainText('Stellar 적재 검증');
  await expect(page.locator('.guided-inspector')).toContainText('미검증');
  await expect(page.locator('footer')).toContainText('Fluentd & Stellar: NOT VERIFIED');
  await page.screenshot({ path: test.info().outputPath('guided-start-desktop.png'), fullPage: true });
});

test('nondeveloper can select a token, test a field proposal and keep JSON family intact', async ({ page }) => {
  await page.goto('/');
  await page.getByRole('button', { name: '다음 단계' }).click();
  await expect(page.getByRole('heading', { name: '로그에서 어떤 값을 추출할까요?' })).toBeVisible();
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
  await expect(page.getByRole('button', { name: '필드 규칙 적용' })).toBeDisabled();
  await page.getByRole('button', { name: '전체 샘플에서 일치 검사' }).click();
  await expect(page.getByRole('status')).toContainText('2 / 3개 이벤트 일치');
  await page.getByRole('button', { name: '필드 규칙 적용' }).click();
  await expect(page.getByRole('button', { name: 'JSON', exact: true })).toHaveAttribute('aria-pressed', 'true');
  await page.getByRole('button', { name: '다음 단계' }).click();
  await expect(page.locator('.guided-map-card')).toHaveCount(4);
  await expect(page.getByRole('combobox', { name: 'Source field 3' })).toHaveValue('device');
  await page.getByRole('button', { name: '초안 저장' }).click();
  const revisions = await page.evaluate(() => JSON.stringify(localStorage));
  expect(revisions).not.toContain('DEMO-FW');
  expect(revisions).toContain('custom.device');
});

test('complete six UI stages, execute browser test, download typed contract but never unverified pair', async ({ page }) => {
  await page.goto('/');
  await page.getByLabel('Guided parser name').fill('Synthetic Firewall');
  await page.getByLabel('Guided vendor').fill('Fictitious Network Lab');
  await page.getByLabel('Parser ID').fill('sample_fw');
  await page.getByRole('button', { name: '다음 단계' }).click();
  await page.getByRole('button', { name: 'JSON', exact: true }).click();
  await page.getByRole('button', { name: '다음 단계' }).click();
  await page.getByRole('combobox', { name: 'Mapping group 2' }).selectOption('ns_fields');
  await page.getByRole('button', { name: '다음 단계' }).click();
  await expect(page.getByRole('heading', { name: '로그는 어디에서 들어오고 어떻게 분류되나요?' })).toBeVisible();
  await page.getByLabel('Receiving port').fill('7512');
  await expect(page.getByLabel('UDP receiver')).toBeChecked();
  await expect(page.getByLabel('TCP receiver')).toBeChecked();
  await expect(page.getByLabel('Rule class 0')).toHaveValue('Threat');
  await page.getByRole('button', { name: '다음 단계' }).click();
  await page.getByRole('button', { name: '브라우저 전체 테스트' }).click();
  await expect(page.locator('.guided-test-metrics')).toContainText('입력 이벤트');
  await expect(page.locator('.guided-test-metrics')).toContainText('3');
  await expect(page.getByText('테스트 엔진: browser-preview')).toBeVisible();
  await page.getByRole('button', { name: '다음 단계' }).click();
  await expect(page.getByRole('heading', { name: '어떤 파일을 생성하게 되나요?' })).toBeVisible();
  await expect(page.getByText('customized_sample_fw.conf')).toBeVisible();
  await expect(page.getByText('customized_sample_fw', { exact: true })).toBeVisible();
  await expect(page.getByRole('button', { name: '파서 2개 파일 생성 (연결 대기)' })).toBeDisabled();
  await expect(page.getByText('UI 입력 검사는 통과했습니다.')).toBeVisible();
  const download = page.waitForEvent('download');
  await page.getByRole('button', { name: '백엔드용 프로젝트 JSON 다운로드' }).click();
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
  await page.goto('/');
  await page.getByLabel('Parser ID').fill('../unsafe');
  await page.getByRole('button', { name: /4\. 수신·분류/ }).click();
  await page.getByLabel('Receiving port').fill('22');
  await page.getByLabel('UDP receiver').uncheck();
  await page.getByLabel('TCP receiver').uncheck();
  await page.getByRole('button', { name: /6\. 파일 생성/ }).click();
  await expect(page.locator('.guided-contract-errors').first()).toContainText('Parser ID');
  await expect(page.locator('.guided-contract-errors').first()).toContainText('Receiving port');
  await expect(page.getByRole('button', { name: '백엔드용 프로젝트 JSON 다운로드' })).toBeDisabled();
  await expect(page.getByRole('button', { name: '파서 2개 파일 생성 (연결 대기)' })).toBeDisabled();
});

test('guided draft and expert editor share rules, samples and local revision state', async ({ page }) => {
  await page.goto('/');
  await page.getByLabel('Guided vendor').fill('Shared Draft Vendor');
  await page.getByRole('button', { name: '전문가 화면 열기' }).click();
  await expect(page.getByRole('heading', { name: 'Parser pipeline' })).toBeVisible();
  await expect(page.locator('.input-row input')).toHaveValue('Shared Draft Vendor');
  await page.getByRole('button', { name: 'Guided Builder' }).click();
  await expect(page.getByLabel('Guided vendor')).toHaveValue('Shared Draft Vendor');
  await page.getByRole('button', { name: /4\. 수신·분류/ }).click();
  await page.getByLabel('Receiving port').fill('7588');
  await page.getByRole('button', { name: '초안 저장' }).click();
  await page.getByRole('button', { name: 'Parser Library' }).click();
  await expect(page.locator('.revision-card')).toHaveCount(1);
  await page.locator('.revision-card').click();
  await expect(page.getByRole('heading', { name: '어떤 로그를 처리할까요?' })).toBeVisible();
  await page.getByRole('button', { name: /4\. 수신·분류/ }).click();
  await expect(page.getByLabel('Receiving port')).toHaveValue('7588');
  await expect(page.getByLabel('Guided raw sample logs')).toHaveCount(0);
  await expect(page.locator('footer')).toContainText('Dataset 0');
});

test('small-screen guided mode never hides validation or overflows browser width', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto('/');
  await expect(page.getByRole('main', { name: 'No-code Parser Guided Builder' })).toBeVisible();
  await page.getByRole('button', { name: /4\. 수신·분류/ }).click();
  await expect(page.getByLabel('Receiving port')).toBeVisible();
  await page.getByRole('button', { name: /6\. 파일 생성/ }).click();
  await expect(page.getByRole('button', { name: '파서 2개 파일 생성 (연결 대기)' })).toBeDisabled();
  const width = await page.evaluate(() => ({ content: document.documentElement.scrollWidth, viewport: window.innerWidth }));
  expect(width.content).toBeLessThanOrEqual(width.viewport + 1);
  await page.screenshot({ path: test.info().outputPath('guided-mobile.png'), fullPage: true });
});

test('ordered no-code event classification previews the reason per sample without native claims', async ({ page }) => {
  await page.goto('/');
  await page.getByRole('button', { name: /4\. 수신·분류/ }).click();
  await expect(page.locator('.guided-routing-row')).toHaveCount(3);
  await expect(page.locator('.guided-routing-row').nth(0)).toContainText('Session');
  await expect(page.locator('.guided-routing-row').nth(0)).toContainText('action = allow');
  await expect(page.locator('.guided-routing-row').nth(1)).toContainText('Threat');
  await expect(page.locator('.guided-routing-row').nth(2)).toContainText('Threat');
  await page.getByLabel('Rule value 1').fill('not-allow');
  await page.getByLabel('Default classification').selectOption('Winlogevent');
  await expect(page.locator('.guided-routing-row').nth(0)).toContainText('Winlogevent');
  await expect(page.locator('.guided-routing-row').nth(0)).toContainText('기본값');
  await expect(page.locator('.guided-routing-row').nth(1)).toContainText('Threat');
  await expect(page.getByText('실제 stellar_log_index 태그 라우팅은 별도 Fluentd 엔진 검증')).toBeVisible();
});


test('no-code classification shows per-event rule reason and fallback without claiming native routing', async ({ page }) => {
  await page.goto('/');
  await page.getByRole('button', { name: /4\. 수신·분류/ }).click();
  const routes = page.getByLabel('Sample classification preview');
  await expect(routes.locator('.guided-routing-row')).toHaveCount(3);
  await expect(routes.locator('.guided-routing-row').nth(0)).toContainText('Session');
  await expect(routes.locator('.guided-routing-row').nth(0)).toContainText('action = allow · 조건 2');
  await expect(routes.locator('.guided-routing-row').nth(1)).toContainText('Threat');
  await expect(routes.locator('.guided-routing-row').nth(1)).toContainText('action = deny · 조건 1');

  await page.getByLabel('Rule value 0').fill('block');
  await expect(routes.locator('.guided-routing-row').nth(1)).toContainText('Syslog');
  await expect(routes.locator('.guided-routing-row').nth(1)).toContainText('기본 이벤트 유형 적용');
  await page.getByLabel('Default classification').selectOption('Winlogevent');
  await expect(routes.locator('.guided-routing-row').nth(1)).toContainText('Winlogevent');
  await expect(page.getByText('실제 stellar_log_index 태그 라우팅은 별도 Fluentd 엔진 검증이 필요합니다.')).toBeVisible();
  await page.screenshot({ path: test.info().outputPath('guided-routing-preview.png'), fullPage: true });
});

test('malformed sample remains explicitly unclassified instead of being silently routed', async ({ page }) => {
  await page.goto('/');
  await page.getByLabel('Guided raw sample logs').fill('a log message with no structured fields');
  await page.getByRole('button', { name: /4\. 수신·분류/ }).click();
  const routes = page.getByLabel('Sample classification preview');
  await expect(routes.locator('.guided-routing-row')).toHaveCount(1);
  await expect(routes.locator('.guided-routing-row').first()).toContainText('미분류');
  await expect(routes.locator('.guided-routing-row').first()).toContainText('추출 실패');
  await expect(routes.locator('.guided-routing-row').first()).not.toContainText('Syslog');
});
