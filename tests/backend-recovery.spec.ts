import { expect, test } from '@playwright/test';

test('backend field error offers a keyboard-accessible route to its no-code editor', async ({ page }) => {
  const cap = {
    contract: 'host-customized-pair.v0.1', projectSchemaRevision: '0.1',
    authoring: {
      receiverProtocols: ['udp', 'tcp'], extractionFormats: ['json', 'kv', 'csv'],
      formatCoverage: 'reviewed-bounded-subset', multiline: false,
      arbitraryRuby: false, httpReceiver: false, multipleDistinctReceiverPorts: false,
    },
    import: { exactInternalPairsEditable: true, unknownLegacyRubyEditable: false, structuralInspectionOnly: true },
    verification: { engineVerified: false, targetImportVerified: false, liveListenerVerified: false, proprietaryLoaderVerified: false },
    limits: { maxProjectBodyBytes: 262144, maxInspectBodyBytes: 2097152 },
  };
  await page.route('**/api/v1/parser-pairs/capabilities', route => route.fulfill({
    status: 200, contentType: 'application/json', body: JSON.stringify(cap),
  }));
  await page.route('**/api/v1/parser-pairs/validate', route => route.fulfill({
    status: 422, contentType: 'application/json', body: JSON.stringify({
      ok: false,
      issues: [{ code:'UNMAPPED_ROUTE',path:'/classification/rules/0',message:'Route requires a normalized field' }],
    }),
  }));
  await page.goto('/');
  await page.getByLabel('Guided raw sample logs').fill('{"action":"allow","src_ip":"198.51.100.10","dst_port":443}');
  await page.getByRole('button', { name: /2\. 필드 추출/ }).click();
  await page.getByRole('button', { name: 'JSON', exact: true }).click();
  await page.getByRole('button', { name: /6\. 파일 생성/ }).click();
  await page.getByRole('button', { name: '백엔드 입력 검사' }).click();
  await expect(page.getByLabel('Backend validation errors')).toContainText('UNMAPPED_ROUTE');
  await page.getByRole('button', { name: '분류 설정으로 이동' }).click();
  await expect(page.locator('.guided-step.active')).toContainText('수신·분류');
});
