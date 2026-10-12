import { expect, test } from '@playwright/test';

const capabilities = {
  contract:'host-customized-pair.v0.1', projectSchemaRevision:'0.1',
  authoring: { receiverProtocols:['udp','tcp'], extractionFormats:['json','kv','csv','syslog_rfc5424','cef','leef'],
    formatCoverage:'reviewed-bounded-subset', multiline:false, arbitraryRuby:false,
    httpReceiver:false, multipleDistinctReceiverPorts:false },
  import: { exactInternalPairsEditable:true, unknownLegacyRubyEditable:false, structuralInspectionOnly:true },
  verification: { engineVerified:false,targetImportVerified:false,liveListenerVerified:false,proprietaryLoaderVerified:false },
  limits: { maxProjectBodyBytes:262144,maxInspectBodyBytes:2097152 },
};

for (const {name, separator} of [
  {name:'semicolon',separator:';'},
  {name:'TAB',separator:'\t'},
]) {
  test('CSV ' + name + ' delimiter is preserved across browser preview and backend project', async ({page}) => {
    const projects: Array<Record<string, unknown>> = [];
    await page.route('**/api/v1/parser-pairs/capabilities', route =>
      route.fulfill({status:200,contentType:'application/json',body:JSON.stringify(capabilities)}));
    await page.route('**/api/v1/parser-pairs/validate', route => {
      projects.push(route.request().postDataJSON() as Record<string, unknown>);
      return route.fulfill({status:200,contentType:'application/json',body:JSON.stringify({ok:true,issues:[]})});
    });
    await page.goto('/');
    await page.getByLabel('Guided raw sample logs').fill(
      ['allow','198.51.100.10','443'].join(separator) + '\n' +
      ['deny','203.0.113.12','22'].join(separator),
    );
    await page.getByRole('button',{name:/2\. 필드 추출/}).click();
    await page.getByRole('button',{name:'CSV',exact:true}).click();
    await page.getByLabel('Guided CSV columns').fill('action,src_ip,dst_port');
    await page.getByLabel('Guided CSV data delimiter').selectOption(separator);
    await page.getByRole('button',{name:/5\. 검사·수정/}).click();
    await page.getByRole('button',{name:'브라우저 전체 테스트'}).click();
    await expect(page.locator('.guided-test-metric').filter({hasText:'실패'}).locator('strong')).toHaveText('0');
    await expect(page.locator('.guided-test-metric').filter({hasText:'정규화 성공'}).locator('strong')).toHaveText('2');
    await page.getByRole('button',{name:/6\. 파일 생성/}).click();
    await page.getByRole('button',{name:'백엔드 입력 검사'}).click();
    await expect(page.getByText('Schema PASS · 엔진 미검증')).toBeVisible();
    expect(projects).toHaveLength(1);
    expect(projects[0].extraction).toEqual({
      format:'csv', csvColumns:['action','src_ip','dst_port'], csvDelimiter:separator,
    });
    expect(JSON.stringify(projects)).not.toContain('198.51.100.10');
    expect(JSON.stringify(projects)).not.toContain('203.0.113.12');
  });
}

test('legacy CSV drafts without a delimiter remain comma based', async ({page}) => {
  await page.goto('/');
  await page.getByRole('button',{name:/2\. 필드 추출/}).click();
  await page.getByRole('button',{name:'CSV',exact:true}).click();
  await expect(page.getByLabel('Guided CSV data delimiter')).toHaveValue(',');
});
