import { expect, test } from '@playwright/test';

const capabilities = {
  contract:'host-customized-pair.v0.1', projectSchemaRevision:'0.1',
  authoring:{receiverProtocols:['udp','tcp'],extractionFormats:['json','kv','csv','syslog_rfc5424','cef','leef'],
    formatCoverage:'reviewed-bounded-subset', multiline:false,arbitraryRuby:false,
    httpReceiver:false,multipleDistinctReceiverPorts:false},
  import:{exactInternalPairsEditable:true,unknownLegacyRubyEditable:false,structuralInspectionOnly:true},
  verification:{engineVerified:false,targetImportVerified:false,liveListenerVerified:false,proprietaryLoaderVerified:false},
  limits:{maxProjectBodyBytes:262144,maxInspectBodyBytes:2097152},
};
for (const [dialect, eventBody] of [
  ['json', '{"action":"allow","src_ip":"198.51.100.10"}'],
  ['kv', 'action=allow src_ip=198.51.100.10'],
] as const) {
  test('reviewed RFC5424 ' + dialect + ' body previews nested fields and validates declarative output', async ({page}) => {
    const sent: Record<string, unknown>[] = [];
    await page.route('**/api/v1/parser-pairs/capabilities', route => route.fulfill({
      status:200, contentType:'application/json', body:JSON.stringify(capabilities),
    }));
    await page.route('**/api/v1/parser-pairs/validate', route => {
      sent.push(route.request().postDataJSON() as Record<string, unknown>);
      return route.fulfill({status:200,contentType:'application/json',body:JSON.stringify({ok:true,issues:[]})});
    });
    await page.goto('/');
    await page.getByLabel('Synthetic starter template').selectOption('syslog_rfc5424');
    await page.getByRole('button', {name:'합성 예제 적용'}).click();
    await page.getByLabel('Guided raw sample logs').fill(
      '<34>1 2026-10-12T00:00:00Z fw app 1 EV01 - ' + eventBody + '\n' +
      '<34>1 2026-10-12T00:00:01Z fw app 1 EV02 - ' + eventBody,
    );
    await page.getByRole('button',{name:/2\. 필드 추출/}).click();
    await page.getByLabel('RFC5424 message body format').selectOption(dialect);
    await expect(page.locator('.guided-extracted-tags')).toContainText('body.action');
    await page.getByRole('button',{name:/5\. 검사·수정/}).click();
    await page.getByRole('button',{name:'브라우저 전체 테스트'}).click();
    await expect(page.locator('.guided-test-metric').filter({hasText:'실패'}).locator('strong')).toHaveText('0');
    await page.getByRole('button',{name:/6\. 파일 생성/}).click();
    await page.getByRole('button',{name:'백엔드 입력 검사'}).click();
    await expect(page.getByText('Schema PASS · 엔진 미검증')).toBeVisible();
    expect(sent).toHaveLength(1);
    expect(sent[0].extraction).toEqual({format:'syslog_rfc5424',syslogBodyFormat:dialect});
    expect(JSON.stringify(sent)).not.toContain('198.51.100.10');
  });
}

test('existing RFC5424 drafts default to raw body to preserve legacy parser behavior', async ({page}) => {
  await page.goto('/');
  await page.getByRole('button',{name:/2\. 필드 추출/}).click();
  await page.getByRole('button',{name:'RFC5424',exact:true}).click();
  await expect(page.getByLabel('RFC5424 message body format')).toHaveValue('raw');
});
