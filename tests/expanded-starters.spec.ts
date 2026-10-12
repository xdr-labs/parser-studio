import { expect, test } from '@playwright/test';

const caps = {
  contract:'host-customized-pair.v0.1',projectSchemaRevision:'0.1',
  authoring:{receiverProtocols:['udp','tcp'],extractionFormats:['json','kv','csv','syslog_rfc5424','cef','leef'],
    formatCoverage:'reviewed-bounded-subset',httpReceiver:false,multipleDistinctReceiverPorts:false,
    multiline:false,arbitraryRuby:false,
    rfc5424AdjacentStructuredDataSubset:true,rfc5424StructuredDataMaxBytes:1024,
    rfc5424BodyFormats:['raw','json','kv','cef','leef'],leefHexSeparatorSubset:true},
  import:{exactInternalPairsEditable:true,unknownLegacyRubyEditable:false,structuralInspectionOnly:true},
  verification:{engineVerified:false,targetImportVerified:false,liveListenerVerified:false,proprietaryLoaderVerified:false},
  limits:{maxProjectBodyBytes:262144,maxInspectBodyBytes:2097152},
};

for(const [id,mode,portSource] of [
  ['rfc5424_cef','cef','body.dpt'],
  ['rfc5424_leef','leef','body.dstPort'],
] as const){
  test('no-code synthetic '+mode+' RFC5424 envelope includes correct mappings and guarded backend DRAFT',async({page})=>{
    const sent:Record<string,unknown>[]=[];
    await page.route('**/api/v1/parser-pairs/capabilities',route=>route.fulfill({
      status:200,contentType:'application/json',body:JSON.stringify(caps)}));
    await page.route('**/api/v1/parser-pairs/validate',route=>{
      sent.push(route.request().postDataJSON() as Record<string,unknown>);
      return route.fulfill({status:200,contentType:'application/json',body:JSON.stringify({ok:true,issues:[]})});
    });
    await page.goto('/');
    await page.getByLabel('Synthetic starter template').selectOption(id);
    await page.getByRole('button',{name:'합성 예제 적용'}).click();
    await expect(page.getByLabel('Parser ID')).toHaveValue('example_'+id);
    await page.getByRole('button',{name:/2\. 필드 추출/}).click();
    await expect(page.getByRole('button',{name:'RFC5424',exact:true})).toHaveAttribute('aria-pressed','true');
    await expect(page.getByLabel('RFC5424 message body format')).toHaveValue(mode);
    await expect(page.locator('.guided-extracted-tags')).toContainText('body.act');
    await page.getByRole('button',{name:/3\. 필드 매핑/}).click();
    await expect(page.getByLabel('Source field 0')).toHaveValue('body.src');
    await expect(page.getByLabel('Source field 1')).toHaveValue(portSource);
    await page.getByRole('button',{name:/4\. 수신·분류/}).click();
    const preview=page.getByLabel('Sample classification preview');
    await expect(preview.locator('.guided-routing-row')).toHaveCount(2);
    await expect(preview.locator('.guided-routing-row').first()).toContainText('Session');
    await expect(preview.locator('.guided-routing-row').nth(1)).toContainText('Threat');
    await page.getByRole('button',{name:/5\. 검사·수정/}).click();
    await page.getByRole('button',{name:'브라우저 전체 테스트'}).click();
    await expect(page.locator('.guided-test-metric').filter({hasText:'실패'}).locator('strong')).toHaveText('0');
    await page.getByRole('button',{name:/6\. 파일 생성/}).click();
    await page.getByRole('button',{name:'백엔드 입력 검사'}).click();
    await expect(page.getByText('Schema PASS · 엔진 미검증')).toBeVisible();
    expect(sent).toHaveLength(1);
    expect(sent[0].extraction).toEqual({format:'syslog_rfc5424',syslogBodyFormat:mode});
    expect(JSON.stringify(sent)).not.toContain('198.51.100.10');
    expect(JSON.stringify(sent)).not.toContain('203.0.113.11');
  });
}
