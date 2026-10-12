import { expect, test } from '@playwright/test';

const legacy = {
  contract:'host-customized-pair.v0.1',projectSchemaRevision:'0.1',
  authoring:{receiverProtocols:['udp','tcp'],extractionFormats:['json','kv','csv','syslog_rfc5424','cef','leef'],
    formatCoverage:'reviewed-bounded-subset',multiline:false,arbitraryRuby:false,
    httpReceiver:false,multipleDistinctReceiverPorts:false},
  import:{exactInternalPairsEditable:true,unknownLegacyRubyEditable:false,structuralInspectionOnly:true},
  verification:{engineVerified:false,targetImportVerified:false,liveListenerVerified:false,proprietaryLoaderVerified:false},
  limits:{maxProjectBodyBytes:262144,maxInspectBodyBytes:2097152},
};
const expanded = {...legacy,authoring:{...legacy.authoring,
  rfc5424AdjacentStructuredDataSubset:true,rfc5424StructuredDataMaxBytes:1024,
  rfc5424BodyFormats:['raw','json','kv','cef','leef'],leefHexSeparatorSubset:true,
}};

for(const [mode,body] of [
  ['cef','CEF:0|Synthetic|FW|1|42|Blocked|8|src=192.0.2.11 dpt=443 act=deny'],
  ['leef','LEEF:2.0|Synthetic|FW|1|501|0x5E|src=203.0.113.8^dstPort=80^act=deny'],
] as const){
  test('new reviewed RFC5424 nested '+mode+' body: local preview → capability → backend metadata',async ({page})=>{
    const sent:Record<string,unknown>[]=[];
    await page.route('**/api/v1/parser-pairs/capabilities',route=>route.fulfill({
      status:200,contentType:'application/json',body:JSON.stringify(expanded)}));
    await page.route('**/api/v1/parser-pairs/validate',route=>{
      sent.push(route.request().postDataJSON() as Record<string,unknown>);
      return route.fulfill({status:200,contentType:'application/json',body:JSON.stringify({ok:true,issues:[]})});
    });
    const head='<165>1 2026-10-12T01:02:03Z edge fw 1 ID ';
    await page.goto('/');
    await page.getByLabel('Guided raw sample logs').fill(
      head+'- '+body+'\n'+head+'- '+body,
    );
    await page.getByRole('button',{name:/2\. 필드 추출/}).click();
    await page.getByRole('button',{name:'RFC5424',exact:true}).click();
    await page.getByLabel('RFC5424 message body format').selectOption(mode);
    await expect(page.locator('.guided-extracted-tags')).toContainText('body.src');
    await page.getByRole('button',{name:/3\. 필드 매핑/}).click();
    await page.getByRole('button',{name:/안전한 남은 필드 모두 추가/}).click();
    await page.getByRole('button',{name:/5\. 검사·수정/}).click();
    await page.getByRole('button',{name:'브라우저 전체 테스트'}).click();
    await expect(page.locator('.guided-test-metric').filter({hasText:'실패'}).locator('strong')).toHaveText('0');
    await expect(page.locator('.guided-test-metric').filter({hasText:'정규화 성공'}).locator('strong')).toHaveText('2');
    await page.getByRole('button',{name:/6\. 파일 생성/}).click();
    await page.getByRole('button',{name:'백엔드 입력 검사'}).click();
    await expect(page.getByText('Schema PASS · 엔진 미검증')).toBeVisible();
    expect(sent).toHaveLength(1);
    expect(sent[0].extraction).toEqual({format:'syslog_rfc5424',syslogBodyFormat:mode});
    expect(JSON.stringify(sent)).not.toContain('192.0.2.11');
    expect(JSON.stringify(sent)).not.toContain('203.0.113.8');
  });
}

test('old backend is not treated as authorizing newer RFC5424 nested CEF',async({page})=>{
  let validationCalls=0;
  await page.route('**/api/v1/parser-pairs/capabilities',route=>route.fulfill({
    status:200,contentType:'application/json',body:JSON.stringify(legacy)}));
  await page.route('**/api/v1/parser-pairs/validate',route=>{
    validationCalls++;
    return route.abort();
  });
  await page.goto('/');
  await page.getByRole('button',{name:/2\. 필드 추출/}).click();
  await page.getByRole('button',{name:'RFC5424',exact:true}).click();
  await page.getByLabel('RFC5424 message body format').selectOption('cef');
  await page.getByRole('button',{name:/6\. 파일 생성/}).click();
  await page.getByRole('button',{name:'백엔드 입력 검사'}).click();
  await expect(page.getByRole('alert')).toContainText('CEF');
  await expect(page.getByRole('button',{name:'파서 2개 파일 생성 (연결 대기)'})).toBeDisabled();
  expect(validationCalls).toBe(0);
});
