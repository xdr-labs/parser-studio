import { expect, test } from '@playwright/test';
import { readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { DEMO_SAMPLES } from '../src/model';

test('explicit downloaded browser suite evidence is bound to samples but excludes customer values',async({page})=>{
  let backendCalls=0;
  page.on('request',request=>{
    if (request.url().includes('/api/v1/parser-pairs/')) backendCalls++;
  });
  await page.goto('/');
  await page.getByRole('button',{name:/5\. 검사·수정/}).click();
  const button=page.getByRole('button',{name:'브라우저 테스트 증거 JSON 다운로드'});
  await expect(button).toBeDisabled();
  await page.getByRole('button',{name:'브라우저 전체 테스트'}).click();
  await expect(button).toBeEnabled();
  const promise=page.waitForEvent('download');
  await button.click();
  const file=await promise;
  expect(file.suggestedFilename()).toMatch(/^parser_studio_[a-z0-9_]+_browser_test_evidence\.json$/);
  const data=await readFile(await file.path(),'utf8');
  const report=JSON.parse(data);
  expect(report).toMatchObject({
    reportSchema:'parser-studio.browser-test-evidence.v0.1',
    engine:'browser-preview',artifactStatus:'DRAFT_ONLY',
    compatibility:{nativeFluentdVerified:false,stellarTargetVerified:false},
    privacy:{rawLogsIncluded:false,normalizedValuesIncluded:false,diagnosticMessagesIncluded:false},
    counts:{total:3},
  });
  expect(report.source.sampleSha256).toBe(createHash('sha256').update(DEMO_SAMPLES).digest('hex'));
  expect(report.events).toHaveLength(3);
  expect(report.events[2].diagnostics).toEqual(expect.arrayContaining([
    {stage:'normalize',severity:'error',code:'TYPE_ERROR'},
  ]));
  for (const secret of ['198.51.100.10','203.0.113.12','DEMO-FW','invalid-ip','"raw"']) {
    expect(data).not.toContain(secret);
  }
  expect(backendCalls).toBe(0);
});

test('editing the sample invalidates the previous browser evidence download',async({page})=>{
  await page.goto('/');
  await page.getByRole('button',{name:/5\. 검사·수정/}).click();
  const button=page.getByRole('button',{name:'브라우저 테스트 증거 JSON 다운로드'});
  await page.getByRole('button',{name:'브라우저 전체 테스트'}).click();
  await expect(button).toBeEnabled();
  await page.getByRole('button',{name:/1\. 로그 가져오기/}).click();
  await page.getByLabel('Guided raw sample logs').fill('{"action":"allow","src_ip":"198.51.100.60","dst_port":443}');
  await page.getByRole('button',{name:/5\. 검사·수정/}).click();
  await expect(button).toBeDisabled();
  await page.getByRole('button',{name:'브라우저 전체 테스트'}).click();
  await expect(button).toBeEnabled();
});
