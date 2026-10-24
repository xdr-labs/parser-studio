import {test,expect} from '@playwright/test';
import {createHash} from 'node:crypto';

test('real local Python Multi-Pass preserves irregular source framing and review-only semantics',async({page})=>{
 const samples=[
  {kind:'bracketed application target',raw:'[10.30 16:49:06] chrome.exe - host.example:5070 open through proxy host.example:5070 HTTPS',
    syntax:'BRACKETED_MONTH_DAY_APPLICATION_TARGET',field:'target_host',expected:'host.example'},
  {kind:'logcat threadtime',raw:'03-17 16:13:38.811  1702  2395 D WindowManager: Untrusted content',
    syntax:'ANDROID_LOGCAT_THREADTIME',field:'tag',expected:'WindowManager'},
  {kind:'six-digit time process',raw:'081109 203615 148 INFO dfs.DataNode$PacketResponder: PacketResponder 1 for block blk_123 terminating',
    syntax:'GENERIC_TEXT_ENVELOPE_DATECODE_LEVEL',field:'text_header',expected:null},
 ];
 const errors:string[]=[];page.on('pageerror',e=>errors.push(e.message));
 for(const sample of samples){
  await page.goto('/');
  await page.getByLabel('Auto Parser raw logs').fill(sample.raw);
  const wait=page.waitForResponse(r=>r.url().includes('/api/v1/multipass/preview')&&r.request().method()==='POST');
  await page.getByRole('button',{name:'Analyze Logs',exact:true}).click();
  const response=await wait;
  expect(response.status(),sample.kind).toBe(200);
  const result=await response.json();
  const event=(result.events?.[0]?.preview??result);
  expect(event.status,sample.kind).toBe('PARTIAL');
  expect(event.syntax,sample.kind).toContain(sample.syntax);
  expect(event.issues,sample.kind).toContain('FREE_TEXT_FIELD_ROLES_NEED_REVIEW');
  expect(event.sourceSha256).toBe(createHash('sha256').update(sample.raw).digest('hex'));
  expect(event.nativeVerified).toBe(false);
  expect(event.targetVerified).toBe(false);
  if(sample.expected===null){
   expect(event.fields.text_header).toBeTruthy();
   expect(event.fields.body.message).toContain('PacketResponder');
  }else expect(event.fields[sample.field]).toBe(sample.expected);
  await expect(page.getByLabel('Auto Parser raw logs')).toHaveValue(sample.raw);
 }
 expect(errors).toEqual([]);
});
