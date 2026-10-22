import {test,expect} from '@playwright/test';
import {createHash} from 'node:crypto';

const first='{"action":"BLOCK","srcip":"192.0.2.1"}';
const second='{"action":"ALLOW","srcip":"198.51.100.2"}';
const raw=first+'\n'+second;
const sha=(value:string)=>createHash('sha256').update(value).digest('hex');
const preview=(source:string,action:string,srcip:string)=>({
  contract:'parser-studio.multipass-source-preview.v0.1',
  status:'SOURCE_PARSED',syntax:'JSON',sourceSha256:sha(source),
  sourceBytes:Buffer.byteLength(source),fields:{action,srcip},
  spans:[],residuals:[],issues:[],nativeVerified:false,targetVerified:false,
});
const firstBytes=Buffer.byteLength(first);
const response={
  contract:'parser-studio.multipass-source-batch-preview.v0.1',
  sourceSha256:sha(raw),sourceBytes:Buffer.byteLength(raw),eventCount:2,
  events:[
    {index:0,startByte:0,endByte:firstBytes,preview:preview(first,'BLOCK','192.0.2.1')},
    {index:1,startByte:firstBytes+1,endByte:Buffer.byteLength(raw),
      preview:preview(second,'ALLOW','198.51.100.2')},
  ],
  separators:[{startByte:firstBytes,endByte:firstBytes+1,kind:'WHITESPACE'}],
  nativeVerified:false,targetVerified:false,
};

test('default Analyze Logs uses exact Multi-Pass event framing and preserves source in review',async({page})=>{
  await page.route('**/api/v1/multipass/preview-batch',async route=>{
    expect(route.request().method()).toBe('POST');
    expect(route.request().postDataJSON()).toEqual({raw});
    await route.fulfill({status:200,contentType:'application/json',body:JSON.stringify(response)});
  });
  await page.goto('/');
  const source=page.getByLabel('Auto Parser raw logs');
  await source.fill(raw);
  await page.getByRole('button',{name:'Analyze Logs',exact:true}).click();
  await expect(page.getByLabel('Beginner analysis summary')).toContainText('2 of 2 log events parsed completely');
  const review=page.getByRole('button',{name:'Review Fields',exact:true});
  await expect(review).toBeEnabled({timeout:20000});
  await review.click();
  const inspector=page.getByLabel('Browser-only event inspector');
  await expect(inspector).toContainText('BLOCK');
  await expect(inspector).toContainText('192.0.2.1');
  await page.getByLabel('Auto Parser review event').selectOption({index:1});
  await expect(inspector).toContainText('ALLOW');
  await expect(inspector).toContainText('198.51.100.2');
  await page.getByRole('button',{name:'Back to Logs'}).click();
  await expect(source).toHaveValue(raw);
  await expect(page.getByLabel('Deeper local log analysis',{exact:true})).toHaveCount(0);
});
