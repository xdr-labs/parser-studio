import {test,expect} from '@playwright/test';
import {createHash} from 'node:crypto';

const original='ALERT#A17#192.0.2.5#198.51.100.4#udp#53#deny';
const checksum=createHash('sha256').update(original).digest('hex');

test('unresolved logs warn before manual copying without requiring a separate masking approval',async({page,context})=>{
  const externalRequests:string[]=[];
  page.on('request',request=>{
    const url=new URL(request.url());
    if(/(?:^|\.)(?:openai\.com|chatgpt\.com)$/.test(url.hostname))
      externalRequests.push(url.hostname);
  });
  await page.route('**/api/v1/multipass/preview',route=>{
    expect(route.request().postDataJSON()).toEqual({raw:original});
    return route.fulfill({status:200,contentType:'application/json',
      body:JSON.stringify({
        contract:'parser-studio.multipass-source-preview.v0.1',
        status:'RAW_ONLY',syntax:'UNKNOWN',sourceSha256:checksum,
        sourceBytes:Buffer.byteLength(original),fields:{},spans:[],
        residuals:[{startByte:0,endByte:Buffer.byteLength(original)}],
        issues:['NO_SUPPORTED_GRAMMAR'],
        nativeVerified:false,targetVerified:false,
      })});
  });
  await page.goto('/');
  await page.getByLabel('Auto Parser raw logs').fill(original);
  await page.getByRole('button',{name:'Analyze Logs'}).click();
  const inspector=page.getByLabel('Parse problem inspector');
  await expect(inspector).toContainText('could not');
  await inspector.getByRole('button',{name:'Fix with ChatGPT'}).click();

  const warning=page.getByRole('note').filter({hasText:'original log input'});
  await expect(warning).toContainText('redact any sensitive values');
  await expect(warning).toContainText('never sends it automatically');
  const prompt=page.getByLabel('Generated ChatGPT repair prompt');
  await expect(prompt).toBeVisible();
  await expect(prompt).toHaveJSProperty('readOnly',false);
  await expect(prompt).toContainText(original);
  const copy=page.getByRole('button',{name:'Copy Prompt'});
  await expect(copy).toBeEnabled();
  await expect(inspector.getByRole('checkbox',{name:/redact|mask|approve/i})).toHaveCount(0);

  // The user may mask values or copy unchanged; there is no forced approval gate.
  await prompt.fill('USER REVIEWED EXAMPLE: ALERT#A17#192.0.2.5#<REDACTED>');
  await context.grantPermissions(['clipboard-read','clipboard-write']);
  await copy.click();
  await expect(inspector.getByRole('status')).toContainText('prompt copied');
  const copied=await page.evaluate(()=>navigator.clipboard.readText());
  expect(copied).toBe('USER REVIEWED EXAMPLE: ALERT#A17#192.0.2.5#<REDACTED>');
  await expect(page.getByLabel('Auto Parser raw logs')).toHaveValue(original);
  expect(externalRequests).toEqual([]);
});
