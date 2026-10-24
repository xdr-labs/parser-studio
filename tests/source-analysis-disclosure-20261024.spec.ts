import {test,expect} from '@playwright/test';

test('Analyze discloses the first-party server upload and never sends logs to ChatGPT',async({page})=>{
 const original='action=deny src_ip=198.51.100.42 dst_port=443';
 const toProvider:string[]=[];
 const analysisRequests:{url:string;raw:string}[]=[];
 page.on('request',request=>{
  if(/api\.openai\.com|chatgpt\.com|api\.anthropic\.com/i.test(request.url()))
    toProvider.push(request.url());
  if(request.method()==='POST'&&request.url().includes('/api/v1/multipass/preview')){
    const data=request.postDataJSON() as {raw?:string}|null;
    analysisRequests.push({url:request.url(),raw:data?.raw??''});
  }
 });
 await page.setViewportSize({width:1280,height:800});
 await page.goto('/');
 await expect(page.getByText('Log analysis uses this server')).toBeVisible();
 const layout=await page.evaluate(()=>({viewport:innerWidth,pageWidth:document.documentElement.scrollWidth}));
 expect(layout.pageWidth).toBeLessThanOrEqual(layout.viewport+1);
 const localButton=page.locator('.topbar-actions button').filter({hasText:'Local Versions'});
 const newButton=page.locator('.topbar-actions button').filter({hasText:'New Parser'});
 await expect(localButton).toBeVisible();
 await expect(newButton).toBeVisible();
 const firstTop=await localButton.evaluate(node=>node.getBoundingClientRect().top);
 const secondTop=await newButton.evaluate(node=>node.getBoundingClientRect().top);
 expect(Math.abs(firstTop-secondTop)).toBeLessThanOrEqual(4);
 await expect(page.getByText('Analyze Logs sends your original sample to this Parser Studio server',{exact:false})).toBeVisible();
 const logs=page.getByLabel('Auto Parser raw logs');
 await logs.fill(original);
 expect(analysisRequests).toHaveLength(0);
 const wait=page.waitForResponse(r=>r.url().includes('/api/v1/multipass/preview')&&r.request().method()==='POST');
 await page.getByRole('button',{name:'Analyze Logs',exact:true}).click();
 const response=await wait;
 expect(response.status()).toBe(200);
 expect(analysisRequests).toHaveLength(1);
 expect(analysisRequests[0]?.raw).toBe(original);
 expect(new URL(analysisRequests[0]!.url).origin).toBe(new URL(page.url()).origin);
 expect(toProvider).toEqual([]);
 await expect(logs).toHaveValue(original);
});
