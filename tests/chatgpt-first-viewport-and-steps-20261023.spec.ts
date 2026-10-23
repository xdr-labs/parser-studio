import {test,expect} from '@playwright/test';

for(const viewport of [{width:1280,height:800},{width:1440,height:900}]){
  test('ChatGPT Assisted starts with original logs and shows ordered copy/paste steps at '+viewport.width,async({page},info)=>{
    await page.setViewportSize(viewport);
    const pageErrors:string[]=[];
    const externalRequests:string[]=[];
    page.on('pageerror',e=>pageErrors.push(e.message));
    await page.goto('/?workspace=chatgpt');
    const origin=new URL(page.url()).origin;
    page.on('request',request=>{
      if(/^https?:/.test(request.url())&&new URL(request.url()).origin!==origin)
        externalRequests.push(request.url());
    });
    await expect(page.getByRole('main',{name:'ChatGPT Assisted Parser'})).toBeVisible();
    const raw=page.getByLabel('ChatGPT local sample logs');
    const rawBounds=await raw.boundingBox();
    expect(rawBounds).not.toBeNull();
    expect(rawBounds!.y).toBeLessThan(viewport.height-90);
    const portBounds=await page.getByLabel('Parser listener port').boundingBox();
    expect(portBounds).not.toBeNull();
    expect(rawBounds!.y).toBeLessThan(portBounds!.y);
    await expect(page.getByRole('heading',{name:'3. Paste the ChatGPT result'})).toHaveCount(0);
    await expect(page.getByRole('heading',{name:'After preparing the prompt: paste ChatGPT’s JSON result'}))
      .toBeVisible();
    await page.screenshot({path:info.outputPath('chatgpt-first-screen.png'),fullPage:false});

    const example=[
      'date=2026-10-23 time=08:11:22 action=blocked srcip=192.0.2.10 dstip=198.51.100.10',
      'date=2026-10-23 time=08:11:23 action=allowed srcip=192.0.2.11 dstip=198.51.100.11',
    ].join('\n');
    await raw.fill(example);
    await page.getByLabel('ChatGPT solution vendor').fill('Example Security');
    await page.getByLabel('ChatGPT solution product').fill('Demo Gateway');
    await page.getByLabel('ChatGPT solution version or model').fill('4.2');
    await expect(page.getByRole('alert').filter({hasText:'The ChatGPT prompt includes your original log text'}))
      .toBeVisible();
    const prepare=page.getByRole('button',{name:'Prepare ChatGPT Prompt'});
    await expect(prepare).toBeEnabled({timeout:20000});
    await prepare.click();
    await expect(page.getByRole('heading',{name:'2. Copy to ChatGPT'}))
      .toBeVisible({timeout:20000});
    await expect(page.getByRole('heading',{name:'3. Paste the ChatGPT result'})).toBeVisible();
    const copied=await page.getByLabel('ChatGPT copyable prompt').inputValue();
    expect(copied).toContain(example);
    expect(copied).toContain('Demo Gateway');
    expect(copied).not.toContain('EXAMPLE-FW');
    expect(pageErrors).toEqual([]);
    expect(externalRequests).toEqual([]);
    await page.screenshot({path:info.outputPath('chatgpt-ordered-steps.png'),fullPage:true});
  });
}
