import {test,expect} from '@playwright/test';

for(const viewport of [{width:1440,height:900},{width:1280,height:800}]){
  test('first-time desktop visitor sees raw log entry without scrolling at '+viewport.width,async({page},info)=>{
    await page.setViewportSize(viewport);
    await page.goto('/');
    const raw=page.getByRole('textbox',{name:'Auto Parser raw logs'});
    await expect(raw).toBeVisible();
    const position=await raw.boundingBox();
    expect(position).not.toBeNull();
    expect(position!.y).toBeLessThan(viewport.height-90);
    const mainHeading=page.getByRole('heading',{name:/Paste security logs/});
    await expect(mainHeading).toBeVisible();
    await page.screenshot({path:info.outputPath('first-viewport.png'),fullPage:false});
    await raw.fill('{"event_type":"alert","src_ip":"192.0.2.11","action":"deny"}');
    const analyze=page.getByRole('button',{name:'Analyze Logs',exact:true});
    await expect(analyze).toBeEnabled();
    const button=await analyze.boundingBox();
    expect(button).not.toBeNull();
    expect(button!.y+button!.height).toBeLessThanOrEqual(viewport.height-12);
    await page.getByRole('button',{name:'Go to log input'}).click();
    await expect(raw).toBeFocused();
  });
}
