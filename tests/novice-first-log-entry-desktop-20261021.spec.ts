import {expect,test} from '@playwright/test';

// Scope: desktop-only user flow. No mobile acceptance, target network, or credentials.
test('a new desktop user can jump from the opening explanation straight to the original raw log input',async({page},info)=>{
  await page.setViewportSize({width:1440,height:900});
  await page.goto('/');
  const start=page.getByRole('button',{name:'Go to log input'});
  await expect(start).toBeVisible();
  const position=await start.boundingBox();
  expect(position).not.toBeNull();
  expect(position!.y+position!.height).toBeLessThanOrEqual(900);
  await start.click();
  const sample=page.getByRole('textbox',{name:'Auto Parser raw logs'});
  await expect(sample).toBeFocused();
  const textarea=await sample.boundingBox();
  expect(textarea).not.toBeNull();
  expect(textarea!.y).toBeLessThan(900);
  expect(textarea!.y+Math.min(textarea!.height,50)).toBeGreaterThan(0);
  await sample.fill('{"event_type":"threat","message":"테스트"}');
  await expect(page.getByRole('button',{name:'Analyze Logs',exact:true})).toBeEnabled();
  await expect(page.getByRole('textbox',{name:'Parser manufacturer'})).toHaveValue('Demo / local draft');
  await page.screenshot({path:info.outputPath('desktop-first-log-entry.png'),fullPage:true});
});

test('the single input shortcut is absent when named log types replace the raw input',async({page})=>{
  await page.setViewportSize({width:1440,height:900});
  await page.goto('/');
  await page.getByRole('button',{name:'Add Another Log Type'}).first().click();
  await expect(page.getByRole('button',{name:'Go to log input'})).toHaveCount(0);
  await expect(page.getByLabel('Log type sample 1')).toBeVisible();
});

test('the desktop shortcut never clears manually entered parser identity',async({page})=>{
  await page.setViewportSize({width:1280,height:800});
  await page.goto('/');
  await page.getByRole('textbox',{name:'Parser manufacturer'}).fill('Example Vendor');
  await page.getByRole('textbox',{name:'Parser product',exact:true}).fill('Example Firewall');
  await page.getByRole('button',{name:'Go to log input'}).click();
  await expect(page.getByRole('textbox',{name:'Auto Parser raw logs'})).toBeFocused();
  await expect(page.getByRole('textbox',{name:'Parser manufacturer'})).toHaveValue('Example Vendor');
  await expect(page.getByRole('textbox',{name:'Parser product',exact:true})).toHaveValue('Example Firewall');
});
