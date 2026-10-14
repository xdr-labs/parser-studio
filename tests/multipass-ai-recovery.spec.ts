import {test,expect} from '@playwright/test';
import {createHash} from 'node:crypto';

test.use({viewport:{width:390,height:844},hasTouch:true,isMobile:true});
const raw='%ASA-4-106023: Deny udp src outside:192.0.2.1/53 dst inside:198.51.100.1/53';
const response={
 contract:'parser-studio.multipass-source-preview.v0.1',status:'PARTIAL',syntax:'CISCO_ASA_FTD_MESSAGE_ID',
 sourceSha256:createHash('sha256').update(raw).digest('hex'),sourceBytes:Buffer.byteLength(raw),
 fields:{asa:{product:'ASA',severity:'4',message_id:'106023',action:'Deny',protocol:'udp'}},
 spans:[
  {path:'asa.product',startByte:1,endByte:4},{path:'asa.severity',startByte:5,endByte:6},
  {path:'asa.message_id',startByte:7,endByte:13},{path:'asa.action',startByte:15,endByte:19},
  {path:'asa.protocol',startByte:20,endByte:23},
 ],residuals:[{startByte:15,endByte:75}],issues:[],nativeVerified:false,targetVerified:false,
};

test('touch selection opens exact extracted-field and residual AI correction scopes',async({page})=>{
 if(process.env.PARSER_STUDIO_LIVE_MULTIPASS!=='1'){
  await page.route('**/api/v1/multipass/preview',async route=>{
   const request=route.request();
   expect(request.method()).toBe('POST');
   expect(request.postDataJSON()).toEqual({raw});
   await route.fulfill({status:200,contentType:'application/json',body:JSON.stringify(response)});
  });
 }
 await page.goto('/');
 await page.getByLabel('Auto Parser raw logs').fill(raw);
 await page.getByRole('button',{name:'Analyze Logs'}).tap();
 await page.getByRole('button',{name:'Advanced'}).tap();
 const engine=page.getByLabel('Local Multi-Pass source engine');
 await expect(engine).toContainText('PARTIAL · CISCO_ASA_FTD_MESSAGE_ID');
 const field=page.getByRole('button',{name:'Correct extracted field asa.action bytes 15-19'});
 await field.tap();
 await expect(engine).toContainText('Selected extracted field: asa.action');
 await expect(engine).toContainText('Editing extracted field: asa.action');
 await page.getByRole('button',{name:'Improve Unparsed [15–75]'}).tap();
 await expect(engine).toContainText('Selected unparsed source region');
 await expect(engine).toContainText('Editing an unparsed source region');
 expect(await page.evaluate(()=>document.documentElement.scrollWidth)).toBeLessThanOrEqual(392);
});
