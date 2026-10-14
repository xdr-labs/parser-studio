import {test,expect} from '@playwright/test';
import {createHash} from 'node:crypto';

test('Multi-Pass shows visible mask metadata without reconstructing or leaking hidden values',async({page})=>{
 const raw='src=REDACTED secret=*** custom=PRIVATE_VISIBLE';
 const bytes=new TextEncoder();
 const start=(token:string)=>bytes.encode(raw.slice(0,raw.indexOf(token))).length;
 const spans=[
  {path:'src',startByte:start('REDACTED'),endByte:start('REDACTED')+8},
  {path:'secret',startByte:start('***'),endByte:start('***')+3},
  {path:'custom',startByte:start('PRIVATE_VISIBLE'),endByte:start('PRIVATE_VISIBLE')+15},
 ];
 await page.route('**/api/v1/parser-pairs/capabilities',route=>
  route.fulfill({status:404,contentType:'application/json',body:'{}'}));
 await page.route('**/api/v1/multipass/preview',route=>route.fulfill({
  status:200,contentType:'application/json',body:JSON.stringify({
   contract:'parser-studio.multipass-source-preview.v0.1',status:'SOURCE_PARSED',syntax:'KV',
   sourceSha256:createHash('sha256').update(raw).digest('hex'),sourceBytes:bytes.encode(raw).length,
   fields:{src:'REDACTED',secret:'***',custom:'PRIVATE_VISIBLE'},spans,residuals:[],issues:[],
   redaction:{contract:'parser-studio.visible-redaction-assessment.v0.1',
    assessment:'EXPLICIT_VISIBLE_MASKS',sourceOccurrences:3,explicitMaskOccurrences:2,
    unassessedVisibleOccurrences:1,excludedEvent:false,occurrences:[
     {sourcePath:'src',occurrence:0,markerClass:'REDACTED_KEYWORD',startByte:spans[0].startByte,endByte:spans[0].endByte},
     {sourcePath:'secret',occurrence:0,markerClass:'ASTERISK_RUN',startByte:spans[1].startByte,endByte:spans[1].endByte},
    ],sourceExtractionPreserved:true,hiddenValueReconstruction:false},
   nativeVerified:false,targetVerified:false,
  }),
 }));
 await page.goto('/');
 await page.getByLabel('Auto Parser raw logs').fill(raw);
 await page.getByRole('button',{name:'Analyze Logs'}).click();
 await page.getByRole('button',{name:'Advanced'}).click();
 const review=page.getByLabel('Visible masking and redaction assessment');
 await expect(review).toContainText('2 explicit markers');
 await expect(review).toContainText('REDACTED KEYWORD');
 await expect(review).toContainText('ASTERISK RUN');
 await expect(review).toContainText('hidden content is never reconstructed');
 await expect(review).toContainText('Hidden-value reconstruction OFF');
 await expect(review).not.toContainText('PRIVATE_VISIBLE');
 await expect(page.getByLabel('Local Multi-Pass source engine')).toContainText('PRIVATE_VISIBLE');
});
