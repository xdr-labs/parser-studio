import {test,expect} from '@playwright/test';
import {createHash} from 'node:crypto';

test('Multi-Pass shows value-free exact Dictionary guidance without auto-applying mappings',async({page})=>{
 const raw='srcip=192.0.2.10 dstport=443 action=deny custom=PRIVATE_VALUE';
 const bytes=new TextEncoder();
 const start=(token:string)=>bytes.encode(raw.slice(0,raw.indexOf(token))).length;
 const span=(path:string,token:string)=>({path,startByte:start(token),endByte:start(token)+bytes.encode(token).length});
 const spans=[
  span('srcip','192.0.2.10'),span('dstport','443'),span('action','deny'),span('custom','PRIVATE_VALUE'),
 ];
 await page.route('**/api/v1/parser-pairs/capabilities',route=>
  route.fulfill({status:404,contentType:'application/json',body:'{}'}));
 await page.route('**/api/v1/multipass/preview',route=>route.fulfill({
  status:200,contentType:'application/json',body:JSON.stringify({
   contract:'parser-studio.multipass-source-preview.v0.1',status:'SOURCE_PARSED',syntax:'KV',
   sourceSha256:createHash('sha256').update(raw).digest('hex'),sourceBytes:bytes.encode(raw).length,
   fields:{srcip:'192.0.2.10',dstport:'443',action:'deny',custom:'PRIVATE_VALUE'},
   spans,residuals:[],issues:[],
   dictionary:{
    contract:'parser-studio.stellar-dictionary-projection.v0.1',
    dictionaryRevision:'stellar-standard-metadata-7.0.xs-2026-10-14',
    sourceUrls:[
     'https://docs.stellarcyber.ai/prod-docs/6.5.xs/Common/Metadata-Dictionary.htm?TocPath=REFERENCE%7C_____8',
     'https://docs.stellarcyber.ai/7.0.xs/Common/Metadata-Dictionary.htm',
     'https://community.opentext.com/cfs-filesystemfile/__key/communityserver-discussions-components-files/224/3731.CommonEventFormatV25.pdf',
    ],
    mapped:[
     {...spans[0],sourcePath:'srcip',targetField:'srcip',documentedType:'ip',mappingClass:'EXACT_DICTIONARY_NAME'},
     {...spans[1],sourcePath:'dstport',targetField:'dstport',documentedType:'integer',mappingClass:'EXACT_DICTIONARY_NAME'},
     {...spans[2],sourcePath:'action',targetField:'action',documentedType:'string',mappingClass:'EXACT_DICTIONARY_NAME'},
    ].map(({path:_,...item})=>item),
    unmappedCount:1,issues:[],automaticAliasInference:false,standardizedAliasMapping:true,sourceExtractionPreserved:true,
    nativeVerified:false,targetVerified:false,
   },nativeVerified:false,targetVerified:false,
  }),
 }));
 await page.goto('/');
 await page.getByLabel('Auto Parser raw logs').fill(raw);
 await page.getByRole('button',{name:'Run Local Multi-Pass Source Preview'}).click();
 const review=page.getByLabel('Stellar Dictionary normalization suggestions');
 await expect(review).toContainText('3 mapped · 1 preserved unmapped');
 await expect(review).toContainText('srcip → srcip');
 await expect(review).toContainText('dstport → dstport');
 await expect(review).toContainText('action → action');
 await expect(review).toContainText('No source values are copied into this metadata');
 await expect(review).toContainText('stellar-standard-metadata-7.0.xs-2026-10-14');
 await expect(review).toContainText('Native parser and Stellar target NOT VERIFIED');
 await expect(review).not.toContainText('192.0.2.10');
 await expect(review).not.toContainText('PRIVATE_VALUE');
 await expect(page.getByLabel('Local Multi-Pass source engine')).toContainText('PRIVATE_VALUE');
});
