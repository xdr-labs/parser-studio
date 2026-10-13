import {test,expect,type Page} from '@playwright/test';
import {createHash} from 'node:crypto';

const input=[
  '{"action":"allow","src_ip":"198.51.100.10","dst_port":443}',
  '{"action":"deny","src_ip":"203.0.113.5","dst_port":22}',
].join('\n');
const sha=(text:string)=>createHash('sha256').update(text).digest('hex');
const ruby='# synthetic test Ruby fragment\n';
const conf='# synthetic test CONF for port 7501\n';
const files=[{name:'customized_demo_firewall.conf',content:conf,bytes:Buffer.byteLength(conf),sha256:sha(conf)},
{name:'customized_demo_firewall',content:ruby,bytes:Buffer.byteLength(ruby),sha256:sha(ruby)}];
const cap={
  contract:'host-customized-pair.v0.1',projectSchemaRevision:'0.1',
  authoring:{receiverProtocols:['udp','tcp'],extractionFormats:['json','kv','csv','syslog_rfc5424','cef','leef'],
    rfc5424BodyFormats:['raw','json','kv','cef','leef'],rfc5424AdjacentStructuredDataSubset:true,
    rfc5424StructuredDataMaxBytes:1024,leefHexSeparatorSubset:true,
    formatCoverage:'reviewed-bounded-subset',httpReceiver:false,multipleDistinctReceiverPorts:false,
    multiline:false,arbitraryRuby:false},
  import:{exactInternalPairsEditable:true,unknownLegacyRubyEditable:false,structuralInspectionOnly:true},
  verification:{engineVerified:false,targetImportVerified:false,liveListenerVerified:false,proprietaryLoaderVerified:false},
  downloads:{individualGeneratedFiles:true,zipWithManifest:true,requiresDpConnection:false,
    requiresApiKey:false,autoDeploys:false,exactArtifactRevision:true},
  limits:{maxProjectBodyBytes:262144,maxInspectBodyBytes:2097152},
};
const generated={contract:'host-customized-pair.v0.1',files,manifest:{
  contract:'host-customized-pair.v0.1',schemaRevision:'0.1',status:'DRAFT',
  engineVerified:false,targetImportVerified:false,
  projectId:'draft-demo_firewall',projectRevision:1,
  fileHashes:Object.fromEntries(files.map(f=>[f.name,f.sha256])),warnings:[],
}};
async function mockBackend(page:Page){
 let posts=0;
 await page.route('**/api/v1/parser-pairs/**',route=>{
   const req=route.request(),path=new URL(req.url()).pathname;
   if(path.endsWith('/capabilities'))
     return route.fulfill({status:200,contentType:'application/json',body:JSON.stringify(cap)});
   if(path.endsWith('/schema')){
     // This negative fixture intentionally prevents false schema PASS.
     return route.fulfill({status:503,contentType:'application/json',body:JSON.stringify({error:'SCHEMA_UNAVAILABLE'})});
   }
   if(path.endsWith('/validate')||path.endsWith('/generate')){
     posts++;
     const body=JSON.stringify(req.postDataJSON());
     expect(body).not.toContain('198.51.100.10');
     expect(body).not.toContain('203.0.113.5');
     expect(body).not.toContain('apiKey');
     if(path.endsWith('/validate'))return route.fulfill({status:200,contentType:'application/json',
       body:JSON.stringify({ok:true,issues:[]})});
     return route.fulfill({status:200,contentType:'application/json',body:JSON.stringify(generated)});
   }
   throw Error('Unexpected private/API invocation: '+path);
 });
 return ()=>posts;
}
async function begin(page:Page){
 await page.goto('/');
 await page.getByLabel('Auto Parser raw logs').fill(input);
 await expect(page.getByLabel('Automatic event accounting')).toContainText('2/2 events analyzed locally');
 await page.getByRole('button',{name:'Review Detected Results'}).click();
 await expect(page.getByLabel('Review Results stage')).toBeVisible();
}
test('new visitor sees only the two supported creation methods and a three-step Auto Parser',async({page})=>{
 await page.goto('/');
 await expect(page.getByRole('main',{name:'Auto Parser v2'})).toBeVisible();
 await expect(page.getByRole('heading',{name:'From raw logs to a parser draft in three steps.'})).toBeVisible();
 await expect(page.getByRole('navigation',{name:'Auto Parser steps'}).getByRole('button')).toHaveCount(3);
 await expect(page.getByRole('complementary',{name:'Parser creation methods'}).getByRole('button')).toHaveCount(2);
 await expect(page.getByLabel('Auto Parser raw logs')).toBeEmpty();
 await expect(page.getByRole('button',{name:'Review Detected Results'})).toBeDisabled();
 await expect(page.getByRole('main',{name:'No-code Parser Guided Builder'})).toHaveCount(0);
 await expect(page.getByRole('region',{name:'Parser pipeline rules'})).toHaveCount(0);
 await page.getByRole('button',{name:'ChatGPT Assisted Parser',exact:true}).click();
 await expect(page.getByRole('main',{name:'ChatGPT Assisted Parser'})).toBeVisible();
 await page.getByRole('button',{name:'Auto Parser',exact:true}).click();
 await expect(page.getByLabel('Add Logs stage')).toBeVisible();
});
test('novice reviews original/extracted/normalized samples, keeps source, and sees safe mapping provenance',async({page})=>{
 const posts=await mockBackend(page);
 await begin(page);
 await expect(page.getByLabel('Browser-only event inspector')).toContainText('198.51.100.10');
 await expect(page.getByLabel('Browser-only event inspector')).toContainText('custom.source_ip');
 await expect(page.getByLabel('Suggested field mappings')).toContainText('not official catalog');
 await page.getByLabel('Auto Parser review event').selectOption('event-2');
 await expect(page.getByLabel('Browser-only event inspector')).toContainText('203.0.113.5');
 await page.getByRole('button',{name:'Test & Generate',exact:false}).last().click();
 await expect(page.getByLabel('Test and Generate stage')).toBeVisible();
 await expect(page.getByRole('button',{name:'Run Tests & Generate DRAFT Files'})).toBeEnabled();
 await page.getByRole('button',{name:'Review Results'}).last().click();
 await page.getByRole('button',{name:'Back to Logs'}).click();
 await expect(page.getByLabel('Auto Parser raw logs')).toHaveValue(input);
 expect(posts()).toBe(0);
});
test('mixed families and unknown logs are not dropped or transmitted to validation',async({page})=>{
 const posts=await mockBackend(page);
 await page.goto('/');
 await page.getByLabel('Auto Parser raw logs').fill(input+'\naction=allow src_ip=192.0.2.10\nMALFORMED_SECRET');
 await expect(page.getByLabel('Automatic event accounting')).toContainText('4/4 events analyzed locally');
 await page.getByRole('button',{name:'Review Detected Results'}).click();
 await expect(page.getByLabel('Add Logs stage')).toBeVisible();
 await expect(page.getByRole('alert')).toContainText('unsupported family combination, malformed, or unrecognized');
 await expect(page.getByRole('navigation',{name:'Auto Parser steps'})
   .getByRole('button',{name:/Test & Generate/})).toBeDisabled();
 expect(posts()).toBe(0);
});
test('denied backend metadata blocks beginner compilation and does not exfiltrate samples',async({page})=>{
 await page.route('**/api/v1/parser-pairs/capabilities',route=>route.fulfill({status:403,
   contentType:'application/json',body:JSON.stringify({error:'CAPABILITY_DISABLED'})}));
 await page.goto('/');
 await page.getByLabel('Auto Parser raw logs').fill(input);
 await page.getByRole('button',{name:'Review Detected Results'}).click();
 await expect(page.getByRole('alert')).toContainText('backend capabilities are unavailable');
 await expect(page.getByLabel('Review Results stage')).toHaveCount(0);
 await expect(page.getByLabel('Auto Parser raw logs')).toHaveValue(input);
});
test('narrow viewport allows keyboard controls, avoids horizontal overflow, and never auto-sends source',async({page})=>{
 await page.setViewportSize({width:390,height:844});
 await mockBackend(page);
 await page.goto('/');
 await expect(page.getByLabel('Auto Parser raw logs')).toBeVisible();
 await page.getByLabel('Auto Parser raw logs').fill(input);
 await expect(page.getByLabel('Automatic event accounting')).toContainText('2/2');
 await expect(page.evaluate(()=>document.documentElement.scrollWidth)).resolves.toBeLessThanOrEqual(392);
 const review=page.getByRole('button',{name:'Review Detected Results'});
 await expect(review).toBeEnabled();
 await review.focus();
 await expect(review).toBeFocused();
 await page.keyboard.press('Enter');
 await expect(page.getByLabel('Review Results stage')).toBeVisible();
});
