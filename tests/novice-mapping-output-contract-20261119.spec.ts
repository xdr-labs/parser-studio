import {test,expect} from './support/downloadSink';
import {createHash} from 'node:crypto';

const source='{"client_hint":"sample-source","action":"allow"}';
const sha=(value:string)=>createHash('sha256').update(value).digest('hex');
const capability={
 contract:'host-customized-pair.v0.1',projectSchemaRevision:'0.1',
 authoring:{receiverProtocols:['udp','tcp'],extractionFormats:['json','kv','csv','syslog_rfc5424','cef','leef'],
  rfc5424BodyFormats:['raw','json','kv','cef','leef'],rfc5424AdjacentStructuredDataSubset:true,
  rfc5424StructuredDataMaxBytes:1024,leefHexSeparatorSubset:true,formatCoverage:'reviewed-bounded-subset',
  httpReceiver:false,multipleDistinctReceiverPorts:false,multiline:false,arbitraryRuby:false},
 import:{exactInternalPairsEditable:true,unknownLegacyRubyEditable:false,structuralInspectionOnly:true},
 verification:{engineVerified:false,targetImportVerified:false,liveListenerVerified:false,proprietaryLoaderVerified:false},
 downloads:{individualGeneratedFiles:true,zipWithManifest:true,requiresDpConnection:false,requiresApiKey:false,
  autoDeploys:false,exactArtifactRevision:true},limits:{maxProjectBodyBytes:262144,maxInspectBodyBytes:2097152},
};

test('novice keeps one source event through suggestions, blocked manual AI proposal, final preview and DRAFT pair',async({page})=>{
 const postRequests:Array<{origin:string;path:string}>=[];
 page.on('request',request=>{
  if(request.method()==='POST'){
   const url=new URL(request.url());postRequests.push({origin:url.origin,path:url.pathname});
  }
 });
 await page.route('**/api/v1/parser-pairs/capabilities',route=>route.fulfill({status:200,
  contentType:'application/json',body:JSON.stringify(capability)}));
 await page.route('**/api/v1/parser-pairs/validate',route=>route.fulfill({status:200,
  contentType:'application/json',body:JSON.stringify({ok:true,issues:[]})}));
 await page.route('**/api/v1/parser-pairs/generate',async route=>{
  const project=route.request().postDataJSON() as {slug:string};
  const ruby='# deterministic browser DRAFT Ruby\n',conf='# deterministic browser DRAFT CONF\n';
  const files=[{name:`customized_${project.slug}.conf`,content:conf,bytes:Buffer.byteLength(conf),sha256:sha(conf)},
   {name:`customized_${project.slug}`,content:ruby,bytes:Buffer.byteLength(ruby),sha256:sha(ruby)}];
  await route.fulfill({status:200,contentType:'application/json',body:JSON.stringify({
   contract:'host-customized-pair.v0.1',files,manifest:{status:'DRAFT',contract:'host-customized-pair.v0.1',
    schemaRevision:'0.1',projectId:project.slug,projectRevision:1,
    fileHashes:Object.fromEntries(files.map(file=>[file.name,file.sha256])),
    engineVerified:false,targetImportVerified:false,warnings:[]},
  })});
 });
 await page.goto('/');
 await page.getByLabel('Auto Parser raw logs').fill(source);
 await expect(page.getByLabel('Automatic event accounting')).toContainText('1/1 events analyzed locally');
 await page.getByRole('button',{name:'Analyze Logs',exact:true}).click();
 await page.getByRole('button',{name:'Review Fields',exact:true}).click();
 const review=page.getByLabel('Review Fields stage');
 await review.getByRole('button',{name:'Map Fields',exact:true}).click();
 const map=page.getByLabel('Map Fields stage');
 await expect(map.getByLabel('Recommended field matches')).toBeVisible();
 await expect(map.getByRole('region',{name:'Source fields'})).toContainText('sample-source');
 await map.getByLabel('Search source fields').fill('client_hint');
 await map.getByRole('button',{name:'client_hint',exact:true}).click();
 const mapped=map.locator('[data-source-path="client_hint"]');
 await expect(mapped).toBeVisible();
 await expect(mapped.getByRole('combobox',{name:/Stellar field/})).toHaveValue('client_hint');
 await mapped.getByRole('combobox',{name:/Stellar field/}).fill('client_hint_reviewed');
 await expect(map.getByLabel('Final event preview')).toContainText('client_hint_reviewed');
 await expect(map.getByLabel('Final event preview')).toContainText('sample-source');
 await expect(map.getByRole('region',{name:'Source fields'})).toContainText('EMITTED IN BROWSER PREVIEW');
 await map.getByRole('button',{name:'Improve mappings with ChatGPT JSONata'}).click();
 await map.getByRole('button',{name:'Prepare Mapping Prompt'}).click();
 const prompt=await map.getByLabel('ChatGPT JSONata mapping prompt').inputValue();
 const fingerprint=prompt.match(/"sha256"\s*:\s*"([a-f0-9]{64})"/)?.[1];
 expect(fingerprint).toBeTruthy();
 await map.getByLabel('Paste ChatGPT JSONata mapping response').fill(JSON.stringify({
  contract:'parser-studio.mapping-jsonata.v0.1',sample:{sha256:fingerprint,events:1},
  mappings:[{expression:'client_hint',target:'srcip'}],
 }));
 await map.getByRole('button',{name:'Check JSONata Mappings'}).click();
 await expect(map.getByLabel('Reviewed ChatGPT JSONata mappings')).toContainText('BLOCKED');
 await expect(map.getByLabel('Final event preview')).toContainText('sample-source');
 await expect(map.getByRole('button',{name:'Create Parser'})).toBeEnabled();
 await map.getByRole('button',{name:'Create Parser'}).click();
 await expect(page.getByLabel('Create Parser stage')).toBeVisible();
 await page.getByRole('button',{name:'Create Parser Files'}).click();
 const created=page.getByLabel('Generated parser files');
 await expect(created).toBeVisible();
 await expect(created).toContainText('DRAFT files were generated');
 await expect(created.getByRole('button')).toHaveCount(3);
 await expect(created.getByRole('button').filter({hasText:'.conf'})).toHaveCount(1);
 await expect(created.getByRole('button').filter({hasText:/customized_/})).toHaveCount(2);
 expect(postRequests.every(request=>request.origin===new URL(page.url()).origin)).toBe(true);
 expect(postRequests.map(request=>request.path)).toEqual(expect.arrayContaining([
  '/api/v1/parser-pairs/validate','/api/v1/parser-pairs/generate',
 ]));
 expect(postRequests.every(request=>[
  '/api/v1/multipass/preview','/api/v1/multipass/preview-batch',
  '/api/v1/parser-pairs/validate','/api/v1/parser-pairs/generate',
  '/api/v1/parser-pairs/recipe/v0.2/validate','/api/v1/parser-pairs/recipe/v0.2/generate',
 ].includes(request.path))).toBe(true);
});
