import {test,expect} from './support/downloadSink';

const fixtures=[
  {name:'Threat',raw:'{"event_type":"threat","src_ip":"192.0.2.10","action":"deny"}'},
  {name:'User',raw:'{"event_type":"user","username":"example-user","action":"login"}'},
  {name:'Asset',raw:'{"event_type":"asset","hostname":"example-host","action":"found"}'},
];

test('ChatGPT Assisted compiles one previously reviewed conditional parser for three independent types',async({page})=>{
  const unsupportedV02Posts:string[]=[];
  page.on('request',request=>{
    if(request.method()==='POST'&&request.url().includes('/recipe/v0.2/'))
      unsupportedV02Posts.push(request.url());
  });
  test.skip(process.env.PARSER_STUDIO_SCOPED_AUTHORING_E2E!=='1',
    'Requires isolated exact-HEAD backend and Multi-Pass source parsing.');
  await page.goto('/');
  await page.getByRole('button',{name:'Add Another Log Type'}).click();
  for(let i=0;i<2;i++){
    await page.getByLabel('Log type name '+(i+1)).fill(fixtures[i]!.name);
    await page.getByLabel('Log type sample '+(i+1)).fill(fixtures[i]!.raw);
  }
  await page.getByLabel('Named log type samples')
    .getByRole('button',{name:'Add Another Log Type'}).click();
  await page.getByLabel('Log type name 3').fill(fixtures[2]!.name);
  await page.getByLabel('Log type sample 3').fill(fixtures[2]!.raw);
  await page.getByRole('button',{name:'Analyze Logs',exact:true}).click();
  const next=page.getByLabel('Add Logs stage').getByRole('button',{name:'Review Fields',exact:true});
  await expect(next).toBeEnabled({timeout:15000});
  await next.click();
  const review=page.getByLabel('Review Fields stage');
  const router=review.getByLabel('Configure one parser for event types');
  if(!(await router.evaluate(el=>(el as HTMLDetailsElement).open)))await router.locator('summary').first().click();
  await expect(router.getByLabel('Proposed event type rules')).toContainText('3 reviewed types');
  await router.getByLabel('Approve explicit family routing changes').check();
  await router.getByRole('button',{name:'Apply reviewed event types to this parser'}).click();
  await expect(router.getByLabel('Configured event profiles')).toContainText('3 explicit event types');
  await page.getByRole('complementary',{name:'Parser Studio navigation'})
    .getByRole('button',{name:'ChatGPT Assisted Parser'}).click();
  for(let i=0;i<3;i++)
    await expect(page.getByLabel('Log type sample '+(i+1))).toHaveValue(fixtures[i]!.raw);
  await page.getByLabel('Parser manufacturer').fill('Example Vendor');
  await page.getByLabel('Parser product',{exact:true}).fill('Security Gateway');
  await page.getByLabel('Parser product version').fill('9.4');
  await expect(page.getByRole('button',{name:'Prepare ChatGPT Prompt'})).toBeDisabled();
  const combined=page.getByLabel('Combined parser routing review');
  await expect(combined.getByLabel('Approved conditional parser')).toContainText('3 explicitly reviewed event types');
  const generate=combined.getByRole('button',{name:'Validate & Generate One Multi-Type Parser'});
  await expect(generate).toBeEnabled({timeout:15000});
  await generate.click();
  await expect(combined.getByLabel('Combined parser downloads'))
    .toContainText('Two integrity-checked DRAFT files are available',{timeout:20000});
  expect(unsupportedV02Posts).toEqual([]);
  const downloadPromise=page.waitForEvent('download');
  await combined.getByLabel('Combined parser downloads')
    .getByRole('button',{name:'Download customized_example_vendor_security_gateway',exact:true}).click();
  const download=await downloadPromise;
  const chunks:Buffer[]=[];
  const stream=await download.createReadStream();
  for await(const part of stream)chunks.push(Buffer.from(part));
  const ruby=Buffer.concat(chunks).toString('utf8');
  const b64=/Base64.strict_decode64\('([^']+)'\)/.exec(ruby)?.[1];
  expect(b64).toBeTruthy();
  const compiled=JSON.parse(Buffer.from(b64!,'base64').toString('utf8'));
  expect(compiled.vendor).toBe('Example Vendor');
  expect(compiled.product).toBe('Security Gateway');
  expect(compiled.productVersion).toBe('9.4');
  expect(compiled.projectId).toBe('draft-example_vendor_security_gateway');
  expect(compiled.normalization.eventProfiles.variants.map((x:{name:string})=>x.name))
    .toEqual(['threat','user','asset']);
});
