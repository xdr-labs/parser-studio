import {test,expect,type BrowserContext,type Page} from '@playwright/test';
import {createHash} from 'node:crypto';

// This is a two-ISOLATED-BROWSER-PROFILE synthetic acceptance test, not a claim
// that two independent humans have granted product or production acceptance.
// No credentials, user-origin logs, live DP, sensors, or external AI are used.
const threat='{"event_type":"threat","src_ip":"192.0.2.81","action":"deny","message":"테스트 차단"}';
const user='{"event_type":"user","username":"김민수","action":"login"}';
const asset='{"event_type":"asset","hostname":"fw01","action":"found"}';
const assistedSource='allow,198.51.100.81\ndeny,203.0.113.82';
const assistedHoldout='allow,192.0.2.31\ndeny,192.0.2.32';

const proposal=()=>({
  contract:'parser-studio.recipe.v0.2',schemaRevision:'0.2',compilerMode:'REVIEW_ONLY',
  projectId:'draft-demo_firewall',sourceFormat:'csv',bodyFormat:'csv',
  sample:{sha256:createHash('sha256').update(assistedSource).digest('hex'),events:2},
  stages:[
    {op:'split_event',boundary:'single-line'},
    {op:'parse_csv',columns:['action','src_ip'],delimiter:','},
    {op:'map_field',source:'action',target:'custom.action',data_type:'string',group:'top_fields'},
    {op:'map_field',source:'src_ip',target:'custom.source_ip',data_type:'ip',group:'top_fields'},
    {op:'cast_type',target:'custom.source_ip',data_type:'ip'},
    {op:'classify',defaultIndex:'syslog',rules:[]},
    {op:'fallback_unparsed',mode:'retain_unparsed'},
  ],
  nativeVerified:false,targetVerified:false,
});

function watchUnexpectedFailures(page:Page){
  const browserErrors:string[]=[];
  const serverFailures:string[]=[];
  const offOriginRequests:string[]=[];
  const expectedOrigin=new URL(test.info().project.use.baseURL!).origin;
  page.on('pageerror',error=>browserErrors.push(error.message));
  page.on('response',response=>{
    if(response.url().startsWith(expectedOrigin+'/api/')&&response.status()>=500)
      serverFailures.push(String(response.status()));
  });
  page.on('request',request=>{
    if(!request.url().startsWith('http:')&&!request.url().startsWith('https:'))return;
    if(new URL(request.url()).origin!==expectedOrigin)
      offOriginRequests.push(new URL(request.url()).origin);
  });
  return {browserErrors,serverFailures,offOriginRequests};
}

async function downloadText(page:Page,name:RegExp){
  const downloadPromise=page.waitForEvent('download');
  await page.getByRole('button',{name}).click();
  const download=await downloadPromise;
  const chunks:Buffer[]=[];
  const stream=await download.createReadStream();
  for await(const part of stream)chunks.push(Buffer.from(part));
  return {filename:download.suggestedFilename(),contents:Buffer.concat(chunks).toString('utf8')};
}

async function namedUserJourney(page:Page){
  await page.getByRole('button',{name:'Add Another Log Type'}).click();
  await page.getByLabel('Log type name 1').fill('Threat');
  await page.getByLabel('Log type sample 1').fill(threat);
  await page.getByLabel('Log type name 2').fill('User');
  await page.getByLabel('Log type sample 2').fill(user);
  await page.getByLabel('Named log type samples')
    .getByRole('button',{name:'Add Another Log Type'}).click();
  await page.getByLabel('Log type name 3').fill('Asset');
  await page.getByLabel('Log type sample 3').fill(asset);
  await page.getByRole('button',{name:'Local Versions',exact:true}).click();
  const history=page.getByLabel('Local Versions workspace');
  await history.getByLabel('Local version name').fill('Profile A private version');
  const writePaths:string[]=[];
  page.on('request',request=>{
    if(request.url().includes('/api/')&&request.method()!=='GET')
      writePaths.push(new URL(request.url()).pathname);
  });
  await history.getByRole('button',{name:'Save Version'}).click();
  await expect(history.getByLabel('Saved local versions')).toContainText('Profile A private version');
  expect(writePaths).toEqual([]);
  await page.getByRole('button',{name:'Analyze Logs',exact:true}).click();
  await expect(page.getByLabel('Named log type samples')).toContainText('Threat: 1 event · 1 parsed');
  await expect(page.getByLabel('Named log type samples')).toContainText('User: 1 event · 1 parsed');
  await expect(page.getByLabel('Named log type samples')).toContainText('Asset: 1 event · 1 parsed');
  const reviewButton=page.getByLabel('Add Logs stage')
    .getByRole('button',{name:'Review Fields',exact:true});
  await expect(reviewButton).toBeEnabled();
  await reviewButton.click();
  const review=page.getByLabel('Review Fields stage');
  const router=review.getByLabel('Configure one parser for event types');
  if(!(await router.evaluate(e=>(e as HTMLDetailsElement).open)))
    await router.locator('summary').first().click();
  await expect(router.getByLabel('Proposed event type rules')).toContainText('3 reviewed types');
  await router.getByLabel('Approve explicit family routing changes').check();
  await router.getByRole('button',{name:'Apply reviewed event types to this parser'}).click();
  await expect(router.getByLabel('Configured event profiles')).toContainText('3 explicit event types');
  await review.getByRole('button',{name:'Map Fields'}).click();
  await expect(page.getByLabel('Map Fields stage')).toBeVisible();
  await page.getByLabel('Map Fields stage').getByRole('button',{name:'Create Parser'}).click();
  await page.getByLabel('Create Parser Files').click();
  const files=page.getByLabel('Generated parser files');
  await expect(files).toContainText('Parser files created successfully',{timeout:25000});
  await expect(files).toContainText('The files have not been installed in a live Stellar system.');
  const downloaded=await downloadText(page,/customized_demo_firewall$/);
  expect(downloaded.filename).toBe('customized_demo_firewall');
  const base64=/Base64.strict_decode64\('([^']+)'\)/.exec(downloaded.contents)?.[1];
  expect(base64).toBeTruthy();
  const project=JSON.parse(Buffer.from(base64!,'base64').toString('utf8'));
  expect(project.normalization.eventProfiles.variants.map((item:{name:string})=>item.name))
    .toEqual(['threat','user','asset']);
  expect(downloaded.contents).not.toContain('김민수');
  expect(downloaded.contents).not.toContain('198.51.100.81');
  return {workflow:'named-3-type',downloaded:downloaded.filename,eventTypes:3};
}

async function assistedUserJourney(page:Page){
  await page.getByLabel('ChatGPT local sample logs').fill(assistedSource);
  await page.getByLabel('ChatGPT redacted examples').fill('allow,REDACTED_IP\ndeny,REDACTED_IP');
  await page.getByRole('button',{name:'Prepare ChatGPT Prompt'}).click();
  await expect(page.getByLabel('ChatGPT copyable prompt')).toContainText('FULL_RECOVERY');
  await page.getByLabel('ChatGPT result JSON').fill(JSON.stringify(proposal()));
  await page.getByRole('button',{name:'Check ChatGPT Result'}).click();
  await expect(page.getByLabel('ChatGPT result ready for testing'))
    .toContainText('ChatGPT result accepted for testing');
  await page.getByLabel('Additional ChatGPT test logs').fill(assistedHoldout);
  await page.getByLabel('Confirm test examples are different').check();
  await page.getByRole('button',{name:'Test Proposed Fix'}).click();
  await expect(page.getByLabel('ChatGPT fix test result')).toContainText('Overall test: PASS');
  await page.getByLabel('Approve tested ChatGPT fix').check();
  await page.getByRole('button',{name:'Apply Fix & Create Parser Files'}).click();
  const files=page.getByLabel('ChatGPT created parser files');
  await expect(files).toContainText('Parser files created successfully',{timeout:25000});
  const downloaded=await downloadText(page,/^Download customized_demo_firewall\.conf$/);
  expect(downloaded.filename).toBe('customized_demo_firewall.conf');
  expect(downloaded.contents).not.toContain('192.0.2.81');
  await files.getByRole('button',{name:'Review Fields in Auto Parser'}).click();
  await expect(page.getByLabel('Auto Parser raw logs')).toHaveValue(assistedSource);
  return {workflow:'chatgpt-reviewed-recovery',downloaded:downloaded.filename};
}

test('two independent browser profiles complete distinct public beta drafts with no version crossing',
  async({browser})=>{
    test.skip(process.env.PARSER_STUDIO_SCOPED_AUTHORING_E2E!=='1',
      'Requires real HTTP and approved current offline authoring backend.');
    test.setTimeout(120_000);
    const baseURL=test.info().project.use.baseURL;
    if(typeof baseURL!=='string')throw new Error('Two-profile test requires one exact origin');
    const userA:BrowserContext=await browser.newContext({baseURL,acceptDownloads:true});
    const userB:BrowserContext=await browser.newContext({baseURL,acceptDownloads:true});
    try{
      const a=await userA.newPage();
      const b=await userB.newPage();
      const failuresA=watchUnexpectedFailures(a);
      const failuresB=watchUnexpectedFailures(b);
      await Promise.all([
        a.goto('/'),
        b.goto('/'),
      ]);
      await expect(a.getByRole('heading',{name:/Paste security logs/})).toBeVisible();
      await expect(b.getByRole('heading',{name:/Paste security logs/})).toBeVisible();

      // User A saves a version. User B must not inherit that browser's IndexedDB.
      await a.getByLabel('Auto Parser raw logs').fill(threat);
      await a.getByRole('button',{name:'Local Versions',exact:true}).click();
      const aHistory=a.getByLabel('Local Versions workspace');
      await aHistory.getByLabel('Local version name').fill('Profile A preflight');
      await aHistory.getByRole('button',{name:'Save Version'}).click();
      await expect(aHistory.getByLabel('Saved local versions')).toContainText('Profile A preflight');
      await b.getByRole('button',{name:'Local Versions',exact:true}).click();
      await expect(b.getByLabel('Saved local versions')).toContainText('No versions saved yet');
      await expect(b.getByLabel('Saved local versions')).not.toContainText('Profile A preflight');
      await Promise.all([a.goto('/'),b.goto('/?workspace=chatgpt')]);

      // Two separate browser users intentionally operate the SAME public backend.
      const [aResult,bResult]=await Promise.all([
        namedUserJourney(a),
        assistedUserJourney(b),
      ]);

      await b.getByRole('button',{name:'Local Versions',exact:true}).click();
      const bHistory=b.getByLabel('Local Versions workspace');
      await expect(bHistory.getByLabel('Saved local versions')).toContainText('No versions saved yet');
      await bHistory.getByLabel('Local version name').fill('Profile B private version');
      await bHistory.getByRole('button',{name:'Save Version'}).click();
      await expect(bHistory.getByLabel('Saved local versions')).toContainText('Profile B private version');

      // Reload both physical browser profiles: no shared history, draft, or raw text.
      await Promise.all([a.reload(),b.reload()]);
      await Promise.all([
        a.getByRole('button',{name:'Local Versions',exact:true}).click(),
        b.getByRole('button',{name:'Local Versions',exact:true}).click(),
      ]);
      await expect(a.getByLabel('Saved local versions')).toContainText('Profile A private version');
      await expect(a.getByLabel('Saved local versions')).toContainText('Profile A preflight');
      await expect(a.getByLabel('Saved local versions')).not.toContainText('Profile B private version');
      await expect(b.getByLabel('Saved local versions')).toContainText('Profile B private version');
      await expect(b.getByLabel('Saved local versions')).not.toContainText('Profile A private version');

      a.on('dialog',dialog=>dialog.accept());
      b.on('dialog',dialog=>dialog.accept());
      await a.getByText('Profile A private version',{exact:true}).locator('..').locator('..')
        .getByRole('button',{name:'Restore'}).click();
      await expect(a.getByLabel('Log type sample 2')).toHaveValue(user);
      await expect(a.getByLabel('Log type sample 3')).toHaveValue(asset);
      await b.getByText('Profile B private version',{exact:true}).locator('..').locator('..')
        .getByRole('button',{name:'Restore'}).click();
      await expect(b.getByLabel('Auto Parser raw logs')).toHaveValue(assistedSource);
      for(const result of [failuresA,failuresB]){
        expect(result.browserErrors).toEqual([]);
        expect(result.serverFailures).toEqual([]);
        expect(result.offOriginRequests).toEqual([]);
      }
      await test.info().attach('two-isolated-browser-profile-beta-evidence',{
        contentType:'application/json',
        body:JSON.stringify({
          contract:'parser-studio.two-synthetic-browser-profiles.v1',
          host:new URL(test.info().project.use.baseURL!).origin,
          profiles:2,sharedHttpBackend:true,mockedResponses:false,
          profileA:aResult,profileB:bResult,
          versionIsolation:'BROWSER_ONLY',
          nativeTargetVerified:false,twoHumanOwnerAcceptance:false,
        },null,2),
      });
    }finally{
      await userA.close();
      await userB.close();
    }
  });
