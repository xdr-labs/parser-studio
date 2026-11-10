import {test,expect} from './support/downloadSink';

const source='{"timestamp":"2026-10-26T00:00:00Z","action":"deny","src_ip":"192.0.2.10"}';

test('Auto Parser metadata is the sole shared source for ChatGPT prompt and CONF port',async({page})=>{
  const pageErrors:string[]=[];
  const outsideRequests:string[]=[];
  page.on('pageerror',error=>pageErrors.push(error.message));
  await page.goto('/');
  const origin=new URL(page.url()).origin;
  page.on('request',request=>{
    if(/^https?:/.test(request.url())&&new URL(request.url()).origin!==origin)
      outsideRequests.push(request.url());
  });
  const auto=page.getByRole('main',{name:'Auto Parser v2'});
  await auto.getByRole('textbox',{name:'Parser manufacturer'}).fill('Fortinet');
  await auto.getByRole('textbox',{name:'Parser product',exact:true}).fill('FortiGate');
  await auto.getByRole('textbox',{name:'Parser product version'}).fill('7.4.5');
  await auto.getByRole('spinbutton',{name:'Parser listener port'}).fill('6819');
  await auto.getByLabel('Auto Parser raw logs').fill(source);
  await expect(auto).toContainText('customized_fortinet_fortigate.conf');
  await expect(auto).toContainText('Generated .conf receiving port: 6819');

  await page.getByRole('button',{name:'ChatGPT Assisted Parser',exact:true}).click();
  const assisted=page.getByRole('main',{name:'ChatGPT Assisted Parser'});
  const identity=assisted.getByLabel('Parser product identity');
  await expect(identity.getByRole('textbox',{name:'Parser manufacturer'})).toHaveValue('Fortinet');
  await expect(identity.getByRole('textbox',{name:'Parser product',exact:true})).toHaveValue('FortiGate');
  await expect(identity.getByRole('textbox',{name:'Parser product version'})).toHaveValue('7.4.5');
  await expect(identity.getByRole('spinbutton',{name:'Parser listener port'})).toHaveValue('6819');
  await expect(identity).toContainText('customized_fortinet_fortigate.conf');
  await expect(assisted.getByLabel('ChatGPT log source or delivery')).toHaveCount(0);
  await expect(assisted.getByLabel('ChatGPT local sample logs')).toHaveValue(source);

  const prepare=assisted.getByRole('button',{name:'Prepare ChatGPT Prompt'});
  await expect(prepare).toBeEnabled({timeout:20000});
  await prepare.click();
  const prompt=assisted.getByLabel('ChatGPT copyable prompt');
  await expect(prompt).toBeVisible({timeout:20000});
  await expect(prompt).toContainText('Fortinet');
  const promptText=await prompt.inputValue();
  expect(promptText).toContain('"vendor":"Fortinet","product":"FortiGate","versionOrModel":"7.4.5","logDelivery":""');
  expect(promptText).toContain(source);
  expect(promptText).not.toContain('"logDelivery":"Syslog');
  await identity.getByRole('textbox',{name:'Parser product',exact:true}).fill('FortiGate NGFW');
  await expect(prompt).toHaveCount(0);
  await page.getByRole('button',{name:'Auto Parser',exact:true}).click();
  await expect(auto.getByRole('textbox',{name:'Parser product',exact:true})).toHaveValue('FortiGate NGFW');
  await expect(auto.getByRole('spinbutton',{name:'Parser listener port'})).toHaveValue('6819');
  await expect(auto).toContainText('customized_fortinet_fortigate_ngfw.conf');
  expect(pageErrors).toEqual([]);
  expect(outsideRequests).toEqual([]);
});

test('untouched demo metadata is not asserted to be real manufacturer evidence in the AI prompt',async({page})=>{
  await page.goto('/?workspace=chatgpt');
  const identity=page.getByLabel('Parser product identity');
  await expect(identity.getByRole('textbox',{name:'Parser manufacturer'})).toHaveValue('Demo Local Draft');
  await expect(identity.getByRole('textbox',{name:'Parser product',exact:true})).toHaveValue('Untitled parser');
  await expect(identity.getByRole('textbox',{name:'Parser product version'})).toHaveValue('1.0.0');
  await expect(identity.getByRole('spinbutton',{name:'Parser listener port'})).toHaveValue('6801');
  await page.getByLabel('ChatGPT local sample logs').fill(source);
  const prepare=page.getByRole('button',{name:'Prepare ChatGPT Prompt'});
  await expect(prepare).toBeEnabled({timeout:20000});
  await prepare.click();
  const prompt=await page.getByLabel('ChatGPT copyable prompt').inputValue();
  expect(prompt).toContain('"vendor":"","product":"","versionOrModel":"","logDelivery":""');
});

test('ChatGPT DRAFT native files retain the shared manufacturer, product, version and listener port',async({page})=>{
  test.skip(process.env.PARSER_STUDIO_SCOPED_AUTHORING_E2E!=='1',
    'Requires the explicitly selected local authoring backend and Multi-Pass server.');
  const sample='allow,198.51.100.10\ndeny,203.0.113.4';
  const holdout='allow,192.0.2.10\ndeny,192.0.2.11';
  await page.goto('/?workspace=chatgpt');
  await page.getByRole('textbox',{name:'Parser manufacturer'}).fill('Fortinet');
  await page.getByRole('textbox',{name:'Parser product',exact:true}).fill('FortiGate');
  await page.getByRole('textbox',{name:'Parser product version'}).fill('7.4.5');
  await page.getByRole('spinbutton',{name:'Parser listener port'}).fill('6819');
  await page.getByLabel('ChatGPT local sample logs').fill(sample);
  const prepare=page.getByRole('button',{name:'Prepare ChatGPT Prompt'});
  await expect(prepare).toBeEnabled({timeout:20000});
  await prepare.click();
  const prompt=await page.getByLabel('ChatGPT copyable prompt').inputValue();
  const projectId=prompt.match(/"projectId":"([^"]+)"/)?.[1];
  const sourceHash=prompt.match(/"sourceHash":"([a-f0-9]{64})"/)?.[1];
  expect(projectId).toBeTruthy();
  expect(sourceHash).toBeTruthy();
  const recipe={
    contract:'parser-studio.recipe.v0.2',schemaRevision:'0.2',compilerMode:'REVIEW_ONLY',
    projectId,sourceFormat:'csv',bodyFormat:'csv',sample:{sha256:sourceHash,events:2},
    stages:[
      {op:'split_event',boundary:'single-line'},
      {op:'parse_csv',columns:['action','src_ip'],delimiter:','},
      {op:'map_field',source:'action',target:'custom.action',data_type:'string',group:'top_fields'},
      {op:'map_field',source:'src_ip',target:'custom.source_ip',data_type:'ip',group:'top_fields'},
      {op:'cast_type',target:'custom.source_ip',data_type:'ip'},
      {op:'classify',defaultIndex:'syslog',rules:[]},
      {op:'fallback_unparsed',mode:'retain_unparsed'},
    ],nativeVerified:false,targetVerified:false,
  };
  await page.getByLabel('ChatGPT result JSON').fill(JSON.stringify(recipe));
  await page.getByRole('button',{name:'Check ChatGPT Result'}).click();
  await expect(page.getByLabel('ChatGPT result ready for testing')).toBeVisible({timeout:25000});
  await page.getByLabel('Additional ChatGPT test logs').fill(holdout);
  await page.getByLabel('Confirm test examples are different').check();
  await page.getByRole('button',{name:'Test Proposed Fix'}).click();
  await expect(page.getByLabel('ChatGPT fix test result')).toContainText('Overall test: PASS',{timeout:25000});
  await page.getByLabel('Approve tested ChatGPT fix').check();
  const generate=page.waitForRequest(request=>
    request.url().endsWith('/parser-pairs/generate')&&request.method()==='POST');
  await page.getByRole('button',{name:'Apply Fix & Create Parser Files'}).click();
  const request=await generate;
  expect(request.postDataJSON()).toMatchObject({
    vendor:'Fortinet',product:'FortiGate',productVersion:'7.4.5',receiver:{port:6819},
  });
  const files=page.getByLabel('ChatGPT created parser files');
  await expect(files).toContainText('Parser files created successfully',{timeout:25000});
  const button=files.getByRole('button',{name:'Download customized_fortinet_fortigate.conf'});
  await expect(button).toBeVisible();
  const downloadWait=page.waitForEvent('download');
  await button.click();
  const download=await downloadWait;
  expect(download.suggestedFilename()).toBe('customized_fortinet_fortigate.conf');
  const {readFile}=await import('node:fs/promises');
  const conf=await readFile(await download.path(),'utf8');
  expect(conf).toMatch(/^\s+port 6819$/m);
  await files.getByRole('button',{name:'Review Fields in Auto Parser'}).click();
  await expect(page.getByRole('textbox',{name:'Parser manufacturer'})).toHaveValue('Fortinet');
  await expect(page.getByRole('textbox',{name:'Parser product',exact:true})).toHaveValue('FortiGate');
  await expect(page.getByRole('textbox',{name:'Parser product version'})).toHaveValue('7.4.5');
  await expect(page.getByRole('spinbutton',{name:'Parser listener port'})).toHaveValue('6819');
});

test('mobile ChatGPT metadata exposes the same four controls without horizontal overflow',async({page})=>{
  await page.setViewportSize({width:390,height:844});
  await page.goto('/?workspace=chatgpt');
  const identity=page.getByLabel('Parser product identity');
  await expect(identity.getByRole('textbox',{name:'Parser manufacturer'})).toBeVisible();
  await expect(identity.getByRole('textbox',{name:'Parser product',exact:true})).toBeVisible();
  await expect(identity.getByRole('textbox',{name:'Parser product version'})).toBeVisible();
  await expect(identity.getByRole('spinbutton',{name:'Parser listener port'})).toBeVisible();
  const width=await page.evaluate(()=>({
    viewport:document.documentElement.clientWidth,
    content:document.documentElement.scrollWidth,
  }));
  expect(width.content).toBeLessThanOrEqual(width.viewport+2);
});
