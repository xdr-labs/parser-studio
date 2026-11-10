import {test,expect,type Page} from './support/downloadSink';

async function openReviewedFlow(page:Page,reanalyze=true){
  const review=page.getByRole('button',{name:'Review Fields',exact:true});
  if(reanalyze||!await review.isEnabled()){
    await page.getByRole('button',{name:'Analyze Logs',exact:true}).click();
    await expect(page.getByLabel('Beginner analysis summary'))
      .toBeVisible({timeout:20000});
  }
  await expect(review).toBeEnabled({timeout:20000});
  await review.click();
  await expect(page.getByLabel('Review Fields stage')).toBeVisible();
}

const source=[
  '{"event_type":"threat","src_ip":"192.0.2.10","action":"deny"}',
  '{"event_type":"user","username":"김민수","action":"login"}',
  '{"event_type":"asset","hostname":"fw01","action":"found"}',
].join('\n');

test('one reviewed parser DRAFT retains all three event types with exact backend capability',async({page})=>{
  test.skip(process.env.PARSER_STUDIO_SCOPED_AUTHORING_E2E!=='1',
    'Runs separately against the current compiled offline backend exact Git HEAD.');
  await page.goto('/');
  const raw=page.getByLabel('Auto Parser raw logs');
  await raw.fill(source);
  await expect(page.getByLabel('Automatic event accounting'))
    .toContainText('3/3 events analyzed locally');

  await openReviewedFlow(page);
  const review=page.getByLabel('Review Fields stage');
  await expect(review).toBeVisible();
  const config=page.locator('details[aria-label="Configure one parser for event types"]');
  await config.locator('summary').first().click();
  await expect(config.getByLabel('Proposed event type rules')).toContainText('3 reviewed types');
  await expect(config.getByLabel('Proposed event type rules')).not.toContainText('김민수');
  const userFields=config.locator('details[aria-label="Type-specific mappings for user"]');
  await userFields.locator('summary').click();
  await userFields.getByLabel('user output for username').fill('custom.reviewed_user');
  await config.getByLabel('Approve explicit family routing changes').check();
  const apply=config.getByRole('button',{name:'Apply reviewed event types to this parser'});
  await expect(apply).toBeEnabled();
  await apply.click();
  await expect(config.getByLabel('Configured event profiles')).toContainText('3 explicit event types');
  await expect(review).toContainText('Save a Local Version');

  const inspector=page.getByLabel('Browser-only event inspector');
  await expect(inspector).toContainText('192.0.2.10');
  await page.getByLabel('Auto Parser review event').selectOption({index:1});
  await expect(inspector).toContainText('김민수');
  await page.getByLabel('Auto Parser review event').selectOption({index:2});
  await expect(inspector).toContainText('fw01');
  await page.getByLabel('Review Fields stage').getByRole('button',{name:'Map Fields'}).click();
  await expect(page.getByLabel('Map Fields stage')).toBeVisible();
  await page.getByLabel('Map Fields stage').getByRole('button',{name:'Create Parser'}).click();
  await expect(page.getByLabel('Create Parser stage')).toBeVisible();
  const create=page.getByLabel('Create Parser Files');
  await expect(create).toBeEnabled();
  await create.click();
  const files=page.getByLabel('Generated parser files');
  await expect(files).toBeVisible({timeout:25_000});
  await expect(files).toContainText('Parser files created successfully');
  await expect(files).toContainText('Native runtime and Stellar target verification are separate; nothing was deployed.');
  const parserDownload=page.waitForEvent('download');
  await files.getByRole('button',{name:/customized_demo_firewall$/}).click();
  const downloaded=await parserDownload;
  expect(downloaded.suggestedFilename()).toBe('customized_demo_firewall');
  const stream=await downloaded.createReadStream();
  const chunks:Buffer[]=[];
  for await(const item of stream)chunks.push(Buffer.from(item));
  const ruby=Buffer.concat(chunks).toString('utf8');
  const encoded=/Base64.strict_decode64\('([^']+)'\)/.exec(ruby)?.[1];
  expect(encoded).toBeTruthy();
  const project=JSON.parse(Buffer.from(encoded!,'base64').toString('utf8'));
  const user=project.normalization.eventProfiles.variants.find(
    (variant:{name:string})=>variant.name==='user');
  const userLocations=['topFields','nsFields','vendorFields']
    .map(group=>user[group]?.username).filter(Boolean);
  expect(userLocations).toHaveLength(1);
  expect(userLocations[0].normalized_name).toBe('custom.reviewed_user');
  expect(JSON.stringify(project)).not.toContain('김민수');
  await page.getByRole('button',{name:/Add Logs/}).first().click();
  await expect(raw).toHaveValue(source);
});

test('reviewed relay and three event types compile into the same downloaded Ruby pair',async({page})=>{
  test.skip(process.env.PARSER_STUDIO_SCOPED_AUTHORING_E2E!=='1',
    'Requires the current exact-HEAD offline conditional authoring backend.');
  const lines=[
    '<134>Jan 16 15:19:05 relay01 fw: {"event_type":"threat","src_ip":"192.0.2.10","action":"deny"}',
    '<134>Jan 16 15:19:06 relay01 fw: {"event_type":"user","username":"山田","action":"login"}',
    '<134>Jan 16 15:19:07 relay01 fw: {"event_type":"asset","hostname":"fw01","action":"found"}',
  ];
  const source=lines.join('\n');
  await page.goto('/');
  const input=page.getByLabel('Auto Parser raw logs');
  await input.fill(source);
  // A source-only literal boundary review must coexist with reviewed relay
  // compilation without trimming or mutating the original multilingual input.
  const boundary=page.locator('details[aria-label="Manually mark a log prefix or postfix"]');
  await expect(boundary).toBeVisible();
  await boundary.locator('summary').click();
  await input.evaluate((element:HTMLTextAreaElement)=>element.setSelectionRange(0,5));
  await boundary.getByRole('button',{name:'Mark selection as prefix'}).click();
  await expect(boundary.getByLabel('Literal boundary review status'))
    .toContainText('Exact boundary matches: 3 source events');
  await expect(boundary).toContainText('Source-only review');
  await expect(input).toHaveValue(source);
  const relay=page.locator('details[aria-label="Review declared relay hosts"]');
  await relay.locator('summary').click();
  await relay.getByLabel('Declared relay hostname list').fill('relay01');
  await expect(relay.getByLabel('Relay source preview')).toContainText('3 of 3 events recognized');
  await relay.getByRole('button',{name:'Apply declared relay profile'}).click();
  await expect(relay.getByLabel('Active declared relays')).toContainText('relay01');
  await expect(input).toHaveValue(source);
  await expect(page.getByLabel('Automatic event accounting')).toContainText('3/3 events analyzed locally');
  await openReviewedFlow(page);
  const panel=page.locator('details[aria-label="Configure one parser for event types"]');
  await expect(panel).toBeVisible();
  await panel.locator('summary').first().click();
  await expect(panel.getByLabel('Proposed event type rules')).toContainText('3 reviewed types');
  await panel.getByLabel('Approve explicit family routing changes').check();
  await panel.getByRole('button',{name:'Apply reviewed event types to this parser'}).click();
  await expect(panel.getByLabel('Configured event profiles')).toContainText('3 explicit event types');
  await page.getByLabel('Review Fields stage').getByRole('button',{name:'Map Fields'}).click();
  await expect(page.getByLabel('Map Fields stage')).toBeVisible();
  await page.getByLabel('Map Fields stage').getByRole('button',{name:'Create Parser'}).click();
  await expect(page.getByLabel('Create Parser stage')).toBeVisible();
  const create=page.getByLabel('Create Parser Files');
  await expect(create).toBeEnabled();
  await create.click();
  const files=page.getByLabel('Generated parser files');
  await expect(files).toBeVisible({timeout:25_000});
  const download=page.waitForEvent('download');
  await files.getByRole('button',{name:/customized_demo_firewall$/}).click();
  const artifact=await download;
  const stream=await artifact.createReadStream();
  const data:Buffer[]=[];
  for await(const chunk of stream)data.push(Buffer.from(chunk));
  const content=Buffer.concat(data).toString('utf8');
  const token=/Base64.strict_decode64\('([^']+)'\)/.exec(content)?.[1];
  expect(token).toBeTruthy();
  const config=JSON.parse(Buffer.from(token!,'base64').toString('utf8'));
  expect(config.extraction.forwarder).toEqual({maxHops:1,relayHosts:['relay01']});
  expect(config.normalization.eventProfiles.variants.map((row:{name:string})=>row.name))
    .toEqual(['threat','user','asset']);
  expect(JSON.stringify(config)).not.toContain('山田');
  await page.getByRole('button',{name:/Add Logs/}).first().click();
  await expect(input).toHaveValue(source);
});

test('declared relay source review must match all events, never one sample only',async({page})=>{
  test.skip(process.env.PARSER_STUDIO_SCOPED_AUTHORING_E2E!=='1',
    'Runs separately against the current compiled offline backend exact Git HEAD.');
  const sample=[
    '<134>Jan 16 15:19:05 relay01 fw: {"event_type":"threat","action":"deny"}',
    '<134>Jan 16 15:19:06 relay01 fw: {"event_type":"user","username":"山田"}',
  ].join('\n');
  await page.goto('/');
  await page.getByLabel('Auto Parser raw logs').fill(sample);
  const relay=page.locator('details[aria-label="Review declared relay hosts"]');
  await relay.locator('summary').click();
  await relay.getByLabel('Declared relay hostname list').fill('relay01');
  await expect(relay.getByLabel('Relay source preview')).toContainText('2 of 2 events recognized');
  await expect(relay.getByRole('button',{name:'Apply declared relay profile'})).toBeEnabled();
  await relay.getByRole('button',{name:'Apply declared relay profile'}).click();
  await expect(relay.getByLabel('Active declared relays')).toContainText('relay01');
  const sourceArea=page.getByLabel('Auto Parser raw logs');
  await expect(sourceArea).toHaveValue(sample);

  const stale=sample.replace('Jan 16 15:19:06 relay01','Jan 16 15:19:06 unknown-relay');
  await sourceArea.fill(stale);
  await expect(relay.getByLabel('Relay source preview')).toContainText('1 of 2 events recognized');
  await expect(relay.getByRole('button',{name:'Apply declared relay profile'})).toBeDisabled();
  await expect(sourceArea).toHaveValue(stale);
});


test('reviewed mapping collisions and oversized event schemas fail closed in the novice UI',async({page})=>{
  test.skip(process.env.PARSER_STUDIO_SCOPED_AUTHORING_E2E!=='1',
    'Requires the actual current offline backend, not an unsupported pinned compiler.');
  await page.goto('/');
  const raw=page.getByLabel('Auto Parser raw logs');
  const source=[
    '{"event_type":"threat","indicator":"198.51.100.1","confidence":"high","action":"deny"}',
    '{"event_type":"user","username":"홍길동","action":"login"}',
    '{"event_type":"asset","hostname":"asset-01","action":"found"}',
  ].join('\n');
  await raw.fill(source);
  await expect(page.getByLabel('Automatic event accounting'))
    .toContainText('3/3 events analyzed locally');
  await openReviewedFlow(page);
  const config=page.locator('details[aria-label="Configure one parser for event types"]');
  await config.locator('summary').first().click();
  const threat=config.locator('details[aria-label="Type-specific mappings for threat"]');
  await threat.locator('summary').click();
  await threat.getByLabel('threat output for indicator').fill('custom.duplicate');
  await threat.getByLabel('threat output for confidence').fill('custom.duplicate.child');
  await config.getByLabel('Approve explicit family routing changes').check();
  await config.getByRole('button',{name:'Apply reviewed event types to this parser'}).click();
  await expect(config).toContainText('same or overlapping output');
  await expect(config.getByLabel('Configured event profiles')).toHaveCount(0);
  await threat.getByLabel('threat output for confidence').fill('custom.confidence');
  await threat.getByLabel('threat type for confidence').selectOption('integer');
  await expect(config).toContainText('cannot be interpreted as integer');
  await config.getByLabel('Approve explicit family routing changes').check();
  await expect(config.getByRole('button',{name:'Apply reviewed event types to this parser'}))
    .toBeDisabled();
  await threat.getByLabel('threat type for confidence').selectOption('string');
  await config.getByLabel('Approve explicit family routing changes').check();
  await config.getByRole('button',{name:'Apply reviewed event types to this parser'}).click();
  await expect(config.getByLabel('Configured event profiles')).toContainText('3 explicit event types');
  await page.getByRole('button',{name:/Add Logs/}).first().click();
  await expect(raw).toHaveValue(source);
  const wide=Object.fromEntries(Array.from({length:101},(_,i)=>['wide_'+i,'v']));
  const wideSource=[
    JSON.stringify({event_type:'threat',...wide}),
    JSON.stringify({event_type:'user',username:'demo'}),
  ].join('\n');
  await raw.fill(wideSource);
  await openReviewedFlow(page);
  const wideConfig=page.locator('details[aria-label="Configure one parser for event types"]');
  await wideConfig.locator('summary').first().click();
  await expect(wideConfig).toContainText('over 100 safe fields');
  await expect(wideConfig.getByRole('button',{name:'Apply reviewed event types to this parser'}))
    .toBeDisabled();
  await page.getByRole('button',{name:/Add Logs/}).first().click();
  await expect(raw).toHaveValue(wideSource);
});


test('saved multi-event and declared relay rules remain comparable and restorable offline',async({page})=>{
  test.skip(process.env.PARSER_STUDIO_SCOPED_AUTHORING_E2E!=='1',
    'Requires current exact-HEAD offline compiler with conditional family and relay capabilities.');
  page.on('dialog',dialog=>dialog.accept());
  const source=[
    '<134>Jan 16 15:19:05 relay01 fw: {"event_type":"threat","src_ip":"192.0.2.10","action":"deny"}',
    '<134>Jan 16 15:19:06 relay01 fw: {"event_type":"user","username":"김민수","action":"login"}',
    '<134>Jan 16 15:19:07 relay01 fw: {"event_type":"asset","hostname":"fw01","action":"found"}',
  ].join('\n');
  await page.goto('/');
  const raw=page.getByLabel('Auto Parser raw logs');
  await raw.fill(source);
  const toggle=page.getByRole('button',{name:'Local Versions',exact:true});
  await toggle.click();
  const history=page.getByLabel('Local Versions workspace');
  await history.getByLabel('Local version name').fill('Before relay or event routing');
  await history.getByRole('button',{name:'Save Version'}).click();
  await expect(history.getByRole('status')).toContainText('Saved in this browser only');
  await toggle.click();
  const relay=page.locator('details[aria-label="Review declared relay hosts"]');
  await relay.locator('summary').first().click();
  await relay.getByLabel('Declared relay hostname list').fill('relay01');
  await expect(relay.getByLabel('Relay source preview')).toContainText('3 of 3 events recognized');
  await relay.getByRole('button',{name:'Apply declared relay profile'}).click();
  await expect(relay.getByLabel('Active declared relays')).toContainText('relay01');
  await expect(page.getByLabel('Automatic event accounting'))
    .toContainText('3/3 events analyzed locally');
  await openReviewedFlow(page);
  const types=page.locator('details[aria-label="Configure one parser for event types"]');
  await types.locator('summary').first().click();
  await expect(types.getByLabel('Proposed event type rules')).toContainText('3 reviewed types');
  await types.getByLabel('Approve explicit family routing changes').check();
  await types.getByRole('button',{name:'Apply reviewed event types to this parser'}).click();
  await expect(types.getByLabel('Configured event profiles')).toContainText('3 explicit event types');
  await toggle.click();
  const versions=page.getByLabel('Local Versions workspace');
  await versions.getByLabel('Local version name').fill('Reviewed three event types and relay');
  await versions.getByRole('button',{name:'Save Version'}).click();
  await expect(versions.getByLabel('Saved local versions'))
    .toContainText('Reviewed three event types and relay');
  await versions.getByLabel('Compare version A')
    .selectOption({label:'Before relay or event routing'});
  await versions.getByLabel('Compare version B')
    .selectOption({label:'Reviewed three event types and relay'});
  await expect(versions.getByLabel('Local version differences'))
    .toContainText('Declared relay profile');
  await expect(versions.getByLabel('Local version differences'))
    .toContainText('Event-type routing / conditional mappings');
  const versionRow=(title:string)=>versions.getByText(title,{exact:true})
    .locator('..').locator('..');
  await versionRow('Before relay or event routing')
    .getByRole('button',{name:'Restore'}).click();
  await expect(page.getByLabel('Auto Parser raw logs')).toHaveValue(source);
  await versionRow('Reviewed three event types and relay')
    .getByRole('button',{name:'Restore'}).click();
  await expect(page.getByLabel('Auto Parser raw logs')).toHaveValue(source);
  await openReviewedFlow(page,false);
  await expect(page.locator('details[aria-label="Configure one parser for event types"]')
    .getByLabel('Configured event profiles')).toContainText('3 explicit event types');
  await page.getByRole('button',{name:/Add Logs/}).first().click();
  await expect(page.locator('details[aria-label="Review declared relay hosts"]')
    .getByLabel('Active declared relays')).toContainText('relay01');
  await expect(page.getByLabel('Auto Parser raw logs')).toHaveValue(source);
});


// This bridges two previously separate contracts: saved offline versions must
// still produce the exact reviewed compiler DRAFT after a full browser reload.
test('saved reviewed relay and event families download intact after reload',async({page})=>{
  test.skip(process.env.PARSER_STUDIO_SCOPED_AUTHORING_E2E!=='1',
    'Requires the same exact-HEAD scoped offline compiler as the user E2E.');
  page.on('dialog',dialog=>dialog.accept());
  const source=[
    '<134>Jan 16 15:19:05 relay01 fw: {"event_type":"threat","src_ip":"192.0.2.10","action":"deny"}',
    '<134>Jan 16 15:19:06 relay01 fw: {"event_type":"user","username":"김민수","action":"login"}',
    '<134>Jan 16 15:19:07 relay01 fw: {"event_type":"asset","hostname":"fw01","action":"found"}',
  ].join('\n');
  const outsideRequests:string[]=[];
  page.on('request',req=>{
    if(!req.url().startsWith('http://127.0.0.1:'))
      outsideRequests.push(req.url());
  });
  await page.goto('/');
  await page.getByLabel('Auto Parser raw logs').fill(source);
  const relay=page.locator('details[aria-label="Review declared relay hosts"]');
  await relay.locator('summary').first().click();
  await relay.getByLabel('Declared relay hostname list').fill('relay01');
  await relay.getByLabel('Maximum declared relay hops').selectOption('2');
  await expect(relay.getByLabel('Relay source preview'))
    .toContainText('3 of 3 events recognized');
  await relay.getByRole('button',{name:'Apply declared relay profile'}).click();
  await expect(relay.getByLabel('Active declared relays')).toContainText('relay01');
  await openReviewedFlow(page);
  const family=page.locator('details[aria-label="Configure one parser for event types"]');
  await family.locator('summary').first().click();
  await expect(family.getByLabel('Proposed event type rules')).toContainText('3 reviewed types');
  await family.getByLabel('Approve explicit family routing changes').check();
  await family.getByRole('button',{name:'Apply reviewed event types to this parser'}).click();
  await expect(family.getByLabel('Configured event profiles')).toContainText('3 explicit event types');
  await page.getByRole('button',{name:'Local Versions',exact:true}).click();
  const history=page.getByLabel('Local Versions workspace');
  await history.getByLabel('Local version name').fill('Reviewed relay and three types');
  await history.getByRole('button',{name:'Save Version'}).click();
  await expect(history.getByLabel('Saved local versions'))
    .toContainText('Reviewed relay and three types');
  await page.reload();
  await page.getByRole('button',{name:'Local Versions',exact:true}).click();
  const versions=page.getByLabel('Local Versions workspace');
  await expect(versions.getByLabel('Saved local versions'))
    .toContainText('Reviewed relay and three types');
  await versions.getByText('Reviewed relay and three types',{exact:true})
    .locator('..').locator('..').getByRole('button',{name:'Restore'}).click();
  await expect(page.getByLabel('Auto Parser raw logs')).toHaveValue(source);
  const restoredRelay=page.locator('details[aria-label="Review declared relay hosts"]');
  await restoredRelay.locator('summary').first().click();
  await expect(restoredRelay.getByLabel('Declared relay hostname list')).toHaveValue('relay01');
  await expect(restoredRelay.getByLabel('Maximum declared relay hops')).toHaveValue('2');
  await openReviewedFlow(page,false);
  await expect(page.getByLabel('Configured event profiles')).toContainText('3 explicit event types');
  await page.getByLabel('Review Fields stage').getByRole('button',{name:'Map Fields'}).click();
  await page.getByLabel('Map Fields stage').getByRole('button',{name:'Create Parser'}).click();
  await page.getByLabel('Create Parser Files').click();
  const generated=page.getByLabel('Generated parser files');
  await expect(generated).toContainText('Parser files created successfully',{timeout:25_000});
  const download=page.waitForEvent('download');
  await generated.getByRole('button',{name:/customized_demo_firewall$/}).click();
  const artifact=await download;
  const chunks:Buffer[]=[];
  for await (const item of await artifact.createReadStream())chunks.push(Buffer.from(item));
  const ruby=Buffer.concat(chunks).toString('utf8');
  const token=/Base64.strict_decode64\('([^']+)'\)/.exec(ruby)?.[1];
  expect(token).toBeTruthy();
  const project=JSON.parse(Buffer.from(token!,'base64').toString('utf8'));
  expect(project.extraction.forwarder).toEqual({maxHops:2,relayHosts:['relay01']});
  expect(project.normalization.eventProfiles.variants.map((item:{name:string})=>item.name))
    .toEqual(['threat','user','asset']);
  expect(JSON.stringify(project)).not.toContain('김민수');
  expect(outsideRequests).toEqual([]);
});
