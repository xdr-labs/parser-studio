import {test,expect} from '@playwright/test';

const source=[
  '{"event_type":"threat","src_ip":"192.0.2.10","action":"deny"}',
  '{"event_type":"user","username":"김민수","action":"login"}',
  '{"event_type":"asset","hostname":"fw01","action":"found"}',
].join('\n');

test('one reviewed parser DRAFT retains all three event types with exact backend capability',async({page})=>{
  test.skip(process.env.PARSER_STUDIO_SCOPED_AUTHORING_E2E!=='1',
    'Runs separately against the current compiled offline backend exact Git HEAD.');
  await page.goto('/');
  await page.getByRole('button',{name:'Advanced Tools & Diagnostics'}).click();
  const raw=page.getByLabel('Auto Parser raw logs');
  await raw.fill(source);
  await expect(page.getByLabel('Automatic event accounting'))
    .toContainText('3/3 events analyzed locally');

  await page.getByRole('button',{name:'Review Detected Results'}).click();
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
  await expect(files).toContainText('The files have not been installed in a live Stellar system.');
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
  await page.getByRole('button',{name:'Advanced Tools & Diagnostics'}).click();
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
  const reviewButton=page.getByRole('button',{name:'Review Detected Results'});
  await expect(reviewButton).toBeEnabled();
  await reviewButton.click();
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
