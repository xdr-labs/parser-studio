import {test,expect} from './support/downloadSink';

// Purely authored generic CSV; no vendor originals or privileged target access.
// Field positions are explicitly declared by the user, never inferred from
// the presence of a similar-looking official Stellar metadata field.
const names=[
  'timestamp','src_ip','dst_ip','action','username','hostname','url',
  'event_type','event_id','policy','category','severity','bytes','port',
  'source','destination','sensor','result','location','user_agent',
  'message','device','extra',
];
const quoted=(value:string)=>'"'+value.replaceAll('"','""')+'"';
const raw=Array.from({length:3},(_,i)=>[
  '2026-10-20T08:30:0'+i+'Z','192.0.2.'+(21+i),'198.51.100.'+(51+i),
  i===0?'deny':'allow','민수_'+i,'proxy'+i,
  'https://example.test/search?key=one,two&value='+i,
  'proxy',String(i),'p-001','content','medium',
  String(130+i),'443','src','dst','s01','blocked','KR',
  'Mozilla/5.0 (abc, def)','quoted "content", includes comma '+i,
  'device1','',
].map(quoted).join(',')).join('\n');

test('all 23 reviewed quoted CSV values survive vendor-local severity validation and real DRAFT compilation',async({page})=>{
  test.skip(process.env.PARSER_STUDIO_SCOPED_AUTHORING_E2E!=='1',
    'Requires the current pinned offline authoring and Python Multi-Pass HTTP servers.');
  test.setTimeout(75_000);
  const jsErrors:string[]=[];
  const serverErrors:number[]=[];
  page.on('pageerror',e=>jsErrors.push(e.message));
  page.on('response',r=>{
    if(r.url().includes('/api/')&&r.status()>=500)serverErrors.push(r.status());
  });

  await page.goto('/');
  const source=page.getByLabel('Auto Parser raw logs');
  await source.fill(raw);
  await page.getByRole('button',{name:'Analyze Logs',exact:true}).click();
  const summary=page.getByLabel('Beginner analysis summary');
  await expect(summary).toContainText('Values found in 3 of 3 log events');
  const csv=page.getByLabel('Review CSV column names');
  await expect(csv).toContainText('23 consistent columns detected');
  await csv.getByLabel('Reviewed CSV column names').fill(names.join(','));
  await csv.getByLabel('Reviewed CSV data separator').selectOption(',');
  const confirm=csv.getByRole('button',{name:'I Confirm These CSV Column Names'});
  await expect(confirm).toBeEnabled();
  await confirm.click();

  const review=page.getByRole('button',{name:'Review Fields',exact:true});
  await expect(review).toBeEnabled();
  await review.click();
  const reviewStage=page.getByLabel('Review Fields stage');
  const mapButton=reviewStage.getByRole('button',{name:'Map Fields',exact:true});
  await expect(mapButton).toBeEnabled();
  await mapButton.click();

  const mapping=page.getByLabel('Map Fields stage');
  await expect(mapping.getByLabel('Field mapping summary')).toContainText('23');
  await expect(mapping.getByLabel('Field mapping checks')).toContainText('No mapping problems found');
  const rows=await mapping.locator('article.normalization-map-row').evaluateAll(elements=>
    elements.map(element=>({
      source:(element.querySelector('input[aria-label^="Source field"]') as HTMLInputElement)?.value,
      target:(element.querySelector('input[aria-label^="Stellar field"]') as HTMLInputElement)?.value,
      valueType:(element.querySelector('select[aria-label^="Value type"]') as HTMLSelectElement)?.value,
      custom:element.classList.contains('custom'),
    })));
  const categorical=rows.find(row=>row.source==='severity');
  expect(categorical).toMatchObject({target:'severity',valueType:'string',custom:true});
  expect(rows.some(row=>row.source==='extra')).toBe(false);
  expect(rows.length).toBe(22);

  const create=mapping.getByRole('button',{name:'Create Parser',exact:true});
  await expect(create).toBeEnabled();
  await create.click();
  await expect(page.getByLabel('Create Parser stage')).toBeVisible();
  await page.getByLabel('Create Parser Files').click();
  const generated=page.getByLabel('Generated parser files');
  await expect(generated).toContainText('Parser files created successfully',{timeout:30000});
  await expect(generated).toContainText('Native runtime and Stellar target verification are separate; nothing was deployed.');
  const downloadPromise=page.waitForEvent('download');
  await generated.getByRole('button',{name:/customized_demo_firewall$/}).click();
  const download=await downloadPromise;
  expect(download.suggestedFilename()).toBe('customized_demo_firewall');
  const contents:Buffer[]=[];
  const stream=await download.createReadStream();
  for await(const chunk of stream)contents.push(Buffer.from(chunk));
  const ruby=Buffer.concat(contents).toString('utf8');
  const payload=/Base64.strict_decode64\('([^']+)'\)/.exec(ruby)?.[1];
  expect(payload).toBeTruthy();
  const project=JSON.parse(Buffer.from(payload!,'base64').toString('utf8'));
  expect(project.extraction.format).toBe('csv');
  expect(project.extraction.csvColumns).toEqual(names);
  expect(project.extraction.csvDelimiter).toBe(',');
  expect(ruby).not.toContain('민수_0');
  expect(ruby).not.toContain('192.0.2.21');
  // The Add Logs input is intentionally not mounted on Create Parser.
  // Return through the user-visible step navigation before checking source.
  await page.getByRole('navigation',{name:'Auto Parser steps'})
    .getByRole('button',{name:/Add Logs/}).click();
  await expect(source).toHaveValue(raw);
  expect(jsErrors).toEqual([]);
  expect(serverErrors).toEqual([]);
});
