import {test,expect,type Page,type TestInfo} from '@playwright/test';
import {createHash} from 'node:crypto';
import {writeFile} from 'node:fs/promises';

// Synthetic structural examples. The proposed rule is reviewed by the user;
// no vendor names, semantic field assignments or live AI call are involved.
const source=[
  '[client 192.0.2.3] Gateway: Access denied with code 403 (phase 2). [id "942100"] [msg "Request blocked by policy"]',
  '[client 198.51.100.4] Gateway: Access denied with code 401 (phase 1). [id "942110"] [msg "Unknown account rejected"]',
].join('\n');
const holdout=[
  '[client 203.0.113.7] Edge: Request denied with code 429 (phase 3). [id "942200"] [msg "Request limit reached"]',
  '[client 192.0.2.9] Edge: Request denied with code 400 (phase 4). [id "942210"] [msg "사용자 요청 검토"]',
].join('\n');
const pattern='^(?<raw_event>\\[client (?<address>[^\\]]+)\\] (?<description>[^\\[]+)\\[id "(?<id>[^"]+)"\\] \\[msg "(?<message>[^"]+)"\\])$';
const fields=['address','description','id','message','raw_event'];
const recipe=(omitId=false)=>({
  contract:'parser-studio.recipe.v0.2',schemaRevision:'0.2',compilerMode:'REVIEW_ONLY',
  projectId:'draft-demo_firewall',sourceFormat:'regex',bodyFormat:'regex',
  sample:{sha256:createHash('sha256').update(source).digest('hex'),events:2},
  stages:[
    {op:'split_event',boundary:'single-line'},
    {op:'parse_regex',pattern},
    ...fields.filter(field=>!omitId||field!=='id').map(field=>({
      op:'map_field',source:field,target:field,data_type:'string',group:'vendor_fields',
    })),
    {op:'classify',defaultIndex:'syslog',rules:[]},
    {op:'fallback_unparsed',mode:'retain_unparsed'},
  ],
  nativeVerified:false,targetVerified:false,
});

async function downloadDraft(page:Page,info:TestInfo){
  await page.getByRole('button',{name:'Review Fields',exact:true}).click();
  const review=page.getByLabel('Review Fields stage');
  await expect(review).toBeVisible();
  await review.getByRole('button',{name:'Map Fields',exact:true}).click();
  const mapping=page.getByLabel('Map Fields stage');
  await expect(mapping.getByLabel('Field mapping checks')).toContainText('No mapping problems found');
  await mapping.getByRole('button',{name:'Create Parser',exact:true}).click();
  await page.getByLabel('Create Parser Files').click();
  const generated=page.getByLabel('Generated parser files');
  await expect(generated).toContainText('Parser files created successfully',{timeout:30000});
  await expect(generated).toContainText('Native runtime and Stellar target verification are separate; nothing was deployed.');
  const downloads:Record<string,string>={};
  for(const filename of ['customized_demo_firewall','customized_demo_firewall.conf']){
    const pending=page.waitForEvent('download');
    await generated.getByRole('button',{name:new RegExp(filename.replaceAll('.','\\.')+'$')}).click();
    const download=await pending;
    expect(download.suggestedFilename()).toBe(filename);
    const chunks:Buffer[]=[];
    for await(const chunk of (await download.createReadStream())!)chunks.push(Buffer.from(chunk));
    downloads[filename]=Buffer.concat(chunks).toString('utf8');
    expect(downloads[filename]!.length).toBeGreaterThan(0);
    await download.saveAs(info.outputPath(filename));
  }
  const encoded=/Base64.strict_decode64\('([^']+)'\)/.exec(downloads.customized_demo_firewall!);
  expect(encoded).not.toBeNull();
  const project=JSON.parse(Buffer.from(encoded![1]!,'base64').toString('utf8'));
  expect(project.extraction.format).toBe('regex');
  expect(project.extraction.pattern).toBe(pattern);
  const targets=Object.keys({
    ...project.normalization.topFields,...project.normalization.nsFields,
    ...project.normalization.vendorFields,
  });
  expect(targets).toEqual(expect.arrayContaining(fields));
  await writeFile(info.outputPath('recovery-source-and-project.json'),JSON.stringify({source,holdout,project},null,2));
  await page.screenshot({path:info.outputPath('reviewed-recovery-downloads.png'),fullPage:true});
  await page.getByRole('navigation',{name:'Auto Parser steps'}).getByRole('button',{name:/Add Logs/}).click();
  await expect(page.getByLabel('Auto Parser raw logs')).toHaveValue(source);
}

test.skip(
  process.env.PARSER_STUDIO_LIVE_BACKEND!=='1'&&process.env.PARSER_STUDIO_SCOPED_AUTHORING_E2E!=='1',
  'Requires the scoped local authoring backend and real source-preview service.'
);

test('a novice preserves partial source values, reviews an independent fix, and downloads Ruby and CONF',async({page},info)=>{
  test.setTimeout(120000);
  const errors:string[]=[];
  page.on('pageerror',error=>errors.push(error.message));
  await page.goto('/');
  await page.getByLabel('Auto Parser raw logs').fill(source);
  await page.getByRole('button',{name:'Analyze Logs',exact:true}).click();
  const summary=page.getByLabel('Beginner analysis summary');
  await expect(summary).toContainText('0 of 2 log events parsed completely',{timeout:20000});
  await expect(page.getByRole('button',{name:'Review Fields',exact:true})).toBeDisabled();
  const preserved=page.getByLabel('Preserved source values');
  await preserved.locator('summary').click();
  await expect(preserved).toContainText('generic_atoms.network.0');
  await expect(preserved).toContainText('192.0.2.3');
  await expect(preserved).toContainText('generic_labels.id.0');
  await expect(preserved).toContainText('942100');
  await expect(preserved).toContainText('Request blocked by policy');
  await expect(page.getByLabel('Text recovery steps')).toContainText('current logs and additional examples');
  await page.getByLabel('Parse problem inspector').getByRole('button',{name:'Fix with ChatGPT',exact:true}).click();
  const prompt=page.getByLabel('Generated ChatGPT repair prompt');
  await expect(prompt).toContainText('Original source value occurrences to preserve:');
  await expect(prompt).toContainText('generic_labels.id.0');
  await expect(prompt).toContainText('preserve every unparsed source region');
  const proposed=page.getByLabel('ChatGPT JSON result');
  const additional=page.getByLabel('Additional test logs',{exact:true});

  // Even a matching Regex must retain every existing source value in output.
  await proposed.fill(JSON.stringify(recipe(true)));
  await additional.fill(holdout);
  await page.getByLabel('Confirm different test examples').check();
  await page.getByRole('button',{name:'Test Proposed Fix',exact:true}).click();
  await expect(page.getByLabel('ChatGPT repair prompt',{exact:true})).toContainText(/would drop .*source value occurrences from the final parser output/);
  await expect(page.getByLabel('Apply Verified Fix')).toHaveCount(0);

  // Reusing the original examples is not independent qualification.
  await proposed.fill(JSON.stringify(recipe()));
  await additional.fill(source);
  await page.getByLabel('Confirm different test examples').check();
  await page.getByRole('button',{name:'Test Proposed Fix',exact:true}).click();
  await expect(page.getByLabel('ChatGPT repair prompt',{exact:true})).toContainText('additional test logs are identical to the original examples');
  await expect(page.getByLabel('Apply Verified Fix')).toHaveCount(0);

  await additional.fill(holdout);
  await page.getByLabel('Confirm different test examples').check();
  await page.getByRole('button',{name:'Test Proposed Fix',exact:true}).click();
  await expect(page.getByLabel('ChatGPT repair prompt',{exact:true})).toContainText('Fix passed: full parser recovery; 2 additional test logs checked with no regressions. Ready to apply.',{timeout:20000});
  const apply=page.getByLabel('Apply Verified Fix');
  await expect(apply).toBeDisabled();
  await page.getByLabel('Approve tested fix').check();
  await apply.click();
  await expect(summary).toContainText('2 of 2 log events parsed completely');
  await expect(page.getByRole('button',{name:'Review Fields',exact:true})).toBeEnabled();
  await downloadDraft(page,info);
  expect(errors).toEqual([]);
});
