import {test,expect} from '@playwright/test';
import {createHash} from 'node:crypto';

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
// Deliberately unanchored: the implicit scan loop overlaps every repeat, so the
// Ruby 2.4.9 static cost classification refuses export and the UI shows why.
const pattern='(?<raw_event>\\[client (?<address>[^\\]]+)\\] (?<description>[^\\[]+)\\[id "(?<id>[^"]+)"\\] \\[msg "(?<message>[^"]+)"\\])$';
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


test.skip(
  process.env.PARSER_STUDIO_LIVE_BACKEND!=='1'&&process.env.PARSER_STUDIO_SCOPED_AUTHORING_E2E!=='1',
  'Requires the scoped local authoring backend and real source-preview service.'
);

test('a novice preserves partial source values and local Regex recovery, but target export is denied',async({page})=>{
  test.setTimeout(120000);
  const errors:string[]=[];
  page.on('pageerror',error=>errors.push(error.message));
  await page.goto('/');
  await page.getByLabel('Auto Parser raw logs').fill(source);
  await page.getByRole('button',{name:'Analyze Logs',exact:true}).click();
  const summary=page.getByLabel('Beginner analysis summary');
  await expect(summary).toContainText('0 of 2 log events structurally parsed',{timeout:20000});
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
  await expect(summary).toContainText('2 of 2 log events structurally parsed');
  await expect(page.getByRole('button',{name:'Review Fields',exact:true})).toBeEnabled();
  // Parsing evidence and deployability are separate. The observed Stellar 7.0
  // Ruby 2.4.9 runtime has no Regexp timeout, so only patterns with a static
  // backtracking-cost proof may leave the target adapter; this one has none.
  await page.getByRole('button',{name:'Review Fields',exact:true}).click();
  await expect(page.getByRole('alert').filter({
    hasText:/Regex samples may be reviewed in the browser/,
  })).toContainText('Ruby 2.4.9');
  await expect(page.getByLabel('Review Fields stage')).toHaveCount(0);
  await expect(page.getByLabel('Generated parser files')).toHaveCount(0);
  await expect(page.getByLabel('Auto Parser raw logs')).toHaveValue(source);
  expect(errors).toEqual([]);
});
