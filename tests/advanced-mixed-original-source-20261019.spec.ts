import {expect,test,type Page} from '@playwright/test';

const threat='{"event_type":"threat","src_ip":"192.0.2.10","action":"deny"}';
const user='{"event_type":"user","username":"김민수","action":"login"}';
const docker=JSON.stringify({
  log:'login user=김민수\n',stream:'stdout',time:'2026-10-19T08:20:00Z',
});

async function requireCompilerBlock(page:Page,raw:string){
  const serverErrors:string[]=[];
  page.on('pageerror',error=>serverErrors.push(error.message));
  await page.getByRole('button',{name:'Analyze Logs',exact:true}).click();
  await expect(page.getByLabel('Beginner analysis summary')).toBeVisible();
  const review=page.getByRole('button',{name:'Review Fields',exact:true});
  // Analyze Logs may finish rendering its summary before the asynchronous
  // source preview and compiler readiness checks settle. Wait for the button
  // to be actionable; one immediate isEnabled() sample races that transition.
  await expect(review).toBeEnabled({timeout:20000});
  await review.click();
  await expect(page.getByLabel('Review Fields stage')).toHaveCount(0);
  const blocked=page.getByLabel('Parser draft not ready');
  await expect(blocked).toBeVisible();
  await expect(blocked).toContainText('original stream or container boundaries');
  await expect(page.getByLabel('Create Parser stage')).toHaveCount(0);
  expect(serverErrors).toEqual([]);
  // The original raw bytes stay in the user's local source or named groups;
  // test source identity separately for each input path.
  expect(raw).toContain(docker);
}

test('Advanced input: ordinary security JSON followed by Docker original JSON-file is not a supported DRAFT',async({page})=>{
  const input=threat+'\n'+docker+'\n';
  await page.goto('/');
  await page.getByLabel('Auto Parser raw logs').fill(input);
  await requireCompilerBlock(page,input);
  await expect(page.getByLabel('Auto Parser raw logs')).toHaveValue(input);
});

test('Advanced named types: eligible Threat/User entries do not qualify a later Docker source wrapper',async({page})=>{
  await page.goto('/');
  await page.getByRole('button',{name:'Add Another Log Type'}).click();
  await page.getByLabel('Log type name 1').fill('Threat');
  await page.getByLabel('Log type sample 1').fill(threat);
  await page.getByLabel('Log type name 2').fill('User');
  await page.getByLabel('Log type sample 2').fill(user);
  await page.getByLabel('Named log type samples')
    .getByRole('button',{name:'Add Another Log Type'}).click();
  await page.getByLabel('Log type name 3').fill('Container wrapper');
  await page.getByLabel('Log type sample 3').fill(docker);
  await requireCompilerBlock(page,threat+'\n'+user+'\n'+docker);
  await expect(page.getByLabel('Log type sample 1')).toHaveValue(threat);
  await expect(page.getByLabel('Log type sample 2')).toHaveValue(user);
  await expect(page.getByLabel('Log type sample 3')).toHaveValue(docker);
});
