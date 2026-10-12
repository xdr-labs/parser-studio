import {expect,test} from '@playwright/test';
import {createDraft} from '../src/model';
import {toBackendProject} from '../src/guided/backendAdapter';

const initial=createDraft();
initial.format='json';
initial.name='Reviewed Offline Synthetic Project';
initial.vendor='Documentation Only';
const result=toBackendProject(initial);
if(!result.ok)throw Error('Reviewed fixture does not satisfy frontend schema');
const project=result.project;
const bytes=(value:unknown)=>Buffer.from(JSON.stringify(value),'utf8');
async function open(page:import('@playwright/test').Page){
  await page.goto('/');
  await page.getByLabel('Guided raw sample logs').fill('PRIVATE_CUSTOMER_SAMPLE_MUST_NOT_BE_STORED');
  await page.getByRole('button',{name:/6\. Generate Files/}).click();
  await page.locator('.guided-local-project-import summary').click();
  return page.locator('.guided-local-project-import');
}
test('review and confirm an exact offline Project JSON without any network calls or raw sample persistence',async({page})=>{
  let api=0;
  page.on('request',request=>{
    if(request.url().includes('/api/v1/'))api++;
  });
  const panel=await open(page);
  await page.getByLabel('Offline project JSON file').setInputFiles({
    name:'synthetic-project.json',mimeType:'application/json',buffer:bytes(project),
  });
  await expect(page.getByLabel('Validated local project')).toHaveCount(0);
  expect(api).toBe(0);
  await panel.getByRole('button',{name:'Validate Local Project JSON'}).click();
  const preview=page.getByLabel('Validated local project');
  await expect(preview).toContainText('Lossless Project Model Verified · No Import Yet');
  await expect(preview).toContainText('Reviewed Offline Synthetic Project');
  await expect(preview).toContainText('One shared port: 7501');
  const restore=preview.getByRole('button',{name:'Restore Validated JSON as Unsaved Draft'});
  await expect(restore).toBeDisabled();
  await preview.getByLabel('Confirm replace draft with Project JSON').check();
  await expect(restore).toBeEnabled();
  await restore.click();
  await expect(page.locator('.guided-content-head h2')).toContainText('normalized');
  await expect(page.getByLabel('Mapping for src_ip')).toBeVisible();
  await page.getByRole('button',{name:/1\. Import Logs/}).click();
  await expect(page.getByLabel('Guided parser name')).toHaveValue('Reviewed Offline Synthetic Project');
  await expect(page.getByLabel('Guided raw sample logs')).toHaveValue('');
  const storage=await page.evaluate(()=>JSON.stringify(localStorage));
  expect(storage).not.toContain('PRIVATE_CUSTOMER_SAMPLE_MUST_NOT_BE_STORED');
  expect(api).toBe(0);
});
test('invalid, lossy or oversized local JSON is denied without draft changes or API calls',async({page})=>{
  let api=0;
  page.on('request',request=>{if(request.url().includes('/api/v1/'))api++;});
  const panel=await open(page);
  const upload=page.getByLabel('Offline project JSON file');
  await upload.setInputFiles({
    name:'lossy.json',mimeType:'application/json',
    buffer:bytes({...project,undocumentedField:'do-not-import'}),
  });
  await panel.getByRole('button',{name:'Validate Local Project JSON'}).click();
  await expect(panel.getByRole('alert')).toContainText('cannot be restored without losing');
  await expect(page.getByLabel('Validated local project')).toHaveCount(0);
  await upload.setInputFiles({
    name:'oversized.json',mimeType:'application/json',
    buffer:Buffer.from(' '.repeat(262145)),
  });
  await panel.getByRole('button',{name:'Validate Local Project JSON'}).click();
  await expect(panel.getByRole('alert')).toContainText('up to 256 KiB');
  await expect(page.getByLabel('Validated local project')).toHaveCount(0);
  await page.getByRole('button',{name:/1\. Import Logs/}).click();
  await expect(page.getByLabel('Guided raw sample logs'))
    .toHaveValue('PRIVATE_CUSTOMER_SAMPLE_MUST_NOT_BE_STORED');
  expect(api).toBe(0);
});
