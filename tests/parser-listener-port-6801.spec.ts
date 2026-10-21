import {test,expect} from '@playwright/test';
import {createHash} from 'node:crypto';
import {readFile} from 'node:fs/promises';

const logs=[
  '{"action":"allow","src_ip":"198.51.100.10","dst_port":443}',
  '{"action":"deny","src_ip":"203.0.113.5","dst_port":22}',
].join('\n');
const sha=(value:string|Buffer)=>createHash('sha256').update(value).digest('hex');

test('new source identity displays editable CONF port before log analysis',async({page})=>{
  await page.goto('/');
  const stage=page.getByLabel('Add Logs stage');
  const listener=stage.getByRole('spinbutton',{name:'Parser listener port'});
  await expect(listener).toHaveValue('6801');
  await expect(stage).toContainText('Generated .conf receiving port: 6801');
  await listener.fill('6819');
  await expect(listener).toHaveValue('6819');
  await expect(stage).toContainText('Generated .conf receiving port: 6819');
  await expect(stage.getByLabel('Auto Parser raw logs')).toBeEmpty();
  await listener.fill('80');
  await expect(listener).toHaveAttribute('aria-invalid','true');
  await listener.fill('6801');
  await expect(listener).toHaveAttribute('aria-invalid','false');
});

test.describe('real source-to-backend DRAFT generation, without DP/sensor operations',()=>{
  test.skip(process.env.PARSER_STUDIO_SCOPED_AUTHORING_E2E!=='1'&&
    process.env.PARSER_STUDIO_LIVE_BACKEND!=='1',
    'Requires same-source localhost offline authoring and Multi-Pass.');
  for(const port of [6801,6819]){
    test(`generated Ruby/CONF files use explicitly selected ${port} on actual backend`,async({page})=>{
      await page.goto('/');
      const listener=page.getByRole('spinbutton',{name:'Parser listener port'});
      await expect(listener).toHaveValue('6801');
      if(port!==6801)await listener.fill(String(port));
      await page.getByLabel('Auto Parser raw logs').fill(logs);
      await expect(page.getByLabel('Automatic event accounting')).toContainText('2/2 events analyzed locally');
      if(await page.getByRole('button',{name:'Advanced'}).count())
        await page.getByRole('button',{name:'Advanced'}).click();
      await page.getByRole('button',{name:'Review Detected Results'}).click();
      await expect(page.getByLabel('Review Fields stage')).toBeVisible();
      await page.getByLabel('Review Fields stage').getByRole('button',{name:'Map Fields'}).click();
      await page.getByLabel('Map Fields stage').getByRole('button',{name:'Create Parser'}).click();
      const generated=page.waitForResponse(response=>response.url().endsWith('/parser-pairs/generate')&&
        response.request().method()==='POST');
      await page.getByRole('button',{name:'Create Parser Files'}).click();
      const response=await generated;
      expect(response.status()).toBe(200);
      const request=response.request().postDataJSON();
      expect(request.receiver.port).toBe(port);
      expect(JSON.stringify(request)).not.toContain('198.51.100.10');
      expect(JSON.stringify(request)).not.toContain('203.0.113.5');
      const pair=await response.json();
      expect(pair.manifest).toMatchObject({status:'DRAFT',engineVerified:false,targetImportVerified:false});
      const conf=pair.files.find((item:{name:string})=>item.name.endsWith('.conf'));
      expect(conf?.content).toMatch(new RegExp('^\\s+port '+port+'$', 'm'));
      expect(sha(conf.content)).toBe(conf.sha256);
      const download=page.waitForEvent('download');
      await page.getByLabel('Generated parser files').getByRole('button',{name:conf.name,exact:true}).click();
      expect(sha(await readFile(await (await download).path()))).toBe(conf.sha256);
    });
  }
});
